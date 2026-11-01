"""The SOC report: what an attack through the Guard looked like, for the people who respond.

Events come from Elasticsearch (the Guard ships every event there), falling back to the Guard's
daily JSONL files, falling back to the Guard's own events endpoint. Everything is summarised per
attacker with indicators of compromise, ATT&CK technique tags and recommended actions.
"""

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from hedwig import config

ELASTIC_URL = "http://127.0.0.1:19200"
INDEX = "chakravyuha-*"
MAX_EVENTS = 5000
MAX_SHOWN = 8
MAX_DETAILED = 6
STOPPED = {"blocked", "banned", "trapped", "tarpitted", "login_failed"}

# rule or category -> (ATT&CK technique id, name)
ATTACK = {
    "bruteforce": ("T1110", "Brute Force"),
    "brute-force": ("T1110", "Brute Force"),
    "distributed-bruteforce": ("T1110.004", "Credential Stuffing"),
    "password-spraying": ("T1110.003", "Password Spraying"),
    "probe": ("T1595", "Active Scanning"),
    "ddos": ("T1498", "Network Denial of Service"),
    "jndi": ("T1190", "Exploit Public-Facing Application"),
    "path-traversal": ("T1190", "Exploit Public-Facing Application"),
    "proto-pollution": ("T1190", "Exploit Public-Facing Application"),
    "webshell": ("T1505.003", "Web Shell"),
    "eicar": ("T1105", "Ingress Tool Transfer"),
    "dropper-command": ("T1105", "Ingress Tool Transfer"),
    "executable-filename": ("T1105", "Ingress Tool Transfer"),
    "archive-executable": ("T1105", "Ingress Tool Transfer"),
    "office-macro": ("T1204.002", "Malicious File"),
    "ransomware-command": ("T1490", "Inhibit System Recovery"),
    "ransomware-extension": ("T1486", "Data Encrypted for Impact"),
    "ransom-note": ("T1486", "Data Encrypted for Impact"),
    "reverse-shell": ("T1059", "Command and Scripting Interpreter"),
    "honeytoken": ("T1552", "Unsecured Credentials"),
}
CRITICAL_RULES = {
    "webshell", "eicar", "dropper-command", "ransomware-command", "ransomware-extension",
    "ransom-note", "reverse-shell", "archive-executable", "office-macro",
}  # fmt: skip


@dataclass
class Attacker:
    ip: str
    first: str = ""
    last: str = ""
    requests: int = 0
    stopped: int = 0
    decoy: int = 0
    trapped_at: str = ""
    banned_at: str = ""
    banned_until: str = ""
    ban_reason: str = ""
    rules: Counter = field(default_factory=Counter)
    targets: Counter = field(default_factory=Counter)
    agents: set = field(default_factory=set)
    users: set = field(default_factory=set)
    passwords: set = field(default_factory=set)
    files: dict = field(default_factory=dict)  # sha256 -> file name


@dataclass
class SocData:
    since: str
    until: str
    source: str
    events: int
    attackers: list[Attacker]
    honeytokens: list[dict]
    campaigns: list[str]
    timeline: list[dict]
    techniques: list[tuple[str, str, str]]  # (id, name, evidence)
    severity: str
    actions: list[str]
    shown: list[Attacker] = field(default_factory=list)  # the most important, for the tables
    more: int = 0  # how many other sources are not listed
    detailed: list[Attacker] = field(default_factory=list)  # those that get an indicators block
    credential: str = ""  # one line about the credential attack, if there was one


def parse_since(text: str) -> timedelta:
    match = re.fullmatch(r"(\d+)\s*([smhd])", text.strip())
    if not match:
        raise ValueError("--since looks like 30m, 2h or 1d")
    return timedelta(
        **{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[match[2]]: int(match[1])}
    )


def _stamp(event: dict) -> datetime:
    return datetime.fromisoformat(str(event.get("@timestamp", "")).replace("Z", "+00:00"))


def from_elastic(since: datetime) -> list[dict] | None:
    url = os.environ.get("CHAKRA_ELASTIC_URL", ELASTIC_URL).rstrip("/")
    body = {
        "size": MAX_EVENTS,
        "sort": [{"@timestamp": "asc"}],
        "query": {"range": {"@timestamp": {"gte": since.isoformat()}}},
    }
    try:
        done = httpx.post(f"{url}/{INDEX}/_search", json=body, timeout=10)
        done.raise_for_status()
        return [hit["_source"] for hit in done.json()["hits"]["hits"]]
    except (httpx.HTTPError, KeyError, ValueError):
        return None


def events_folder(root: Path) -> Path | None:
    guard = (config.load_project(root) or {}).get("guard") or {}
    candidates = [guard.get("events"), "../data/events", "../../data/events", "guard/data/events"]
    for item in candidates:
        if item and (root / item).is_dir():
            return (root / item).resolve()
    return None


def from_files(root: Path, since: datetime) -> list[dict] | None:
    folder = events_folder(root)
    if folder is None:
        return None
    found = []
    for path in sorted(folder.glob("*.jsonl"))[-3:]:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
                if _stamp(event) >= since:
                    found.append(event)
            except (ValueError, TypeError):
                continue
    return found


def gather(root: Path, since: datetime) -> tuple[list[dict], str]:
    events = from_elastic(since)
    if events:
        return events, "Elasticsearch"
    events = from_files(root, since)
    if events is not None:
        return events, "the Guard's event files"
    from hedwig.core import guard_feed

    attacks, note = guard_feed.fetch(root)
    if note:
        raise RuntimeError(f"no attack events found: {note}")
    return [], "the Guard's events endpoint"


def _iso(event: dict) -> str:
    return _stamp(event).astimezone(UTC).isoformat(timespec="seconds")


def summarise(events: list[dict], since: datetime, source: str) -> SocData:
    attackers: dict[str, Attacker] = {}
    honeytokens: list[dict] = []
    campaigns: dict[str, str] = {}
    timeline: list[dict] = []
    failures: list[dict] = []  # routine login failures are summarised, not listed one by one
    swept: list[dict] = []  # sources the Scout trapped as one campaign, likewise
    for event in events:
        action = event.get("event.action", "")
        ip = event.get("source.ip", "")
        if event.get("event.category") == "honeytoken":
            honeytokens.append(event)
        if event.get("campaign"):
            campaigns[str(event["campaign"])] = str(event.get("rule") or "")
        if action not in STOPPED and not event.get("hedwig.decoy"):
            continue
        who = attackers.setdefault(ip, Attacker(ip=ip, first=_iso(event)))
        who.last = _iso(event)
        who.requests += 1
        rule = event.get("rule") or event.get("event.category") or "?"
        if event.get("hedwig.decoy"):
            who.decoy += 1
            who.trapped_at = who.trapped_at or _iso(event)
        else:
            who.stopped += 1
            who.rules[rule] += 1
            if action == "login_failed":
                failures.append(event)
                continue
            if rule == "campaign":
                swept.append(event)
                continue
            timeline.append(
                {"at": _iso(event), "ip": ip, "action": action, "rule": rule,
                 "target": f"{event.get('service') or '-'} {event.get('url.path') or ''}".strip()}
            )  # fmt: skip
        if action == "trapped":
            who.trapped_at = who.trapped_at or _iso(event)
        if action == "banned":
            who.banned_at = who.banned_at or _iso(event)
            who.ban_reason = rule
            minutes = event.get("hedwig.ban_minutes")
            if minutes:
                until = _stamp(event) + timedelta(minutes=float(minutes))
                who.banned_until = until.astimezone(UTC).strftime("%H:%M:%S UTC")
        who.targets[f"{event.get('service') or '-'} {event.get('url.path') or ''}".strip()] += 1
        if event.get("user_agent.original"):
            who.agents.add(str(event["user_agent.original"]))
        if event.get("user.name"):
            who.users.add(str(event["user.name"]))
        if event.get("hedwig.password_fp"):
            who.passwords.add(str(event["hedwig.password_fp"]))
        if event.get("file.hash.sha256"):
            who.files[str(event["file.hash.sha256"])] = str(event.get("file.name") or "(no name)")
    if failures:
        sources = {e.get("source.ip") for e in failures}
        timeline.append(
            {"at": _iso(failures[0]), "ip": f"{len(sources)} sources", "action": "login_failed",
             "rule": "login failures",
             "target": f"{len(failures)} failed logins on {failures[0].get('url.path', '')}"}
        )  # fmt: skip
    if swept:
        timeline.append(
            {"at": _iso(swept[0]), "ip": f"{len({e.get('source.ip') for e in swept})} sources",
             "action": "trapped", "rule": "campaign",
             "target": "named as one campaign by the Scout and drawn into the decoy"}
        )  # fmt: skip
    rules = {r for a in attackers.values() for r in a.rules} | {
        e.get("event.category", "") for e in events
    }
    merged: dict[str, tuple[str, list[str]]] = {}
    for key in sorted(rules):
        if key in ATTACK:
            code, name = ATTACK[key]
            merged.setdefault(code, (name, []))[1].append(key)
    techniques = [(code, name, ", ".join(keys)) for code, (name, keys) in sorted(merged.items())]
    people = sorted(attackers.values(), key=lambda a: a.first)
    critical = bool(honeytokens) or any(set(a.rules) & CRITICAL_RULES for a in people)
    severity = "critical" if critical else ("high" if people else "low")
    actions = _actions(people, honeytokens, campaigns)
    ranked = sorted(people, key=lambda a: (not a.files, not a.banned_at, -a.stopped, a.first))
    shown = ranked[:MAX_SHOWN]
    serious = [a for a in ranked if a.files or a.banned_at or set(a.rules) & CRITICAL_RULES]
    bulk = [a for a in people if a.users and not a.files]
    credential = ""
    if len(bulk) > 1:
        accounts = sorted({u for a in bulk for u in a.users})
        credential = (
            f"{len(bulk)} sources made {sum(a.requests for a in bulk)} login attempts against "
            f"{', '.join(accounts)} (distributed credential attack)."
        )
    return SocData(
        shown=shown,
        more=len(people) - len(shown),
        detailed=(serious or ranked)[:MAX_DETAILED],
        credential=credential,
        since=since.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        until=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        source=source,
        events=len(events),
        attackers=people,
        honeytokens=honeytokens,
        campaigns=[f"{name} ({rule})" if rule else name for name, rule in campaigns.items()],
        timeline=sorted(timeline, key=lambda t: t["at"])[:60],
        techniques=techniques,
        severity=severity,
        actions=actions,
    )


def _actions(people: list[Attacker], honeytokens: list[dict], campaigns: dict) -> list[str]:
    actions = []
    if any(set(a.rules) & CRITICAL_RULES for a in people):
        actions += [
            "Treat the planted files as hostile: keep them (hashes are in the indicators) and "
            "search the other services' upload folders and logs for the same hashes.",
            "Check the bank services for any file or process that should not be there; the Guard "
            "kept the files out, but confirm nothing reached a service.",
        ]
    if honeytokens:
        actions.append(
            "A honeytoken was used: the data it came from exists only inside the decoy, so the "
            "attacker saw decoy content. Rotate any real credential that looks like it."
        )
    if any(a.passwords for a in people) or campaigns:
        actions.append(
            "Credential attack seen: enforce MFA or a per-account throttle, and review failed "
            "logins for the targeted usernames."
        )
    if any(a.banned_at for a in people):
        actions.append("Keep the IP bans in place; block the addresses at the network edge too.")
    return actions or ["No attack activity was found in this window."]


def render(data: SocData) -> str:
    from jinja2 import Environment, FileSystemLoader

    from hedwig.core import report

    env = Environment(
        loader=FileSystemLoader(report.TEMPLATE.parent),
        block_start_string="((*",
        block_end_string="*))",
        variable_start_string="(((",
        variable_end_string=")))",
        comment_start_string="((#",
        comment_end_string="#))",
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(
        tex=report.escape_tex, hl=report.highlight, code=report.code, badge=report.badge
    )
    return env.get_template("soc.tex.j2").render(
        d=data,
        generated=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        severity_color=report.SEVERITY_COLOR.get(data.severity, "low"),
    )


def build_pdf(root: Path, since: str = "30m") -> tuple[Path, SocData]:
    from hedwig.core import report

    cutoff = datetime.now(UTC) - parse_since(since)
    events, source = gather(root, cutoff)
    data = summarise(events, cutoff, source)
    folder = root / report.REPORTS
    folder.mkdir(parents=True, exist_ok=True)
    stem = "SOC-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    tex = folder / f"{stem}.tex"
    tex.write_text(render(data), encoding="utf-8")
    pdf = report.compile_tex(tex)
    return pdf, data
