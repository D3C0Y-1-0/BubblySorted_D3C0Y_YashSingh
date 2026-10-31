"""Reporting to the project manager over SMTP.

Digest: the first unreported event starts a timer (default 30 s); then one email goes out and a
cool-down starts (default 5 min), so a burst of 10,000 blocks sends one email. The Commander
writes the summary; without the agents a plain template is used.

Honeytoken use sends an email immediately, outside the timer.

A failed email never affects proxying: sending happens off the request path in a worker thread,
and every failure is caught and logged.
"""

import os
import smtplib
import ssl
import threading
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Any

REPORTABLE = {"blocked", "banned", "trapped"}  # a decision worth telling the PM about


MAX_ATTACKERS = 10


def _hedwig_settings() -> dict[str, str]:
    """Hedwig's saved settings, if there are any (a plain TOML file of strings)."""
    path = Path.home() / ".hedwig" / "config.toml"
    try:
        return {k: str(v) for k, v in tomllib.loads(path.read_text(encoding="utf-8")).items()}
    except (OSError, ValueError):
        return {}


def _when(stamp: str | None) -> str:
    """An event's ISO timestamp as a UTC time of day."""
    if not stamp:
        return "?"
    try:
        return datetime.fromisoformat(stamp).astimezone(UTC).strftime("%H:%M:%S")
    except ValueError:
        return stamp


@dataclass
class Attacker:
    """What one source address did since the last digest, for the PM."""

    ip: str
    first_seen: str = ""
    targets: dict[str, int] = field(default_factory=dict)  # "service /path" -> requests stopped
    rules: dict[str, int] = field(default_factory=dict)  # rule -> times it caught this client
    stopped: int = 0
    decoy: int = 0  # requests the decoy bank answered instead of the real one
    trapped_at: str = ""
    banned_at: str = ""
    banned_until: str = ""
    ban_reason: str = ""

    def lines(self) -> list[str]:
        target = max(self.targets, key=self.targets.get) if self.targets else "-"
        out = [f"- {self.ip}  targeted {target}"]
        steps = [f"first seen {_when(self.first_seen)}"]
        if self.trapped_at:
            steps.append(f"trapped in the decoy bank at {_when(self.trapped_at)}")
        if self.banned_at:
            until = f" until {self.banned_until}" if self.banned_until else ""
            steps.append(f"banned at {_when(self.banned_at)}{until} ({self.ban_reason})")
        out.append("    " + ", ".join(steps) + " (UTC)")
        rules = ", ".join(f"{r} x{n}" for r, n in sorted(self.rules.items(), key=lambda i: -i[1]))
        out.append(
            f"    stopped {self.stopped} request(s); the decoy answered {self.decoy}; "
            f"caught by: {rules or '-'}"
        )
        return out


@dataclass
class SmtpConfig:
    host: str = ""
    port: int = 587
    user: str = ""
    password: str = ""
    to: str = ""
    sender: str = ""

    @classmethod
    def from_env(cls) -> "SmtpConfig":
        """The environment first, then Hedwig's ~/.hedwig/config.toml, so the demo is set up in
        one place (`hedwig config`). `to` may hold several addresses, comma separated."""
        env = os.environ.get
        saved = _hedwig_settings()
        user = env("SMTP_USER", "") or saved.get("smtp_user", "")
        return cls(
            host=env("SMTP_HOST", "")
            or saved.get("smtp_host", "")
            or ("smtp.gmail.com" if user else ""),
            port=int(env("SMTP_PORT", "") or saved.get("smtp_port", "") or 587),
            user=user,
            password=env("SMTP_PASS", "") or saved.get("smtp_pass", ""),
            to=env("PM_EMAIL", "") or saved.get("pm_email", ""),
            sender=env("SMTP_FROM", "") or user,
        )

    @property
    def ready(self) -> bool:
        return bool(self.host and self.to and self.sender)


def send_smtp(cfg: SmtpConfig, subject: str, body: str) -> None:
    """Blocking SMTP send (Gmail on 587 with STARTTLS by default). Runs in a worker thread."""
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg.sender
    message["To"] = cfg.to
    message.set_content(body)
    context = ssl.create_default_context()
    with smtplib.SMTP(cfg.host, cfg.port, timeout=10) as server:
        server.ehlo()
        if server.has_extn("starttls"):
            server.starttls(context=context)
            server.ehlo()
        if cfg.user and cfg.password:
            server.login(cfg.user, cfg.password)
        server.send_message(message)


class PMNotifier:
    def __init__(
        self,
        config: SmtpConfig | None = None,
        *,
        digest_delay_s: float = 30,
        cooldown_s: float = 300,
        send: Callable[[SmtpConfig, str, str], None] = send_smtp,
        summary: Callable[[], str] | None = None,
        kibana_url: str = "",
        clock: Callable[[], float] = time.monotonic,
        log: Callable[[str], None] = print,
    ) -> None:
        self.config = config or SmtpConfig.from_env()
        self.digest_delay_s = digest_delay_s
        self.cooldown_s = cooldown_s
        self._send = send
        self.summary = summary or (lambda: "")
        self.kibana_url = kibana_url
        self.clock = clock
        self.log = log
        self._lock = threading.Lock()
        self.pending_since: float | None = None
        self.pending: dict[str, int] = {}  # action -> count since the last digest
        self.attackers: dict[str, Attacker] = {}  # ip -> what it did since the last digest
        self.cooldown_until = 0.0
        self.sent = 0  # digests sent
        self.alarms_sent = 0

    @property
    def active(self) -> bool:
        return self.config.ready

    # -- inputs (called inline from the event bus; stay cheap, never raise) ----------------
    def on_event(self, event: dict[str, Any]) -> None:
        action = event.get("event.action")
        if action not in REPORTABLE or event.get("hedwig.monitor"):
            return
        with self._lock:
            self.pending[action] = self.pending.get(action, 0) + 1
            self._note_attacker(action, event)
            if self.pending_since is None:
                self.pending_since = self.clock()

    def _note_attacker(self, action: str, event: dict[str, Any]) -> None:
        ip = event.get("source.ip")
        if not ip:
            return
        stamp = event.get("@timestamp", "")
        who = self.attackers.setdefault(ip, Attacker(ip=ip, first_seen=stamp))
        if action == "trapped" and event.get("hedwig.decoy"):
            who.decoy += 1
            who.trapped_at = who.trapped_at or stamp
            return
        rule = event.get("rule") or event.get("event.category") or "?"
        who.rules[rule] = who.rules.get(rule, 0) + 1
        if action == "trapped":
            who.trapped_at = who.trapped_at or stamp
        elif action == "banned":
            who.banned_at = who.banned_at or stamp
            who.ban_reason = rule
            minutes = event.get("hedwig.ban_minutes")
            if minutes and stamp:
                try:
                    start = datetime.fromisoformat(stamp)
                    who.banned_until = (
                        (start + timedelta(minutes=minutes))
                        .astimezone(UTC)
                        .strftime("%H:%M:%S UTC")
                    )
                except ValueError:
                    pass
        else:
            who.stopped += 1
        target = f"{event.get('service') or '-'} {event.get('url.path') or ''}".strip()
        who.targets[target] = who.targets.get(target, 0) + 1

    def _alarm_attackers(self, alarm: dict[str, Any]) -> str:
        with self._lock:
            mine = [self.attackers[ip] for ip in (alarm.get("issued_to"), alarm.get("ip"))
                    if ip in self.attackers]  # fmt: skip
        return "\n" + self._attackers_text(mine) if mine else ""

    def _attackers_text(self, attackers: list[Attacker]) -> str:
        if not attackers:
            return ""
        shown = sorted(attackers, key=lambda a: a.first_seen)[:MAX_ATTACKERS]
        lines = ["Attackers:"]
        for attacker in shown:
            lines += attacker.lines()
        if len(attackers) > len(shown):
            lines.append(f"- ...and {len(attackers) - len(shown)} more")
        return "\n".join(lines) + "\n\n"

    def on_alarm(self, alarm: dict[str, Any]) -> None:
        """A honeytoken alarm: email at once, outside the digest timer."""
        subject = f"[Chakravyuha] Honeytoken used from {alarm.get('ip')}"
        body = (
            f"A honeytoken ({alarm.get('kind')}) was used from {alarm.get('ip')}.\n"
            f"It was planted for the trapped client {alarm.get('issued_to')}.\n"
            f"Path: {alarm.get('path')}\n"
            f"Banned: {', '.join(alarm.get('banned') or []) or 'none'}\n"
            f"This value only exists inside the decoy bank, so its use is a certain compromise.\n"
            + self._alarm_attackers(alarm)
            + self._kibana_line()
        )
        self.alarms_sent += 1
        self._dispatch(subject, body)

    # -- the timer (called from the Guard's slow loop) -------------------------------------
    def poll(self) -> bool:
        """Send the digest if the timer has elapsed and the cool-down has passed. Returns sent."""
        with self._lock:
            now = self.clock()
            if self.pending_since is None or now - self.pending_since < self.digest_delay_s:
                return False
            if now < self.cooldown_until:
                return False
            counts, self.pending = self.pending, {}
            attackers, self.attackers = list(self.attackers.values()), {}
            self.pending_since = None
            self.cooldown_until = now + self.cooldown_s
            self.sent += 1
        total = sum(counts.values())
        detail = ", ".join(f"{n} {action}" for action, n in sorted(counts.items()))
        summary = self.summary().strip()
        body = (
            f"The Guard handled {total} blocked or trapped requests ({detail}).\n\n"
            + (summary + "\n\n" if summary else "")
            + self._attackers_text(attackers)
            + self._kibana_line()
        )
        self._dispatch(f"[Chakravyuha] {total} requests stopped", body)
        return True

    def _kibana_line(self) -> str:
        return f"Investigate in Kibana: {self.kibana_url}\n" if self.kibana_url else ""

    def _dispatch(self, subject: str, body: str) -> None:
        if not self.active:
            self.log(f"chakravyuha: (no SMTP configured) would email PM: {subject}")
            return
        threading.Thread(
            target=self._worker, args=(subject, body), name="chakravyuha-pm", daemon=True
        ).start()

    def _worker(self, subject: str, body: str) -> None:
        try:
            self._send(self.config, subject, body)
            self.log(f"chakravyuha: emailed the PM: {subject}")
        except Exception as error:  # a failed email must never affect proxying
            self.log(f"chakravyuha: PM email failed ({type(error).__name__}: {error})")
