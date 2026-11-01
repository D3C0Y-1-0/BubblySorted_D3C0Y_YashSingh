"""hedwig watch: find pull requests merged into the project that introduced vulnerable packages,
and contain them. Hedwig scans every merged PR itself, whether or not the PR bot was ever asked.

For each affected service: take it down (when the policy allows), fix it with the minimal change,
bring it back up, and email the PM a report with a UTC timeline of everything that happened.
"""

import json
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hedwig.core import (
    actions,
    audit,
    deploy,
    engine,
    github,
    incidents,
    policy,
    prcheck,
    report,
    runner,
)
from hedwig.core.advisories import AdvisorySource
from hedwig.core.agents import orchestrator
from hedwig.core.models import Finding, Incident, Run

STATE = Path(".hedwig") / "watch.json"
LIST_LIMIT = 30
Say = Callable[[str], None]


@dataclass
class MergedPR:
    number: int
    title: str
    url: str
    merged_at: str
    merged_by: str
    base_ref: str
    head_ref: str
    merge_sha: str
    files: list[str] = field(default_factory=list)
    base_sha: str = ""  # compare against this commit instead of the merge commit's first parent

    @property
    def label(self) -> str:
        """'PR #4', or 'commit abc1234' for a change that was pushed without a PR."""
        return f"PR #{self.number}" if self.number else f"commit {self.merge_sha[:7]}"


def load_state(root: Path) -> dict | None:
    try:
        return json.loads((root / STATE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save_state(root: Path, state: dict) -> None:
    path = root / STATE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def list_merged(repo: Path, slug: str) -> list[MergedPR]:
    fields = "number,title,url,mergedAt,mergedBy,baseRefName,headRefName,mergeCommit,files"
    done = subprocess.run(
        ["gh", "pr", "list", "-R", slug, "--state", "merged", "--limit", str(LIST_LIMIT),
         "--json", fields],
        cwd=repo, capture_output=True, text=True, timeout=60,
    )  # fmt: skip
    if done.returncode != 0:
        raise github.GitHubError(f"gh pr list failed: {done.stderr.strip()[-200:]}")
    found = []
    for item in json.loads(done.stdout):
        commit = (item.get("mergeCommit") or {}).get("oid")
        if not commit:
            continue
        found.append(
            MergedPR(
                number=item["number"],
                title=item["title"],
                url=item["url"],
                merged_at=item["mergedAt"],
                merged_by=(item.get("mergedBy") or {}).get("login", ""),
                base_ref=item["baseRefName"],
                head_ref=item["headRefName"],
                merge_sha=commit,
                files=[f["path"] for f in item.get("files") or []],
            )
        )
    return sorted(found, key=lambda p: p.merged_at)


def affected_services(
    repo: Path, specs: list[engine.ServiceSpec], pr: MergedPR
) -> list[engine.ServiceSpec]:
    """The services whose folder the PR touched."""
    hit = []
    for spec in specs:
        prefix = spec.folder.resolve().relative_to(repo).as_posix()
        if any(f == prefix or f.startswith(prefix + "/") for f in pr.files):
            hit.append(spec)
    return hit


def update_local(repo: Path, base_ref: str) -> str | None:
    """Bring the merged code into the local checkout. Returns an error message, or None."""
    fetched = runner.git(repo, "fetch", "origin", base_ref)
    if fetched.returncode != 0:
        return f"git fetch failed: {fetched.stderr.strip()[-200:]}"
    current = runner.git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    if current != base_ref:
        return f"you are on '{current}', not '{base_ref}', so the merged code was not pulled"
    merged = runner.git(repo, *runner.BOT, "merge", "--no-edit", f"origin/{base_ref}")
    if merged.returncode != 0:
        runner.git(repo, "merge", "--abort")
        return (
            f"could not merge origin/{base_ref}: {(merged.stderr or merged.stdout).strip()[-200:]}"
        )
    return None


def _run_events(incident: Incident, run: Run) -> None:
    incidents.event(incident, "fix started", f"{run.package} {run.from_version} to "
                    f"{run.to_version or '?'}", at=run.started_at[:19] + "+00:00")  # fmt: skip
    for step in run.steps:
        stamp = step.at[:19] + "+00:00"
        if step.name == "publish" and step.status == "ok":
            incidents.event(incident, "fix pull request opened", step.detail, at=stamp)
        elif step.name == "verifier" and step.status == "ok":
            incidents.event(incident, "fix verified", "", at=stamp)
        elif step.name == "act" and step.status == "ok" and run.action in (
            "merged", "rolled_back", "deploy_failed"
        ):  # fmt: skip
            incidents.event(incident, "fix merged into local main", run.branch, at=stamp)
        elif step.name == "deploy" and step.status == "ok":
            incidents.event(incident, "image rebuilt", step.detail, at=stamp)
    if run.state == "skipped":
        reason = next((st.detail for st in run.steps if st.status == "skipped"), "")
        incidents.event(
            incident, "fix skipped", f"{run.package}: {reason}",
            at=(run.finished_at or incidents.now())[:19] + "+00:00",
        )  # fmt: skip
    elif run.state != "verified":
        incidents.event(
            incident, "fix not verified",
            f"{run.package}: verification {run.verification or 'failed'}",
            at=(run.finished_at or incidents.now())[:19] + "+00:00",
        )  # fmt: skip


def _is_up(root: Path, service: str) -> bool:
    if deploy.compose_file(root) is not None:
        # "starting" is a container whose healthcheck has not run yet; it is up
        return deploy.status(root, [service])[service] in ("active", "starting")
    return not actions.is_down(root, service)


def handle_service(
    root: Path,
    repo: Path,
    pr: MergedPR,
    spec: engine.ServiceSpec,
    found: list[Finding],
    source: AdvisorySource,
    detected: str,
    say: Say,
    email: bool,
    local_error: str | None = None,
) -> Incident:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    incident = Incident(
        incident_id=f"{stamp}-{spec.name}-" + (f"pr{pr.number}" if pr.number else pr.merge_sha[:7]),
        service=spec.name,
        pr_number=pr.number,
        pr_url=pr.url,
        pr_title=pr.title,
        merged_by=pr.merged_by,
        findings=found,
    )
    incidents.event(
        incident, "PR merged" if pr.number else "change pushed",
        f"{'#' + str(pr.number) + ' ' if pr.number else ''}{pr.title} by {pr.merged_by}",
        at=pr.merged_at[:19] + "+00:00",
    )  # fmt: skip
    ids = ", ".join(sorted({f.id for f in found})[:4])
    incidents.event(
        incident, "vulnerable merge detected", f"{len(found)} finding(s): {ids}", at=detected
    )
    incidents.save(root, incident)
    say(f"[bold]{spec.name}[/bold]: {pr.label} introduced {len(found)} finding(s) ({ids})")

    if local_error:
        # Without the merged code here Hedwig cannot fix anything, so it must not take the
        # service down either: that would leave it down with no way back.
        incidents.event(incident, "response stopped", f"local checkout not updated: {local_error}")
        incident.state = "failed"
        say(f"  [red]{spec.name}: response stopped, {local_error}[/red]")
        return _close(root, incident, email, say)

    decision = policy.decide_incident(spec.allow)
    if decision.action == "takedown":
        note = actions.takedown(root, spec.name, f"vulnerable change ({pr.label}) merged")
        incidents.event(incident, "service taken down", note)
        say(f"  {spec.name} taken down ({note})")
    else:
        incidents.event(incident, "takedown skipped", decision.reason)
    incidents.save(root, incident)

    # fresh findings from the merged tree: they carry the decision and the fix version
    introduced = {(f.package, f.version) for f in found}
    current = engine.scan(root, source, save=True).findings
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in current:
        if f.service == spec.name and (f.package, f.version) in introduced:
            groups.setdefault((f.package, f.version), []).append(f)
    merged_any = False
    for (package, version), group in groups.items():
        say(f"  fixing {package} {version}")

        def on_step(_run: Run, step, say: Say = say) -> None:
            tag = {"running": "...", "ok": "ok", "failed": "FAILED", "skipped": "skipped"}
            mark = tag.get(step.status, step.status)
            line = f"    {step.name}: {mark}"
            if step.detail:
                line += f" — {step.detail[:160]}"
            say(line)

        run = orchestrator.run_fix(root, group, spec, source, on_step=on_step, publish=True)
        incident.run_ids.append(run.run_id)
        _run_events(incident, run)
        merged_any = merged_any or run.action in ("merged", "rolled_back")
        say(f"  {package}: {run.state}, {run.action}" + (f" ({run.pr_url})" if run.pr_url else ""))
        incidents.save(root, incident)

    if decision.action == "takedown" and merged_any and not _is_up(root, spec.name):
        incidents.event(incident, "bringing the service up", "")
        actions.resume(root, spec.name)
    up = _is_up(root, spec.name)
    if decision.action == "takedown" and up:
        incidents.event(incident, "service healthy again", "")
    incident.state = "contained" if up else "down"
    incident.downtime_seconds = incidents.downtime(incident)
    return _close(root, incident, email, say)


def _close(root: Path, incident: Incident, email: bool, say: Say) -> Incident:
    """Stamp the timeline, email the report and save the incident."""
    incident.timeline.sort(key=lambda e: e.at)
    if email:
        incidents.event(incident, "report emailed to PM", "")
        incidents.save(root, incident)
        sent = report.send_incident_report(root, incident)
        incident.report = sent.message
        say(f"  {sent.message}" if sent.ok else f"  [red]report NOT sent:[/red] {sent.message}")
    incidents.save(root, incident)
    audit.record(root, "incident", incident=incident.incident_id, state=incident.state)
    return incident


def respond(
    root: Path,
    repo: Path,
    pr: MergedPR,
    source: AdvisorySource,
    min_severity: str,
    say: Say,
    email: bool,
) -> list[Incident]:
    """Check one merged PR and contain every service it made vulnerable."""
    detected = incidents.now()
    specs = engine.resolve_services(root, "medium")
    touched = affected_services(repo, specs, pr)
    if not touched:
        return []
    before = pr.base_sha or f"{pr.merge_sha}^1"
    parent = runner.git(repo, "rev-parse", before)
    if parent.returncode != 0:
        say(f"{pr.label}: commit {pr.merge_sha[:7]} is not here yet, fetching")
        runner.git(repo, "fetch", "origin", pr.base_ref)
        parent = runner.git(repo, "rev-parse", before)
    if parent.returncode != 0:
        say(f"[red]{pr.label}: cannot find its commits locally[/red]")
        return []
    relative = root.resolve().relative_to(repo).as_posix() or "."
    found = prcheck.at_least(
        prcheck.introduced(repo, parent.stdout.strip(), pr.merge_sha, source, [relative]),
        min_severity,
    )
    touched_names = {s.name for s in touched}
    found = [f for f in found if f.service in touched_names]
    flagged = [f for f in found if f.kind in ("typosquat", "install-script")]
    for f in flagged:  # heuristics need a human: say so, but never take a service down for them
        say(f"[yellow]{pr.label}: {f.service}: {f.summary}[/yellow]")
        audit.record(root, "flagged", pr=pr.number, service=f.service, id=f.id, kind=f.kind)
    found = [f for f in found if f not in flagged]
    if not found:
        say(f"{pr.label} '{pr.title}': introduced nothing vulnerable")
        return []
    error = update_local(repo, pr.base_ref)
    if error:
        say(f"[yellow]{error}[/yellow]")
    result = []
    for spec in touched:
        mine = [f for f in found if f.service == spec.name]
        if mine:
            result.append(
                handle_service(root, repo, pr, spec, mine, source, detected, say, email, error)
            )
    return result


def watch(
    root: Path,
    source: AdvisorySource,
    say: Say,
    interval: int = 20,
    once: bool = False,
    since_minutes: int = 0,
    min_severity: str = "low",
    email: bool = True,
    slug: str | None = None,
) -> None:
    repo = prcheck.toplevel(root)
    reason = github.unavailable(repo)
    if reason:
        raise github.GitHubError(reason)
    slug = slug or github.origin_slug(repo)
    if not slug:
        raise github.GitHubError("origin is not on GitHub")
    state = load_state(root)
    if state is None:
        cutoff = datetime.now(UTC) - timedelta(minutes=since_minutes)
        old = [
            p.number
            for p in list_merged(repo, slug)
            if datetime.fromisoformat(p.merged_at.replace("Z", "+00:00")) < cutoff
        ]
        state = {"seen": old, "started": incidents.now()}
        save_state(root, state)
        say(f"Watching {slug}: {len(old)} earlier merged PR(s) are ignored.")
    while True:
        try:
            prs = list_merged(repo, slug)
        except (github.GitHubError, subprocess.TimeoutExpired, OSError) as err:
            say(f"[yellow]could not list PRs: {err}[/yellow]")
            prs = []
        for pr in prs:
            if pr.number in state["seen"] or pr.head_ref.startswith("hedwig/"):
                continue
            say(f"New merged PR #{pr.number}: {pr.title}")
            try:
                respond(root, repo, pr, source, min_severity, say, email)
            except Exception as err:  # one bad PR must not stop the watch
                say(f"[red]PR #{pr.number}: {type(err).__name__}: {err}[/red]")
            state["seen"].append(pr.number)
            save_state(root, state)
        if once:
            return
        time.sleep(interval)


def _branch_change(repo: Path, slug: str | None, branch: str, last: str, tip: str) -> MergedPR:
    """Describe what landed on the branch between two commits, as a PR when GitHub knows one."""
    subject = runner.git(repo, "log", "-1", "--format=%s", tip).stdout.strip()
    author = runner.git(repo, "log", "-1", "--format=%an", tip).stdout.strip()
    stamp = runner.git(repo, "log", "-1", "--format=%cI", tip).stdout.strip()
    files = runner.git(repo, "diff", "--name-only", last, tip).stdout.split()
    commits = set(runner.git(repo, "rev-list", f"{last}..{tip}").stdout.split())
    base = MergedPR(0, subject, "", stamp, author, branch, "", tip, files, base_sha=last)
    if not slug or github.unavailable(repo):
        return base
    try:
        for pr in list_merged(repo, slug):
            if pr.base_ref == branch and pr.merge_sha in commits:
                pr.files, pr.base_sha = files or pr.files, last
                return pr
    except (github.GitHubError, subprocess.TimeoutExpired, OSError):
        pass
    return base


def watch_branch(
    root: Path,
    source: AdvisorySource,
    say: Say,
    branch: str,
    interval: int = 20,
    once: bool = False,
    min_severity: str = "low",
    email: bool = True,
) -> None:
    """Watch one branch of origin: every new commit range that introduces vulnerable packages
    (a PR merged on GitHub, or a plain git merge and push) is contained, like a merged PR."""
    repo = prcheck.toplevel(root)
    slug = github.origin_slug(repo)
    state = load_state(root)
    if state is None or state.get("branch") != branch:
        runner.git(repo, "fetch", "-q", "origin", branch)
        tip = runner.git(repo, "rev-parse", f"origin/{branch}")
        if tip.returncode != 0:
            raise github.GitHubError(f"origin has no branch '{branch}' yet")
        state = {"branch": branch, "last": tip.stdout.strip(), "started": incidents.now()}
        save_state(root, state)
        say(f"Watching origin/{branch} from {state['last'][:7]}: older commits are ignored.")
    while True:
        runner.git(repo, "fetch", "-q", "origin", branch)
        tip = runner.git(repo, "rev-parse", f"origin/{branch}").stdout.strip()
        if tip and tip != state["last"]:
            say(f"New commits on {branch}: {state['last'][:7]}..{tip[:7]}")
            change = _branch_change(repo, slug, branch, state["last"], tip)
            try:
                respond(root, repo, change, source, min_severity, say, email)
            except Exception as err:  # one bad change must not stop the watch
                say(f"[red]{change.label}: {type(err).__name__}: {err}[/red]")
            state["last"] = tip
            save_state(root, state)
        if once:
            return
        time.sleep(interval)
