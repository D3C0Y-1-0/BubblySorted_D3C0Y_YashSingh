"""What Hedwig does once the policy gate has decided. Every action is audited.

Merge is real (a fast-forward of the fix branch). Takedown is only recorded until the executor
arrives with the deployment phase.
"""

import json
from pathlib import Path

from hedwig.core import audit, deploy, report, runner
from hedwig.core.models import Run

STATE = Path(".hedwig") / "state.json"


def load_state(root: Path) -> dict:
    try:
        return json.loads((root / STATE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"down": {}}


def _save_state(root: Path, state: dict) -> None:
    path = root / STATE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def merge(root: Path, top: Path, branch: str, service: str) -> str | None:
    """Fast-forward the current branch to the fix branch. Returns an error, or None on success."""
    done = runner.git(top, "merge", "--ff-only", branch)
    ok = done.returncode == 0
    audit.record(root, "action", action="merge", service=service, branch=branch, ok=ok)
    return None if ok else (done.stderr or done.stdout).strip()[-300:]


def takedown(root: Path, service: str, reason: str) -> str:
    """Stop the service (`docker compose stop`) when there is a compose file, and record it.

    Returns what happened, so callers can show it. Without a compose file the takedown is
    only recorded, as before.
    """
    try:
        deploy.stop(root, service)
        note = "stopped with docker compose"
    except deploy.DeployError as err:
        note = f"recorded only ({err})"
    state = load_state(root)
    state.setdefault("down", {})[service] = {"reason": reason, "status": note}
    _save_state(root, state)
    audit.record(root, "action", action="takedown", service=service, reason=reason, result=note)
    return note


def resume(root: Path, service: str) -> str:
    """Start the service again and clear its down record."""
    try:
        deploy.start(root, service)
        note = "started with docker compose"
    except deploy.DeployError as err:
        note = f"record cleared only ({err})"
    state = load_state(root)
    state.setdefault("down", {}).pop(service, None)
    _save_state(root, state)
    audit.record(root, "action", action="resume", service=service, result=note)
    return note


def is_down(root: Path, service: str) -> bool:
    return service in load_state(root).get("down", {})


def save_pr(root: Path, run: Run, title: str, body: str, label: str) -> Path:
    """The pull request text, ready for the GitHub phase to open."""
    from hedwig.core import runs

    text = f"# {title}\n\nLabel: `{label}`\nBranch: `{run.branch}`\n\n{body}\n"
    runs.write_artifact(root, run.run_id, "pr.md", text)
    audit.record(root, "action", action="save_pr", run=run.run_id, label=label)
    return runs.run_dir(root, run.run_id) / "pr.md"


def notify_pm(root: Path, service: str, reason: str) -> report.Sent:
    """Email the project manager the service report. Never raises; the result says what happened."""
    sent = report.send_service_report(root, service)
    audit.record(
        root, "action", action="notify_pm", service=service, reason=reason, ok=sent.ok,
        message=sent.message[:300], pdf=str(sent.pdf or ""),
    )  # fmt: skip
    return sent
