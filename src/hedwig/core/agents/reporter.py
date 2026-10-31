"""Reporter: the words for the PR and the project manager. No say in the decision."""

from pathlib import Path

from pydantic import BaseModel

from hedwig.core import llm
from hedwig.core.agents import advisory_block, prompt
from hedwig.core.models import Finding, Run


class Text(BaseModel):
    pr_title: str = ""
    pr_body: str = ""
    report_summary: str = ""


def write(root: Path, finding: Finding, run: Run, diff_stat: str, checks: list[str]) -> Text:
    decision = run.decision.reason if run.decision else "none"
    user = (
        f"{advisory_block(finding)}\n\n"
        f"Service {run.service}: {run.package} {run.from_version} -> {run.to_version}.\n"
        f"Verified: {run.state == 'verified'}. Planned action: {run.action}. Policy: {decision}.\n"
        f"Diff summary:\n{diff_stat}\n\nChecks:\n- " + "\n- ".join(checks) + "\n\n"
        "Answer with the JSON object."
    )
    return llm.chat(root, "reporter", prompt("reporter"), user, Text)
