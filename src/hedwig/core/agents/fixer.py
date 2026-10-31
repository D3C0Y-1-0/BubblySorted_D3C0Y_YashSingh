"""Fixer: the smallest source edit that keeps the service working on the bumped dependency."""

from pathlib import Path

from pydantic import BaseModel

from hedwig.core import llm
from hedwig.core.agents import advisory_block, file_contents, prompt, snippets
from hedwig.core.models import Edit, Finding


class FixerOutput(BaseModel):
    edits: list[Edit] = []
    rationale: str = ""


def propose(
    root: Path,
    folder: Path,
    finding: Finding,
    target: str,
    allowed: list[str],
    failures: list[str],
) -> FixerOutput:
    retry = (
        "\nThe previous attempt failed. Fix exactly these problems:\n- " + "\n- ".join(failures)
        if failures
        else ""
    )
    user = (
        f"{advisory_block(finding)}\n\n"
        f"Package: {finding.package} ({finding.ecosystem}), {finding.version} -> {target}.\n"
        f"Allowed files: {', '.join(allowed)}\n\n"
        f"Call sites:\n{snippets(folder, finding.call_sites)}\n\n"
        f"Current content of the allowed files:\n{file_contents(folder, allowed)}\n"
        f"{retry}\nAnswer with the JSON object."
    )
    return llm.chat(root, "fixer", prompt("fixer"), user, FixerOutput, max_tokens=1000)
