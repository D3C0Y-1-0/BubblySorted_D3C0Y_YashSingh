"""Verifier: reviews the diff against the minimal-change rules. It can only veto."""

from pathlib import Path

from pydantic import BaseModel

from hedwig.core import llm
from hedwig.core.agents import prompt

MAX_DIFF_CHARS = 14_000


class Review(BaseModel):
    approve: bool = False
    violations: list[str] = []


def review(root: Path, diff: str, checks: list[str]) -> Review:
    user = (
        "Automated checks:\n- " + "\n- ".join(checks) + "\n\n"
        f"Diff:\n{diff[:MAX_DIFF_CHARS]}\n\nAnswer with the JSON object."
    )
    return llm.chat(root, "verifier", prompt("verifier"), user, Review)
