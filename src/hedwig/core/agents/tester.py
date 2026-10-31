"""Tester: black-box HTTP cases that exercise the code using the bumped package."""

import json
from pathlib import Path

from pydantic import BaseModel

from hedwig.core import llm
from hedwig.core.agents import prompt, snippets
from hedwig.core.models import Finding

MAX_CASES = 6


class Case(BaseModel):
    method: str = "GET"
    path: str
    body: object | None = None
    headers: dict[str, str] = {}


class TesterOutput(BaseModel):
    cases: list[Case] = []


def known_requests(folder: Path) -> list[dict]:
    path = folder / "hedwig.requests.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def propose(root: Path, folder: Path, finding: Finding) -> list[Case]:
    user = (
        f"Package: {finding.package}\n\n"
        f"Call sites:\n{snippets(folder, finding.call_sites)}\n\n"
        f"Known requests: {json.dumps(known_requests(folder))}\n\n"
        "Answer with the JSON object."
    )
    out = llm.chat(root, "tester", prompt("tester"), user, TesterOutput, max_tokens=500)
    safe = [c for c in out.cases if c.method.upper() in ("GET", "POST") and c.path.startswith("/")]
    return safe[:MAX_CASES]
