"""Append-only audit log: one JSON line per agent call and per decision."""

import json
from datetime import UTC, datetime
from pathlib import Path

AUDIT = Path(".hedwig") / "audit.jsonl"


def record(root: Path, kind: str, **data) -> None:
    path = root / AUDIT
    path.parent.mkdir(parents=True, exist_ok=True)
    line = {"at": datetime.now(UTC).isoformat(), "kind": kind, **data}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")


def read(root: Path) -> list[dict]:
    path = root / AUDIT
    if not path.is_file():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries
