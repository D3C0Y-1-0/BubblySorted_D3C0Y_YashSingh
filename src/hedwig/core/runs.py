"""Where fix runs live on disk: .hedwig/runs/<run-id>/ with run.json and the other artifacts."""

import json
from pathlib import Path

from pydantic import ValidationError

from hedwig.core.models import Run

RUNS = Path(".hedwig") / "runs"
WORK = Path(".hedwig") / "work"


def run_dir(root: Path, run_id: str) -> Path:
    return root / RUNS / run_id


def save(root: Path, run: Run) -> None:
    folder = run_dir(root, run.run_id)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "run.json").write_text(run.model_dump_json(indent=2), encoding="utf-8")


def load(root: Path, run_id: str) -> Run | None:
    path = run_dir(root, run_id) / "run.json"
    try:
        return Run.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError):
        return None


def load_all(root: Path) -> list[Run]:
    """Every run, newest first."""
    base = root / RUNS
    if not base.is_dir():
        return []
    runs = [r for p in sorted(base.iterdir()) if (r := load(root, p.name))]
    return sorted(runs, key=lambda r: r.started_at, reverse=True)


def write_artifact(root: Path, run_id: str, name: str, data) -> None:
    path = run_dir(root, run_id) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    text = data if isinstance(data, str) else json.dumps(data, indent=2)
    path.write_text(text, encoding="utf-8")
