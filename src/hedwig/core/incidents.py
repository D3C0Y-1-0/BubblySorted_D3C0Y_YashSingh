"""Incident records on disk: .hedwig/incidents/<id>.json."""

from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from hedwig.core.models import Incident, TimelineEvent

INCIDENTS = Path(".hedwig") / "incidents"


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def event(incident: Incident, name: str, detail: str = "", at: str | None = None) -> None:
    incident.timeline.append(TimelineEvent(at=at or now(), event=name, detail=detail))


def save(root: Path, incident: Incident) -> None:
    path = root / INCIDENTS / f"{incident.incident_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(incident.model_dump_json(indent=2), encoding="utf-8")


def load(root: Path, incident_id: str) -> Incident | None:
    path = root / INCIDENTS / f"{incident_id}.json"
    try:
        return Incident.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError):
        return None


def load_all(root: Path) -> list[Incident]:
    """Newest first."""
    folder = root / INCIDENTS
    if not folder.is_dir():
        return []
    found = [i for p in sorted(folder.glob("*.json")) if (i := load(root, p.stem))]
    return sorted(found, key=lambda i: i.timeline[0].at if i.timeline else "", reverse=True)


def downtime(incident: Incident) -> float | None:
    """Seconds between the takedown and the service being healthy again, when both happened."""
    stamps = {e.event: e.at for e in incident.timeline}
    down, up = stamps.get("service taken down"), stamps.get("service healthy again")
    if not (down and up):
        return None
    return (datetime.fromisoformat(up) - datetime.fromisoformat(down)).total_seconds()
