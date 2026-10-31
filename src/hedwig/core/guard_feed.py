"""Attack reports from the Guard (plan/guardPLAN.md), read through its events endpoint.

Configured by `guard: {url: http://localhost:8080}` in .hedwig.yml and the token in the
HEDWIG_GUARD_TOKEN environment variable (or the `guard_token` setting). Fields are read
defensively because the Guard is built in parallel and its schema may change.
"""

import os
from dataclasses import dataclass
from pathlib import Path

import httpx

from hedwig import config, settings

TIMEOUT = 3
MAX_EVENTS = 100


@dataclass
class Attack:
    time: str
    category: str
    source: str
    action: str
    detail: str


def _dig(event: dict, dotted: str) -> str:
    """event["a.b"] or event["a"]["b"], whichever the Guard emitted."""
    if dotted in event:
        return str(event[dotted])
    value = event
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return ""
        value = value[part]
    return str(value)


def _first(event: dict, *names: str) -> str:
    return next((v for n in names if (v := _dig(event, n))), "")


def settings_for(root: Path) -> tuple[str, str]:
    """(url, token); the url is empty when the Guard is not configured."""
    guard = (config.load_project(root) or {}).get("guard") or {}
    token = os.environ.get("HEDWIG_GUARD_TOKEN") or settings.load().get("guard_token", "")
    return str(guard.get("url") or "").rstrip("/"), token


def fetch(root: Path) -> tuple[list[Attack], str]:
    """The Guard's latest events, newest first, and a note when they cannot be read."""
    url, token = settings_for(root)
    if not url:
        return [], "Guard not configured (add `guard: {url: ...}` to .hedwig.yml)"
    try:
        response = httpx.get(
            f"{url}/__hedwig/events",
            headers={"Authorization": f"Bearer {token}"} if token else {},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as err:
        return [], f"Guard at {url} unreachable: {type(err).__name__}"
    events = data.get("events", []) if isinstance(data, dict) else data
    attacks = [
        Attack(
            time=_first(e, "@timestamp", "timestamp", "time"),
            category=_first(e, "hedwig.category", "event.category", "category", "rule"),
            source=_first(e, "source.ip", "client_ip", "ip"),
            action=_first(e, "event.action", "action"),
            detail=_first(e, "url.path", "path", "message"),
        )
        for e in events
        if isinstance(e, dict)
    ]
    return sorted(attacks, key=lambda a: a.time, reverse=True)[:MAX_EVENTS], ""
