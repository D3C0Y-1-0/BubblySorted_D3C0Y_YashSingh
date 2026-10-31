"""The local deployment: a Docker Compose project. Thin wrappers over the `docker compose` CLI.

The compose file is `compose:` in .hedwig.yml, else the first of the usual names under the
root. A Hedwig service maps to the compose service of the same name, or `compose_service:`.
"""

import json
import shutil
import subprocess
import time
from pathlib import Path

import httpx

from hedwig import config

COMPOSE_NAMES = ("docker-compose.yml", "compose.yaml", "deploy/docker-compose.yml")
TIMEOUT = 20
START_TIMEOUT = 120


class DeployError(Exception):
    pass


def compose_file(root: Path) -> Path | None:
    project = config.load_project(root) or {}
    if project.get("compose"):
        path = root / project["compose"]
        return path if path.is_file() else None
    return next((root / n for n in COMPOSE_NAMES if (root / n).is_file()), None)


def compose_name(root: Path, service: str) -> str:
    """The compose service that runs this Hedwig service."""
    raw = ((config.load_project(root) or {}).get("services") or {}).get(service) or {}
    return raw.get("compose_service") or service


def _run(root: Path, args: list[str], timeout: int) -> subprocess.CompletedProcess:
    file = compose_file(root)
    if file is None:
        raise DeployError("no compose file found (set `compose:` in .hedwig.yml)")
    if not shutil.which("docker"):
        raise DeployError("docker is not installed")
    try:
        return subprocess.run(
            ["docker", "compose", "-f", str(file), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as err:
        raise DeployError(f"docker compose {' '.join(args)} timed out") from err


def _rows(text: str) -> list[dict]:
    """`docker compose ps --format json` prints one object per line, or one array."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows


def _state(row: dict) -> str:
    state, health = row.get("State", ""), row.get("Health", "")
    if state == "running":
        return "starting" if health == "starting" else "active"
    return "down"


def compose_status(root: Path) -> dict[str, str] | None:
    """Every compose service -> active | starting | down. None when it cannot be read."""
    try:
        listed = _run(root, ["ps", "-a", "--format", "json"], TIMEOUT)
        defined = _run(root, ["config", "--services"], TIMEOUT)
    except DeployError:
        return None
    if listed.returncode != 0 or defined.returncode != 0:
        return None
    result = {name.strip(): "down" for name in defined.stdout.splitlines() if name.strip()}
    for row in _rows(listed.stdout):
        result[row.get("Service", "")] = _state(row)
    return result


def status(root: Path, services: list[str]) -> dict[str, str]:
    """Hedwig service -> active | starting | down | unknown (no compose or Docker)."""
    found = compose_status(root)
    if found is None:
        return {s: "unknown" for s in services}
    return {s: found.get(compose_name(root, s), "unknown") for s in services}


def stop(root: Path, service: str) -> None:
    """`docker compose stop`: keeps the container and network, so `start` is instant."""
    done = _run(root, ["stop", compose_name(root, service)], START_TIMEOUT)
    if done.returncode != 0:
        raise DeployError(done.stderr.strip()[-300:] or "docker compose stop failed")


def start(root: Path, service: str) -> None:
    done = _run(root, ["start", compose_name(root, service)], START_TIMEOUT)
    if done.returncode != 0:
        raise DeployError(done.stderr.strip()[-300:] or "docker compose start failed")


BUILD_TIMEOUT = 900
SMOKE_WAIT = 60
SETTLE_SECONDS = 3


def rebuild(root: Path, service: str) -> None:
    """Rebuild one service's image and restart only that service."""
    name = compose_name(root, service)
    built = _run(root, ["build", name], BUILD_TIMEOUT)
    if built.returncode != 0:
        raise DeployError(f"build failed: {(built.stderr or built.stdout).strip()[-400:]}")
    up = _run(root, ["up", "-d", "--no-deps", name], START_TIMEOUT)
    if up.returncode != 0:
        raise DeployError(f"up failed: {up.stderr.strip()[-300:]}")


def published_url(root: Path, service: str) -> str | None:
    """http://127.0.0.1:<port> of the service's published port, if it publishes one."""
    done = _run(root, ["ps", "-a", "--format", "json", compose_name(root, service)], TIMEOUT)
    for row in _rows(done.stdout):
        for pub in row.get("Publishers") or []:
            if pub.get("PublishedPort"):
                return f"http://{pub.get('URL') or '127.0.0.1'}:{pub['PublishedPort']}"
    return None


def smoke(root: Path, service: str, health_path: str = "/health") -> tuple[bool, str]:
    """Is the service really up? Running, answering its health path, still running after a pause.

    The health path is asked on the published 127.0.0.1 port, not through the Guard, whose
    proof-of-work challenge would turn the check away.
    """
    try:
        url = published_url(root, service)
    except DeployError as err:
        return False, str(err)
    deadline = time.monotonic() + SMOKE_WAIT
    while True:
        running = status(root, [service])[service] in ("active", "starting")
        if running and url:
            try:
                if httpx.get(url + health_path, timeout=3).status_code < 500:
                    break
            except httpx.HTTPError:
                pass
        elif running and not url:
            break
        if time.monotonic() > deadline:
            return False, f"{service} did not become healthy within {SMOKE_WAIT} s"
        time.sleep(1)
    time.sleep(SETTLE_SECONDS)
    if status(root, [service])[service] != "active":
        return False, f"{service} stopped again right after starting"
    return True, f"{service} healthy" + (f" at {url}{health_path}" if url else " (running)")
