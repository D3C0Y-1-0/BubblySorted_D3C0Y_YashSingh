"""One JSON event per decision, fanned out to stdout, a ring buffer, daily JSONL files and
live subscribers (the dashboard). Later phases add Logstash, the agents and the PM notifier.

Field names follow ECS where one exists (`source.ip`, `url.path`, ...). Passwords are never
stored: login events carry only `hedwig.password_fp`, a short keyed hash.
"""

import asyncio
import contextlib
import hashlib
import hmac
import json
import sys
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CATEGORIES = {
    "ddos", "challenge", "probe", "bruteforce", "payload", "phishing", "malware", "trap",
    "honeytoken",
}  # fmt: skip
ACTIONS = {
    "allowed", "challenged", "challenge_solved", "tarpitted", "login_failed", "blocked",
    "banned", "trapped", "released", "guard-error",
}  # fmt: skip
BUFFER_SIZE = 1000


def make_event(
    action: str,
    *,
    ip: str,
    ring: int | str,
    method: str = "",
    path: str = "",
    status: int | None = None,
    service: str | None = None,
    suspicion: float | None = None,
    category: str | None = None,
    rule: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    if action not in ACTIONS:
        raise ValueError(f"unknown event action {action!r}")
    if category is not None and category not in CATEGORIES:
        raise ValueError(f"unknown event category {category!r}")
    event: dict[str, Any] = {
        "@timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "source.ip": ip,
        "url.path": path,
        "http.request.method": method,
        "http.response.status_code": status,
        "service": service,
        "ring": ring,
        "hedwig.suspicion": round(suspicion, 2) if suspicion is not None else None,
        "event.category": category,
        "event.action": action,
        "rule": rule,
    }
    event.update(extra)
    return {key: value for key, value in event.items() if value is not None}


def password_fp(secret: bytes, password: str) -> str:
    """A short keyed hash, enough to count distinct passwords, useless for recovering one."""
    return hmac.new(secret, password.encode("utf-8"), hashlib.sha256).hexdigest()[:12]


class EventBus:
    def __init__(self, data_dir: Path | None, stdout: bool = True) -> None:
        self.buffer: deque[dict[str, Any]] = deque(maxlen=BUFFER_SIZE)
        self.events_dir = data_dir / "events" if data_dir else None
        self.stdout = stdout
        self._subscribers: set[asyncio.Queue] = set()
        self.listeners: list[Callable[[dict[str, Any]], None]] = []  # called inline, keep cheap
        self._file = None
        self._file_day = ""

    def emit(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), default=str)
        self.buffer.append(event)
        if self.stdout:
            print(line, file=sys.stdout, flush=True)
        self._write_file(line)
        for listener in self.listeners:
            try:
                listener(event)
            except Exception as error:  # a broken listener must never stop the proxy
                print(f"chakravyuha: event listener failed: {error}", file=sys.stderr)
        for queue in list(self._subscribers):
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(event)

    def recent(self, limit: int = BUFFER_SIZE) -> list[dict[str, Any]]:
        return list(self.buffer)[-limit:]

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def _write_file(self, line: str) -> None:
        if not self.events_dir:
            return
        try:
            day = datetime.now(UTC).strftime("%Y-%m-%d")
            if day != self._file_day:
                self.close()
                self.events_dir.mkdir(parents=True, exist_ok=True)
                self._file = (self.events_dir / f"{day}.jsonl").open("a", encoding="utf-8")
                self._file_day = day
            self._file.write(line + "\n")
            self._file.flush()
        except OSError as error:  # a full disk must never stop the proxy
            print(f"chakravyuha: cannot write event file: {error}", file=sys.stderr)
