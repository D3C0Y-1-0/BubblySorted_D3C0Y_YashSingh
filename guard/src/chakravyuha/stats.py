"""Live counters for the dashboard, built from the event stream: requests per second, stops per
ring, where each client was last stopped, distinct passwords tried.
"""

import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

STOPPED = {"blocked", "banned", "trapped", "challenged"}
RATE_WINDOW_S = 5
MAX_CLIENTS = 20_000


@dataclass
class ClientView:
    ip: str
    ring: int | str = "centre"  # the ring that last decided for this client
    action: str = "allowed"
    status: int | None = None
    service: str | None = None
    path: str = ""
    requests: int = 0
    stops: int = 0
    seen_at: float = 0.0


@dataclass
class Stats:
    clock: Any = time.monotonic
    started_at: float = field(default=0.0)
    total: int = 0
    actions: Counter = field(default_factory=Counter)
    ring_stops: Counter = field(default_factory=Counter)
    categories: Counter = field(default_factory=Counter)
    clients: dict[str, ClientView] = field(default_factory=dict)
    passwords: set[str] = field(default_factory=set)
    recent: deque = field(default_factory=deque)  # (time, stopped) of the last few seconds

    def __post_init__(self) -> None:
        self.started_at = self.clock()

    def record(self, event: dict[str, Any]) -> None:
        action = event.get("event.action", "")
        if action == "guard-error":
            self.actions[action] += 1
            return
        now = self.clock()
        ip = event.get("source.ip", "unknown")
        ring = event.get("ring", "centre")
        stopped = action in STOPPED and not event.get("hedwig.monitor")
        if category := event.get("event.category"):
            self.categories[category] += 1
        if fp := event.get("hedwig.password_fp"):
            self.passwords.add(fp)
        self.actions[action] += 1

        view = self.clients.get(ip)
        if view is None:
            if len(self.clients) >= MAX_CLIENTS:
                self._prune()
            view = self.clients[ip] = ClientView(ip)
        # a brute-force trip is recorded after the answer, as a second event for one request
        if not (action == "trapped" and event.get("rule") == "brute-force"):
            self.total += 1
            view.requests += 1
            self.recent.append((now, stopped))
        if stopped:
            view.stops += 1
            self.ring_stops[str(ring)] += 1
        view.ring, view.action = ring, action
        view.status = event.get("http.response.status_code")
        view.service, view.path = event.get("service"), event.get("url.path", "")
        view.seen_at = now

    def rates(self) -> dict[str, float]:
        now = self.clock()
        while self.recent and now - self.recent[0][0] > RATE_WINDOW_S:
            self.recent.popleft()
        window = min(RATE_WINDOW_S, max(now - self.started_at, 1))
        stopped = sum(1 for _, s in self.recent if s)
        return {
            "rps": round(len(self.recent) / window, 1),
            "stopped_rps": round(stopped / window, 1),
        }

    def _prune(self) -> None:
        oldest = sorted(self.clients.values(), key=lambda v: v.seen_at)[: MAX_CLIENTS // 4]
        for view in oldest:
            del self.clients[view.ip]
