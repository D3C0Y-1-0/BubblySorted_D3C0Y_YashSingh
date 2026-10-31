"""Shared, in-memory state of the formation: per-client suspicion and counters, bans, traps
and the alert level. Rings read and write it on the request path; agents work on it later.
"""

import time
from collections import deque
from dataclasses import dataclass, field

from .config import Config


@dataclass(frozen=True)
class Signal:
    name: str
    points: float
    cooldown_s: float = 0  # the same signal adds points at most once per cooldown


SCRIPT_UA = Signal("script-ua", 1, cooldown_s=3600)
DEEP_PATH_NO_SESSION = Signal("deep-path-no-session", 1, cooldown_s=3600)
LOGIN_FAILED = Signal("login-failed", 1)
UNKNOWN_ROUTE = Signal("unknown-route", 2)
PROBE_ROUTE = Signal("probe-route", 3)
RATE_LIMITED = Signal("rate-limited", 2, cooldown_s=10)
CHALLENGE_FAILED = Signal("challenge-failed", 2, cooldown_s=10)
CAMPAIGN_MEMBER = Signal("campaign-member", 5, cooldown_s=600)
ATTACK = Signal("attack", 10)  # a payload or a brute-force trip


@dataclass
class Client:
    ip: str
    score: float = 0.0
    scored_at: float = 0.0
    signals: dict[str, float] = field(default_factory=dict)  # signal -> last time it scored
    reasons: dict[str, float] = field(default_factory=dict)  # signal -> points it added
    tokens: float = -1.0  # -1 means a full bucket on first use
    refilled_at: float = 0.0
    limited: deque = field(default_factory=deque)  # times of rate-limited requests
    login_failures: deque = field(default_factory=deque)
    challenges_pending: int = 0  # challenges issued since the last valid session
    challenged_at: float = 0.0
    seen_at: float = 0.0


class State:
    def __init__(self, config: Config, clock=time.monotonic) -> None:
        self.config = config
        self.clock = clock
        self.clients: dict[str, Client] = {}
        self.bans: dict[str, float] = {}  # ip -> expiry (clock time)
        self.traps: dict[str, float] = {}
        self.level = "calm"
        self.in_flight = 0
        self.tarpitted = 0

    def now(self) -> float:
        return self.clock()

    def client(self, ip: str) -> Client:
        client = self.clients.get(ip)
        if client is None:
            if len(self.clients) > 50_000:
                self._prune()
            client = self.clients[ip] = Client(ip)
        client.seen_at = self.now()
        return client

    # -- suspicion -----------------------------------------------------------------------
    def suspicion(self, client: Client) -> float:
        if client.score <= 0:
            return 0.0
        elapsed = self.now() - client.scored_at
        return client.score * 0.5 ** (elapsed / self.config.suspicion.half_life_s)

    def add(self, client: Client, signal: Signal) -> float:
        now = self.now()
        last = client.signals.get(signal.name)
        if signal.cooldown_s and last is not None and now - last < signal.cooldown_s:
            return self.suspicion(client)
        client.score = self.suspicion(client) + signal.points
        client.scored_at = now
        client.signals[signal.name] = now
        client.reasons[signal.name] = client.reasons.get(signal.name, 0) + signal.points
        return client.score

    # -- bans and traps ------------------------------------------------------------------
    def allowlisted(self, ip: str) -> bool:
        return ip in self.config.allowlist

    def ban(self, ip: str, minutes: float) -> bool:
        if self.allowlisted(ip):
            return False
        self.bans[ip] = self.now() + min(minutes, 60) * 60
        return True

    def trap(self, ip: str, minutes: float | None = None) -> bool:
        if self.allowlisted(ip):
            return False
        minutes = self.config.trap_minutes if minutes is None else minutes
        self.traps[ip] = self.now() + min(minutes, 60) * 60
        return True

    def release(self, ip: str) -> bool:
        return self.traps.pop(ip, None) is not None

    def lift_ban(self, ip: str) -> bool:
        return self.bans.pop(ip, None) is not None

    def banned(self, ip: str) -> bool:
        return self._active(self.bans, ip)

    def trapped(self, ip: str) -> bool:
        return self._active(self.traps, ip)

    def _active(self, table: dict[str, float], ip: str) -> bool:
        expiry = table.get(ip)
        if expiry is None:
            return False
        if expiry <= self.now():
            del table[ip]
            return False
        return True

    # -- rate limit ----------------------------------------------------------------------
    def take_token(self, client: Client, rate: float) -> bool:
        """Token bucket per client: `rate` per second, holding `rate x burst_factor`."""
        if self.level != "calm":
            rate /= 2
        capacity = rate * self.config.flood.burst_factor
        now = self.now()
        if client.tokens < 0:
            client.tokens = capacity
        else:
            client.tokens = min(capacity, client.tokens + (now - client.refilled_at) * rate)
        client.refilled_at = now
        if client.tokens >= 1:
            client.tokens -= 1
            return True
        return False

    def note_limited(self, client: Client) -> int:
        """Record a rate-limited request; returns how many fell in the ban window."""
        now = self.now()
        window = self.config.flood.ban_window_s
        client.limited.append(now)
        while client.limited and now - client.limited[0] > window:
            client.limited.popleft()
        return len(client.limited)

    # -- login ---------------------------------------------------------------------------
    def login_failures(self, client: Client) -> int:
        now = self.now()
        while client.login_failures and now - client.login_failures[0] > self.config.login.window_s:
            client.login_failures.popleft()
        return len(client.login_failures)

    def note_login_failure(self, client: Client) -> int:
        client.login_failures.append(self.now())
        return self.login_failures(client)

    def _prune(self) -> None:
        cutoff = self.now() - 3600
        for ip in [ip for ip, c in self.clients.items() if c.seen_at < cutoff]:
            del self.clients[ip]
