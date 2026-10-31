"""The rings. Each takes the request context and either returns a `Stop` (the ring decides)
or None (on to the next ring). Rings only describe side effects such as a ban; the proxy
applies them, so monitor mode can log a decision without acting on it.

Built so far: ring 1 (gate), ring 2 (flood), ring 3 (challenge, in `challenge.py`) and ring 5
(login). Ring 4 is in `routes.py`, ring 7 (the decoy bank) in `decoy.py`; ring 6 lands in a
later phase.
"""

import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs

from starlette.datastructures import Headers

from . import state as signals
from .config import Config, Service
from .events import password_fp
from .state import Client, State

SCRIPT_UA = re.compile(
    r"curl|wget|python|httpx|aiohttp|go-http|java/|okhttp|libwww|perl|ruby|powershell|"
    r"scrapy|nikto|sqlmap|nmap|masscan|zgrab|hydra|headless",
    re.I,
)
USERNAME_FIELDS = ("username", "user", "email", "login")
PASSWORD_FIELDS = ("password", "pass", "passwd", "pwd")


@dataclass
class Stop:
    ring: int
    status: int
    action: str  # blocked | banned | trapped
    rule: str
    category: str | None = None
    ban_minutes: float | None = None
    trap: bool = False
    body: str = ""
    media_type: str = "text/plain"
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Ctx:
    ip: str
    method: str
    path: str  # full request path
    query: str
    headers: Headers
    service_name: str | None
    service: Service | None
    inner_path: str  # path inside the service, prefix stripped
    client: Client
    body: bytes = b""
    tarpit: bool = False
    trapped: bool = False  # set by ring 1: the decoy answers instead of the service
    username: str | None = None
    password_fp: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def is_login(self) -> bool:
        return bool(
            self.service and self.method == "POST" and self.inner_path in self.service.login_paths
        )


# -- ring 1: gate ----------------------------------------------------------------------------
def gate(ctx: Ctx, state: State, config: Config) -> Stop | None:
    if state.banned(ctx.ip):
        return Stop(1, 403, "blocked", "ban-list", body="Forbidden")
    # A trapped client is not stopped here: it passes the same rings as everyone else, so the
    # maze looks earned, and the decoy answers in place of the service at the end.
    ctx.trapped = state.trapped(ctx.ip)
    return None


# -- ring 2: flood ---------------------------------------------------------------------------
def flood(ctx: Ctx, state: State, config: Config) -> Stop | None:
    if ctx.service and ctx.inner_path == ctx.service.health_path:
        return None
    header_bytes = sum(len(k) + len(v) for k, v in ctx.headers.raw)
    if header_bytes > config.flood.max_header_bytes:
        return Stop(2, 431, "blocked", "header-size", category="ddos", body="Headers too large")

    user_agent = ctx.headers.get("user-agent", "")
    if not user_agent or SCRIPT_UA.search(user_agent):
        state.add(ctx.client, signals.SCRIPT_UA)

    rate = ctx.service.rate if ctx.service else 20
    if not state.take_token(ctx.client, rate):
        state.add(ctx.client, signals.RATE_LIMITED)
        if state.note_limited(ctx.client) >= config.flood.ban_after:
            return Stop(
                2, 429, "banned", "rate-limit-repeat", category="ddos",
                ban_minutes=config.flood.ban_minutes, body="Too Many Requests",
            )  # fmt: skip
        return Stop(2, 429, "blocked", "rate-limit", category="ddos", body="Too Many Requests")

    ctx.tarpit = state.suspicion(ctx.client) >= config.suspicion.tarpit
    return None


def tarpit_delay(suspicion: float, config: Config) -> float:
    """Grows from tarpit_min_s at the tarpit threshold to tarpit_max_s at the trap threshold."""
    low, high = config.suspicion.tarpit, config.suspicion.trap
    share = min(max((suspicion - low) / max(high - low, 1e-9), 0), 1)
    flood = config.flood
    return flood.tarpit_min_s + share * (flood.tarpit_max_s - flood.tarpit_min_s)


# -- ring 5: login ---------------------------------------------------------------------------
def login_credentials(ctx: Ctx, secret: bytes) -> None:
    """Pull the username and a password fingerprint from a login body. Never keep the password."""
    if not ctx.is_login or not ctx.body:
        return
    content_type = ctx.headers.get("content-type", "")
    fields: dict = {}
    try:
        if "json" in content_type:
            data = json.loads(ctx.body)
            fields = data if isinstance(data, dict) else {}
        elif "x-www-form-urlencoded" in content_type:
            fields = {k: v[0] for k, v in parse_qs(ctx.body.decode("utf-8", "replace")).items()}
    except ValueError:
        return
    username = next((fields[k] for k in USERNAME_FIELDS if k in fields), None)
    password = next((fields[k] for k in PASSWORD_FIELDS if k in fields), None)
    if username is not None:
        ctx.username = str(username)[:128]
    if password is not None:
        ctx.password_fp = password_fp(secret, str(password))


LEVEL_TIGHTEN = {"calm": 0, "alert": 2, "siege": 4}


def max_failures(state: State, config: Config) -> int:
    """Failures that trip ring 5: 8 when calm, 6 at alert, 4 at siege."""
    return max(config.login.max_failures - LEVEL_TIGHTEN.get(state.level, 0), 2)


@dataclass
class LoginResult:
    failed: bool
    failures: int = 0
    delay: float = 0.0
    trip: Stop | None = None


def login_result(ctx: Ctx, status: int, state: State, config: Config) -> LoginResult | None:
    """After the upstream answers a login: count failures, back off, trip at the threshold."""
    if not ctx.is_login:
        return None
    if 200 <= status < 300:
        ctx.client.login_failures.clear()
        return LoginResult(failed=False)
    if status not in (401, 403):
        return None
    failures = state.note_login_failure(ctx.client)
    state.add(ctx.client, signals.LOGIN_FAILED)
    delay = min(config.login.backoff_step_s * failures, config.login.backoff_max_s)
    trip = None
    if failures >= max_failures(state, config):
        state.add(ctx.client, signals.ATTACK)
        trip = Stop(5, status, "trapped", "brute-force", category="bruteforce", trap=True)
    return LoginResult(failed=True, failures=failures, delay=delay, trip=trip)
