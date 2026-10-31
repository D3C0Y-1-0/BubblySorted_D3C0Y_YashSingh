"""Ring 3: the proof-of-work challenge and the signed sessions it earns.

A client without a valid session gets a challenge token. To pass it must find a nonce so that
`sha256(token + ":" + nonce)` starts with `bits` zero bits, and post both to
`/__hedwig/challenge`. A browser does this invisibly with the script in the challenge page; a
script has to do the same work for every new session. A solution earns an HMAC-signed session
cookie bound to the client IP, so a cookie copied to another IP is worthless.

Tokens and sessions are stateless (signed, not stored). Only solved tokens are remembered, for
their short lifetime, so one solution cannot mint many sessions.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs

from . import state as signals
from .config import Config
from .rings import Ctx, Stop
from .state import State

COOKIE = "hw_session"
LEVEL_BITS = {"calm": 0, "alert": 2, "siege": 4}
MAX_BITS = 32  # the solver checks the first 32-bit word of the hash
PENDING_RESET_S = 300  # challenges issued without a solution are forgotten after this
SKIP_GRACE = 2  # unsolved challenges allowed before coming back without a session scores
PAGE = Path(__file__).parent / "static" / "challenge.html"


def leading_zero_bits_ok(token: str, nonce: str, bits: int) -> bool:
    digest = hashlib.sha256(f"{token}:{nonce}".encode()).digest()
    return int.from_bytes(digest[:4], "big") >> (32 - bits) == 0


def solve(token: str, bits: int) -> str:
    """The reference solver (tests and demo attack scripts)."""
    nonce = 0
    while not leading_zero_bits_ok(token, str(nonce), bits):
        nonce += 1
    return str(nonce)


@dataclass
class Verdict:
    ok: bool
    reason: str  # ok | missing | expired | invalid | reused | wrong | malformed


class Challenger:
    def __init__(self, secret: bytes, clock=time.time) -> None:
        self.key = hmac.new(secret, b"chakravyuha-ring-3", hashlib.sha256).digest()
        self.clock = clock  # wall time, so sessions survive a Guard restart
        self.used: dict[str, float] = {}  # solved token salt -> when it expires
        self._page = PAGE.read_text(encoding="utf-8")

    def _mac(self, *parts) -> str:
        message = "|".join(str(part) for part in parts).encode()
        return hmac.new(self.key, message, hashlib.sha256).hexdigest()[:32]

    # -- difficulty ------------------------------------------------------------------------
    def difficulty(self, suspicion: float, level: str, config: Config, allowlisted: bool) -> int:
        bits = config.challenge.difficulty
        if suspicion >= config.suspicion.hard_challenge:
            bits += config.challenge.hard_bits
        if not allowlisted:  # the formation tightens for everyone except allowlisted clients
            bits += LEVEL_BITS.get(level, 0)
        return min(max(bits, 1), MAX_BITS)

    def session_seconds(self, suspicion: float, config: Config) -> int:
        minutes = config.challenge.session_minutes
        if suspicion >= config.suspicion.hard_challenge:
            minutes = max(minutes / 3, 1)
        return int(minutes * 60)

    # -- tokens ----------------------------------------------------------------------------
    def issue(self, ip: str, bits: int) -> str:
        issued, salt = int(self.clock()), secrets.token_hex(8)
        return f"{issued}.{bits}.{salt}.{self._mac('chal', ip, issued, bits, salt)}"

    def check_solution(self, ip: str, token: str, nonce: str, ttl: int) -> Verdict:
        try:
            issued_s, bits_s, salt, mac = token.split(".")
            issued, bits = int(issued_s), int(bits_s)
        except ValueError:
            return Verdict(False, "malformed")
        if not 1 <= bits <= MAX_BITS or len(nonce) > 64:
            return Verdict(False, "malformed")
        if not hmac.compare_digest(mac, self._mac("chal", ip, issued, bits, salt)):
            return Verdict(False, "invalid")  # forged, or issued to another IP
        now = self.clock()
        if not issued <= now + 5 or now - issued > ttl:
            return Verdict(False, "expired")
        self._prune(now)
        if salt in self.used:
            return Verdict(False, "reused")
        if not leading_zero_bits_ok(token, nonce, bits):
            return Verdict(False, "wrong")
        self.used[salt] = issued + ttl
        return Verdict(True, "ok")

    def _prune(self, now: float) -> None:
        if len(self.used) > 1000:
            self.used = {salt: exp for salt, exp in self.used.items() if exp > now}

    # -- sessions --------------------------------------------------------------------------
    def make_session(self, ip: str, seconds: int) -> str:
        expiry, nonce = int(self.clock()) + seconds, secrets.token_hex(8)
        return f"{expiry}.{nonce}.{self._mac('sess', ip, expiry, nonce)}"

    def check_session(self, ip: str, value: str | None) -> Verdict:
        if not value:
            return Verdict(False, "missing")
        try:
            expiry_s, nonce, mac = value.split(".")
            expiry = int(expiry_s)
        except ValueError:
            return Verdict(False, "invalid")
        if not hmac.compare_digest(mac, self._mac("sess", ip, expiry, nonce)):
            return Verdict(False, "invalid")  # forged, or bound to another IP
        if expiry <= self.clock():
            return Verdict(False, "expired")
        return Verdict(True, "ok")

    # -- the ring --------------------------------------------------------------------------
    def ring(self, ctx: Ctx, state: State, config: Config) -> Stop | None:
        service = ctx.service
        if service and ctx.inner_path == service.health_path:
            return None
        if service and not service.challenge:
            return self._api_key(ctx, state, service.api_key_env)

        verdict = self.check_session(ctx.ip, session_cookie(ctx.headers.get("cookie", "")))
        client = state.client(ctx.ip)
        if verdict.ok:
            ctx.extra["session"] = True
            client.challenges_pending = 0
            return None

        now = state.now()
        if now - client.challenged_at > PENDING_RESET_S:
            client.challenges_pending = 0
        if verdict.reason == "invalid" or client.challenges_pending >= SKIP_GRACE:
            state.add(client, signals.CHALLENGE_FAILED)  # a bad cookie, or the puzzle skipped
        if ctx.inner_path.strip("/").count("/") >= 1:
            state.add(client, signals.DEEP_PATH_NO_SESSION)
        client.challenges_pending += 1
        client.challenged_at = now

        suspicion = state.suspicion(client)
        bits = self.difficulty(suspicion, state.level, config, state.allowlisted(ctx.ip))
        token = self.issue(ctx.ip, bits)
        headers = {
            "X-Hedwig-Challenge": token,
            "X-Hedwig-Difficulty": str(bits),
            "Cache-Control": "no-store",
        }
        rule = "challenge-required" if verdict.reason == "missing" else f"session-{verdict.reason}"
        if "text/html" in ctx.headers.get("accept", ""):
            body = self._page.replace("__TOKEN__", token).replace("__BITS__", str(bits))
            media_type = "text/html"
        else:
            body = json.dumps({"error": "challenge required", "challenge": token, "bits": bits})
            media_type = "application/json"
        return Stop(
            3, 403, "challenged", rule, category="challenge", body=body,
            media_type=media_type, headers=headers,
        )  # fmt: skip

    def _api_key(self, ctx: Ctx, state: State, env_name: str | None) -> Stop | None:
        """Machine APIs skip the puzzle and must send their key instead."""
        expected = os.environ.get(env_name) if env_name else None
        if not expected:
            return None  # no key configured: the service is open (the CLI warns about it)
        supplied = ctx.headers.get("x-api-key") or ctx.headers.get("authorization", "")
        supplied = supplied.removeprefix("Bearer ").strip()
        if supplied and hmac.compare_digest(supplied.encode(), expected.encode()):
            return None
        state.add(state.client(ctx.ip), signals.CHALLENGE_FAILED)
        return Stop(3, 401, "blocked", "api-key", category="challenge", body="Unauthorized")


def session_cookie(header: str) -> str | None:
    for part in header.split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE:
            return value
    return None


def strip_session_cookie(header: str) -> str:
    """The Guard's cookie is none of the upstream's business."""
    parts = [p.strip() for p in header.split(";") if p.strip()]
    return "; ".join(p for p in parts if p.partition("=")[0] != COOKIE)


def parse_solution(body: bytes, content_type: str) -> tuple[str, str]:
    if "x-www-form-urlencoded" in content_type:
        fields = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}
    else:
        data = json.loads(body or b"{}")
        fields = data if isinstance(data, dict) else {}
    return str(fields.get("token", ""))[:256], str(fields.get("nonce", ""))[:65]
