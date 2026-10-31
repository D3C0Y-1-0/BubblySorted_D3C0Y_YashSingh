"""The Guard: a reverse proxy that runs every request through the rings, then forwards it to
the bank service its path prefix routes to. Responses are streamed back.
"""

import asyncio
import contextlib
import hmac
import os
import secrets
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote

import httpx
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Route

from . import challenge, inspection, rings
from . import state as signals
from .agents import Agents
from .challenge import Challenger
from .config import Config, Service
from .decoy import Decoy
from .elastic import EventSource
from .events import EventBus, make_event
from .hedwig_link import HedwigLink
from .honeytokens import Honeytokens, Token
from .notifier import PMNotifier
from .routes import RouteRing
from .shipper import Shipper
from .state import State
from .stats import Stats

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "trailers", "transfer-encoding", "upgrade",
}  # fmt: skip
REQUEST_DROP = HOP_BY_HOP | {"host", "content-length"}
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
}
INTERNAL = "/__hedwig"
CHALLENGE_PATH = f"{INTERNAL}/challenge"


class BodyTooLarge(Exception):
    pass


def load_secret(data_dir: Path | None) -> bytes:
    """CHAKRA_SECRET, else a key kept in the data dir so fingerprints survive restarts."""
    if env := os.environ.get("CHAKRA_SECRET"):
        return env.encode()
    if data_dir is None:
        return secrets.token_bytes(32)
    path = data_dir / "secret.key"
    try:
        if path.is_file():
            return bytes.fromhex(path.read_text().strip())
        key = secrets.token_bytes(32)
        data_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(key.hex())
        return key
    except (OSError, ValueError):
        return secrets.token_bytes(32)


class Guard:
    def __init__(
        self,
        config: Config,
        *,
        token: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        bus: EventBus | None = None,
        state: State | None = None,
        sleep: Callable = asyncio.sleep,
        wallclock: Callable[[], float] = time.time,
        decoy: Decoy | None = None,
        shipper: Shipper | None = None,
        llm=None,
        notifier: PMNotifier | None = None,
    ) -> None:
        self.config = config
        self.token = token
        self.state = state or State(config)
        self.bus = bus or EventBus(config.data_dir, stdout=config.stdout_events)
        self.secret = load_secret(config.data_dir)
        self.challenger = Challenger(self.secret, clock=wallclock)
        self.route_ring = RouteRing(config)
        self.hedwig = HedwigLink(config.bank_root)
        self.blocked_hashes = {h.lower() for h in config.blocked_hashes}
        self.own_hosts = {"127.0.0.1", "localhost", ""}
        for svc in config.services.values():
            host = httpx.URL(svc.upstream).host
            if host:
                self.own_hosts.add(host.lower())
        self.decoy = decoy or Decoy(config)
        # Shared with the dashboard and, from C7 and C10 on, the honeytokens and the agents.
        self.feed: deque[dict] = deque(maxlen=100)  # one line per agent or operator decision
        self.alarms: deque[dict] = deque(maxlen=20)  # honeytoken alarms
        self.campaigns: list[dict] = []
        self.agents_status = "rules"  # rules | ai | offline
        self.shipper = shipper
        if self.shipper is None and config.elk.enabled:
            self.shipper = Shipper(config.elk.logstash).start()
        if self.shipper:
            self.bus.listeners.append(self.shipper.put)
        self.source = EventSource(self.bus, config.elk)
        self.ip_campaign: dict[str, str] = {}  # ip -> the Scout's campaign id
        self.agents = Agents(self, llm=llm)
        tokens_file = config.data_dir / "honeytokens.jsonl" if config.data_dir else None
        self.honeytokens = Honeytokens(self.secret, tokens_file)
        self.decoy.fill = self.honeytokens.fill
        self.links: dict[str, set[str]] = {}  # trapped IP -> IPs that used its honeytokens
        self.alarm_listeners: list[Callable[[dict], None]] = []
        self.notifier = notifier or PMNotifier(
            digest_delay_s=config.digest_delay_s,
            cooldown_s=config.digest_cooldown_s,
            summary=self.agents.summary,
            kibana_url=config.elk.kibana_url,
        )
        self.bus.listeners.append(self.notifier.on_event)
        self.alarm_listeners.append(self.notifier.on_alarm)
        self.stats = Stats()
        self.bus.listeners.append(self.stats.record)
        self.sleep = sleep
        self.upstream = httpx.AsyncClient(
            transport=transport, timeout=httpx.Timeout(30.0, connect=5.0), follow_redirects=False
        )
        # longest prefix first, so /transaction/x never falls to "/"
        self.routes = sorted(
            config.services.items(), key=lambda item: len(item[1].prefix or ""), reverse=True
        )

    # -- helpers ---------------------------------------------------------------------------
    def client_ip(self, request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def route(self, path: str) -> tuple[str | None, Service | None, str]:
        for name, service in self.routes:
            prefix = service.prefix or "/"
            if prefix == "/":
                return name, service, path
            if path == prefix or path.startswith(prefix + "/"):
                return name, service, path[len(prefix) :] or "/"
        return None, None, path

    def emit(self, action: str, ctx: rings.Ctx, status: int | None, ring, **fields) -> None:
        if ctx.username is not None:
            fields.setdefault("user.name", ctx.username)
        if ctx.password_fp is not None:
            fields.setdefault("hedwig.password_fp", ctx.password_fp)
        if campaign := self.ip_campaign.get(ctx.ip):
            fields.setdefault("campaign", campaign)
        if user_agent := ctx.headers.get("user-agent"):
            fields.setdefault("user_agent.original", user_agent[:200])
        script = not user_agent or bool(rings.SCRIPT_UA.search(user_agent))
        fields.setdefault("hedwig.client", "script" if script else "browser")
        self.bus.emit(
            make_event(
                action,
                ip=ctx.ip,
                ring=ring,
                method=ctx.method,
                path=ctx.path,
                status=status,
                service=ctx.service_name,
                suspicion=self.state.suspicion(ctx.client),
                **fields,
            )
        )

    def guard_error(self, ctx: rings.Ctx, ring, error: Exception) -> None:
        try:
            self.emit("guard-error", ctx, None, ring, rule=f"{type(error).__name__}: {error}"[:200])
        except Exception:  # the error event itself must not break the request
            pass

    def monitoring(self, ctx: rings.Ctx) -> bool:
        return self.config.service_mode(ctx.service) == "monitor"

    def stop_response(self, ctx: rings.Ctx, stop: rings.Stop) -> Response | None:
        """Apply a ring's decision. In monitor mode, record it and let the request through."""
        if self.monitoring(ctx):
            self.emit(
                stop.action, ctx, stop.status, stop.ring, category=stop.category,
                rule=stop.rule, **{"hedwig.monitor": True},
            )  # fmt: skip
            return None
        action = stop.action
        if stop.ban_minutes and not self.state.ban(ctx.ip, stop.ban_minutes):
            action = "blocked"  # allowlisted: never banned
        if stop.trap and not self.state.trap(ctx.ip):
            action = "blocked"
        extra = {"hedwig.ban_minutes": stop.ban_minutes} if action == "banned" else {}
        self.emit(
            action, ctx, stop.status, stop.ring, category=stop.category, rule=stop.rule, **extra
        )
        if stop.ring != 1 and not stop.trap:
            self.trap_if_suspicious(ctx)
        response = Response(
            stop.body or "Forbidden", stop.status, headers=stop.headers, media_type=stop.media_type
        )
        return self.with_security(response)

    def trap_if_suspicious(self, ctx: rings.Ctx) -> bool:
        """Suspicion at the trap threshold draws the client into the maze (never in monitor mode
        and never an allowlisted client)."""
        state = self.state
        if (
            self.monitoring(ctx)
            or state.trapped(ctx.ip)
            or state.suspicion(ctx.client) < self.trap_threshold(ctx)
            or not state.trap(ctx.ip)
        ):
            return False
        self.emit("trapped", ctx, None, 7, category="trap", rule="suspicion")
        return True

    def trap_threshold(self, ctx: rings.Ctx) -> float:
        return self.trap_threshold_for(ctx.ip)

    def trap_threshold_for(self, ip: str) -> float:
        """10 when calm; the Commander lowers it to 8 at alert and 6 at siege."""
        return max(self.config.suspicion.trap - rings.LEVEL_TIGHTEN.get(self.state.level, 0), 3)

    def throttle(self, username: str, minutes: float) -> bool:
        """Per-username login throttle ordered by the Scout. True if newly throttled."""
        new = not self.throttled(username)
        self.state.throttled[username] = self.state.now() + min(minutes, 60) * 60
        return new

    def throttled(self, username: str) -> bool:
        expiry = self.state.throttled.get(username)
        return expiry is not None and expiry > self.state.now()

    def alarm_age_s(self) -> float:
        if not self.alarms:
            return float("inf")
        stamp = datetime.fromisoformat(self.alarms[-1]["@timestamp"])
        return (datetime.now(UTC) - stamp).total_seconds()

    def username_throttle(self, ctx: rings.Ctx, state: State, config: Config):
        """Ring 5, on the Scout's order: one login attempt per interval for a throttled name."""
        user = ctx.username
        if not ctx.is_login or not user or not self.throttled(user) or state.allowlisted(ctx.ip):
            return None
        now, last = state.now(), state.user_last_login.get(user)
        if last is not None and now - last < config.agents.throttle_interval_s:
            return rings.Stop(5, 429, "blocked", "username-throttle", category="bruteforce",
                              body="Too Many Requests")  # fmt: skip
        state.user_last_login[user] = now
        return None

    def run_ring(self, number: int, ring: Callable, ctx: rings.Ctx) -> Response | None:
        try:
            stop = ring(ctx, self.state, self.config)
            if stop and number == 3 and stop.action == "challenged":
                self.route_ring.score(ctx, self.state)  # probing scores even without a session
        except Exception as error:  # fail open
            self.guard_error(ctx, number, error)
            return None
        return self.stop_response(ctx, stop) if stop else None

    @staticmethod
    def with_security(response: Response) -> Response:
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response

    async def read_body(self, request: Request) -> bytes:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.config.max_body_bytes:
            raise BodyTooLarge
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > self.config.max_body_bytes:
                raise BodyTooLarge
            chunks.append(chunk)
        return b"".join(chunks)

    # -- endpoints -------------------------------------------------------------------------
    async def health(self, request: Request) -> Response:
        return self.with_security(JSONResponse({"status": "ok"}))

    async def events(self, request: Request) -> Response:
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not self.token or not hmac.compare_digest(supplied.encode(), self.token.encode()):
            return self.with_security(JSONResponse({"error": "unauthorized"}, 401))
        limit = request.query_params.get("limit", "")
        events = self.bus.recent(int(limit) if limit.isdigit() else 1000)
        return self.with_security(JSONResponse(events))

    async def handle(self, request: Request) -> Response:
        state, config = self.state, self.config
        ip = self.client_ip(request)
        if request.url.path.startswith(INTERNAL + "/"):
            name, service, inner = None, None, request.url.path  # the Guard's own endpoints
        else:
            name, service, inner = self.route(request.url.path)
        ctx = rings.Ctx(
            ip=ip,
            method=request.method,
            path=request.url.path,
            query=request.url.query,
            headers=request.headers,
            service_name=name,
            service=service,
            inner_path=inner,
            client=state.client(ip),
        )
        if state.in_flight >= config.flood.max_in_flight:
            stop = rings.Stop(2, 429, "blocked", "in-flight-cap", "ddos", body="Too Many Requests")
            return self.with_security(PlainTextResponse(stop.body, stop.status))
        state.in_flight += 1
        try:
            return await self._handle(request, ctx)
        finally:
            state.in_flight -= 1

    async def _handle(self, request: Request, ctx: rings.Ctx) -> Response:
        config = self.config
        headers = [v for k, v in ctx.headers.items() if k != "host"]
        basic = Honeytokens.decoded_basic(ctx.headers.get("authorization", ""))
        if response := self.check_honeytokens(ctx, 1, ctx.path, ctx.query, basic, *headers):
            return response
        for number, ring in ((1, rings.gate), (2, rings.flood)):
            if response := self.run_ring(number, ring, ctx):
                return response
        if ctx.path == CHALLENGE_PATH and ctx.method == "POST":
            return await self.solve_challenge(request, ctx)
        if response := self.run_ring(3, self.challenger.ring, ctx):
            return response

        try:
            ctx.body = await asyncio.wait_for(self.read_body(request), config.flood.body_timeout_s)
        except BodyTooLarge:
            stop = rings.Stop(2, 413, "blocked", "body-size", category="ddos", body="Too Large")
            if response := self.stop_response(ctx, stop):
                return response
        except TimeoutError:
            stop = rings.Stop(2, 408, "blocked", "slow-request", category="ddos", body="Timeout")
            if response := self.stop_response(ctx, stop):
                return response
        except ClientDisconnect:
            return Response(status_code=499)

        if response := self.check_honeytokens(ctx, 6, ctx.body):
            return response
        if response := self.run_ring(4, self.route_ring.ring, ctx):
            return response
        if ctx.service is None:  # ring 4 failed open or is monitoring: there is nowhere to go
            return self.with_security(PlainTextResponse("Not Found", 404))

        try:
            rings.login_credentials(ctx, self.secret)
        except Exception as error:
            self.guard_error(ctx, 5, error)
        if response := self.run_ring(5, self.username_throttle, ctx):
            return response
        if response := await self.inspect_request(ctx):
            return response

        self.trap_if_suspicious(ctx)
        if ctx.trapped or self.state.trapped(ctx.ip):
            return await self.maze(ctx)
        return await self.forward(ctx)

    async def maze(self, ctx: rings.Ctx) -> Response:
        """Ring 7: the decoy answers. The real service never sees this request."""
        try:
            answer = self.decoy.respond(ctx, self.state)
        except Exception as error:  # never fail open to the real bank from inside the maze
            self.guard_error(ctx, 7, error)
            return self.with_security(PlainTextResponse("Service Unavailable", 503))
        delay = answer.delay
        if ctx.tarpit:
            delay = max(delay, rings.tarpit_delay(self.state.suspicion(ctx.client), self.config))
        if delay:
            await self.sleep(delay)
        self.emit(
            "trapped", ctx, answer.status, 7, category="trap", rule=answer.rule,
            **{"hedwig.decoy": True},
        )  # fmt: skip
        return self.with_security(answer.response)

    # -- honeytokens ------------------------------------------------------------------------
    def check_honeytokens(self, ctx: rings.Ctx, ring: int, *parts) -> Response | None:
        try:
            tokens = self.honeytokens.scan(*parts)
        except Exception as error:  # fail open
            self.guard_error(ctx, ring, error)
            return None
        # a decoy session cookie coming back from its own client is just that client's cookie
        hits = [t for t in tokens if not (t.kind == "session" and t.ip == ctx.ip)]
        return self.honeytoken_alarm(ctx, ring, hits[0]) if hits else None

    def honeytoken_alarm(self, ctx: rings.Ctx, ring: int, token: Token) -> Response | None:
        """Certain compromise: ban every IP linked to the trapped client that got the token."""
        links = self.links.setdefault(token.ip, set())
        links.add(ctx.ip)
        linked = sorted({token.ip, *links})
        fields = {
            "hedwig.honeytoken.kind": token.kind,
            "hedwig.honeytoken.issued_to": token.ip,
            "hedwig.linked_ips": linked,
            "hedwig.ban_minutes": 60,
        }
        if self.monitoring(ctx):
            self.emit(
                "banned",
                ctx,
                None,
                ring,
                category="honeytoken",
                rule=f"honeytoken-{token.kind}",
                **fields,
                **{"hedwig.monitor": True},
            )
            return None
        banned = [ip for ip in linked if self.state.ban(ip, 60)]
        for ip in banned:
            self.state.release(ip)
        self.emit(
            "banned",
            ctx,
            403,
            ring,
            category="honeytoken",
            rule=f"honeytoken-{token.kind}",
            **fields,
        )
        alarm = {
            "@timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "kind": token.kind,
            "ip": ctx.ip,
            "issued_to": token.ip,
            "issued_at": token.issued,
            "path": ctx.path[:200],
            "banned": banned,
        }
        recent = self.alarms[-1] if self.alarms else None
        if not (
            recent
            and (recent["kind"], recent["ip"]) == (token.kind, ctx.ip)
            and recent["@timestamp"][:16] == alarm["@timestamp"][:16]
        ):
            self.alarms.append(alarm)
            self.note(
                "Guard",
                f"honeytoken {token.kind} used from {ctx.ip}; "
                f"it was handed to {token.ip}. Banned: {', '.join(banned) or 'none'}",
            )
            for listener in self.alarm_listeners:
                try:
                    listener(alarm)
                except Exception as error:  # an email failure must never affect proxying
                    self.guard_error(ctx, ring, error)
        return self.with_security(PlainTextResponse("Forbidden", 403))

    def rotate_tokens(self, agent: str = "Operator") -> int:
        epoch = self.honeytokens.rotate()
        self.note(agent, f"honeytokens rotated (set {epoch})")
        return epoch

    @property
    def elk_status(self) -> str:
        """off | online | offline: Elasticsearch reachable and Logstash acknowledging events."""
        if self.shipper and not self.shipper.healthy:
            return "offline"
        return self.source.status

    def note(self, agent: str, text: str) -> None:
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        self.feed.append({"@timestamp": stamp, "agent": agent, "text": text[:300]})

    def lift_ban(self, ip: str) -> bool:
        lifted = self.state.lift_ban(ip)
        if lifted:
            self.bus.emit(make_event("released", ip=ip, ring=1, rule="ban-lifted"))
        return lifted

    def set_level(self, level: str, agent: str = "Operator", why: str = "") -> bool:
        if level not in ("calm", "alert", "siege") or level == self.state.level:
            return False
        old, self.state.level = self.state.level, level
        self.note(agent, f"level {old} → {level}" + (f": {why}" if why else ""))
        return True

    def set_mode(self, service: str, mode: str) -> bool:
        svc = self.config.services.get(service)
        if svc is None or mode not in ("block", "monitor"):
            return False
        svc.mode = mode
        self.note("Operator", f"{service} → {mode} mode")
        return True

    def release(self, ip: str) -> bool:
        released = self.state.release(ip)
        self.decoy.forget(ip)
        if released:
            self.bus.emit(make_event("released", ip=ip, ring=7, category="trap", rule="operator"))
        return released

    # -- ring 6: inspection ----------------------------------------------------------------
    async def inspect_request(self, ctx: rings.Ctx) -> Response | None:
        service = ctx.service
        if service is None:
            return None
        try:
            body_text = ctx.body[: self.config.max_body_bytes].decode("utf-8", "replace")
            decoded = unquote(ctx.path + "?" + ctx.query)  # payloads are often percent-encoded
            finding = inspection.scan_payload(ctx.path, ctx.query, decoded, body_text)
            if finding is None:
                finding = inspection.open_redirect(
                    ctx.query, self.own_hosts, service.redirect_hosts
                )
            if finding is None and service.uploads is not True:
                finding = inspection.scan_upload(ctx.body, service.uploads, self.blocked_hashes)
        except Exception as error:  # fail open
            self.guard_error(ctx, 6, error)
            return None
        if finding is None:
            return None
        return await self.apply_inspection(ctx, finding)

    async def apply_inspection(
        self, ctx: rings.Ctx, finding: inspection.Finding
    ) -> Response | None:
        if finding.category == "payload":  # the link to Hedwig: evidence level 3 for the service
            # decoded, so evidence.read_log's patterns match the payload in the log line
            target = unquote(ctx.path + (f"?{ctx.query}" if ctx.query else ""))
            self.hedwig.record(ctx.service_name, ctx.ip, ctx.method, target, finding.status,
                               finding.rule)  # fmt: skip
        if self.monitoring(ctx):
            self.emit(finding.status and "trapped" if finding.trap else "blocked", ctx,
                      finding.status, 6, category=finding.category, rule=finding.rule,
                      **{"hedwig.monitor": True})  # fmt: skip
            return None
        if finding.trap:
            self.state.trap(ctx.ip)
            self.emit("trapped", ctx, None, 6, category=finding.category, rule=finding.rule,
                      **(finding.detail or {}))  # fmt: skip
            return await self.maze(ctx)
        self.emit("blocked", ctx, finding.status, 6, category=finding.category, rule=finding.rule,
                  **(finding.detail or {}))  # fmt: skip
        return self.with_security(PlainTextResponse("Forbidden", finding.status))

    def inspect_response(self, ctx: rings.Ctx, status: int, headers, body: bytes):
        """Returns a Finding when the response should be replaced, else None."""
        try:
            if 300 <= status < 400:
                location = headers.get("location", "")
                if inspection.external_location(
                    location, self.own_hosts, (ctx.service.redirect_hosts if ctx.service else [])
                ):
                    return inspection.Finding("response", "open-redirect-location", "phishing",
                                              trap=False, status=502)  # fmt: skip
            if body:
                return inspection.scan_response(
                    body, headers.get("content-type", ""), self.own_hosts
                )
        except Exception as error:  # fail open
            self.guard_error(ctx, 6, error)
        return None

    async def forward(self, ctx: rings.Ctx) -> Response:
        service = ctx.service
        assert service is not None
        url = service.upstream.rstrip("/") + ctx.inner_path
        if ctx.query:
            url += "?" + ctx.query
        headers = []
        for key, value in ctx.headers.items():
            if key.lower() == "cookie":
                value = challenge.strip_session_cookie(value)
            if value and key.lower() not in REQUEST_DROP:
                headers.append((key, value))
        headers += [("x-forwarded-for", ctx.ip), ("x-real-ip", ctx.ip)]
        upstream_request = self.upstream.build_request(
            ctx.method, url, headers=headers, content=ctx.body
        )
        try:
            upstream = await self.upstream.send(upstream_request, stream=True)
        except httpx.HTTPError as error:
            self.emit("allowed", ctx, 502, "centre", rule=f"upstream: {type(error).__name__}")
            return self.with_security(PlainTextResponse("Bad Gateway", 502))

        status = upstream.status_code
        if status < 400:  # the decoy copies the real service's header set
            self.decoy.learn(ctx.service_name or "", list(upstream.headers.multi_items()))

        # Ring 6 outbound: buffer a small HTML body (or just read the headers of a redirect),
        # inspect it, and replace a bad response with 502 rather than pass it on.
        buffered = await self._maybe_buffer(upstream, status)
        if buffered is not None:
            finding = self.inspect_response(ctx, status, upstream.headers, buffered)
            if finding and not self.monitoring(ctx):
                await upstream.aclose()
                self.emit("blocked", ctx, finding.status, 6, category=finding.category,
                          rule=finding.rule)  # fmt: skip
                return self.with_security(PlainTextResponse("Bad Gateway", finding.status))
            if finding:
                self.emit("blocked", ctx, finding.status, 6, category=finding.category,
                          rule=finding.rule, **{"hedwig.monitor": True})  # fmt: skip

        action, ring, extra = "allowed", "centre", {}
        delay = 0.0
        try:
            result = rings.login_result(ctx, status, self.state, self.config)
        except Exception as error:
            self.guard_error(ctx, 5, error)
            result = None
        if result and result.failed:
            action, ring = "login_failed", 5
            extra = {"category": "bruteforce", "rule": f"login-failure-{result.failures}"}
            if self.monitoring(ctx):
                extra["hedwig.monitor"] = True
            else:
                delay = result.delay

        if ctx.tarpit and not self.monitoring(ctx):
            if self.state.tarpitted >= self.config.flood.tarpit_cap:
                await upstream.aclose()
                self.emit("blocked", ctx, 429, 2, category="ddos", rule="tarpit-cap")
                return self.with_security(PlainTextResponse("Too Many Requests", 429))
            delay = max(delay, rings.tarpit_delay(self.state.suspicion(ctx.client), self.config))
            if action == "allowed":
                action, ring = "tarpitted", 2

        if delay:
            self.state.tarpitted += ctx.tarpit
            try:
                await self.sleep(delay)
            finally:
                self.state.tarpitted -= ctx.tarpit

        self.emit(action, ctx, status, ring, **extra)
        if result and result.trip:
            self.stop_response_after(ctx, result.trip)

        if buffered is not None:
            await upstream.aclose()
            response = Response(buffered, status_code=status)
            headers = [
                (k.lower().encode("latin-1"), v.encode("latin-1"))
                for k, v in upstream.headers.multi_items()
                if k.lower() not in HOP_BY_HOP and k.lower() != "content-length"
            ]
            response.raw_headers = headers + [(b"content-length", str(len(buffered)).encode())]
            return self.with_security(response)

        # raw bytes pass through still encoded, so the upstream content-length stays valid
        response = StreamingResponse(
            upstream.aiter_raw(), status_code=status, background=BackgroundTask(upstream.aclose)
        )
        response.raw_headers = [
            (k.lower().encode("latin-1"), v.encode("latin-1"))
            for k, v in upstream.headers.multi_items()
            if k.lower() not in HOP_BY_HOP
        ]
        return self.with_security(response)

    async def _maybe_buffer(self, upstream: httpx.Response, status: int) -> bytes | None:
        """Read the body into memory when ring 6 should inspect it: a small, unencoded HTML
        response, or a redirect (whose Location is inspected without a body). Else None: the
        response streams through untouched."""
        headers = upstream.headers
        ctype = headers.get("content-type", "").lower()
        declared = headers.get("content-length", "")
        too_big = declared.isdigit() and int(declared) > self.config.max_response_scan
        html = "html" in ctype and not headers.get("content-encoding") and not too_big
        if html:
            return (await upstream.aread())[: self.config.max_response_scan]
        if 300 <= status < 400:
            return b""  # no body needed; inspect_response reads the Location header
        return None

    def stop_response_after(self, ctx: rings.Ctx, stop: rings.Stop) -> None:
        """A decision made after the answer went out (a brute-force trip): record and apply it."""
        if self.monitoring(ctx):
            self.emit(
                stop.action, ctx, stop.status, stop.ring, category=stop.category,
                rule=stop.rule, **{"hedwig.monitor": True},
            )  # fmt: skip
            return
        if stop.trap and self.state.trap(ctx.ip):
            self.emit(
                "trapped", ctx, stop.status, stop.ring, category=stop.category, rule=stop.rule
            )

    async def solve_challenge(self, request: Request, ctx: rings.Ctx) -> Response:
        """Ring 3's answer desk: a correct proof of work earns a session cookie bound to the IP."""
        state, config = self.state, self.config
        try:
            body = await asyncio.wait_for(request.body(), config.flood.body_timeout_s)
            token, nonce = challenge.parse_solution(
                body[:4096], request.headers.get("content-type", "")
            )
            verdict = self.challenger.check_solution(
                ctx.ip, token, nonce, config.challenge.token_seconds
            )
        except (ValueError, TimeoutError, ClientDisconnect):
            verdict = challenge.Verdict(False, "malformed")
        if not verdict.ok:
            state.add(ctx.client, signals.CHALLENGE_FAILED)
            self.emit(
                "blocked", ctx, 403, 3, category="challenge", rule=f"challenge-{verdict.reason}"
            )
            return self.with_security(JSONResponse({"ok": False, "error": verdict.reason}, 403))

        seconds = self.challenger.session_seconds(state.suspicion(ctx.client), config)
        ctx.client.challenges_pending = 0
        self.emit("challenge_solved", ctx, 200, 3, category="challenge", rule="proof-of-work")
        response = JSONResponse({"ok": True, "session_seconds": seconds})
        response.set_cookie(
            challenge.COOKIE, self.challenger.make_session(ctx.ip, seconds), max_age=seconds,
            path="/", httponly=True, samesite="lax",
        )  # fmt: skip
        response.headers["Cache-Control"] = "no-store"
        return self.with_security(response)

    async def aclose(self) -> None:
        await self.upstream.aclose()
        await self.source.aclose()
        await self.agents.llm.aclose()
        if self.shipper:
            self.shipper.close()
        self.bus.close()

    async def watch(self) -> None:
        """Background loop: the agents' turn every few seconds, never in the request path."""
        while True:
            try:
                if self.config.agents.enabled:
                    await self.agents.tick()
                else:
                    await self.source.ping()
                self.notifier.poll()
            except Exception as error:  # the loop must never die
                print(f"chakravyuha: agents failed: {type(error).__name__}: {error}")
            await asyncio.sleep(self.config.agents.interval_s)


def create_app(config: Config, **kwargs) -> Starlette:
    guard = Guard(config, **kwargs)

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        task = asyncio.create_task(guard.watch())
        yield
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await guard.aclose()

    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    app = Starlette(
        routes=[
            Route(f"{INTERNAL}/health", guard.health, methods=["GET"]),
            Route(f"{INTERNAL}/events", guard.events, methods=["GET"]),
            Route("/{path:path}", guard.handle, methods=methods),
        ],
        lifespan=lifespan,
    )
    app.state.guard = guard
    return app
