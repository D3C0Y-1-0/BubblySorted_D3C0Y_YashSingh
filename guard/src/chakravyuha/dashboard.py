"""The Chakravyuha dashboard: a page on 127.0.0.1:8090 that shows the formation live.

Plain HTML, CSS and JavaScript from `static/`, no build step and no CDN. The page loads a
snapshot, then follows `/api/stream` (Server-Sent Events): batches of events as they happen
and a fresh snapshot every second.
"""

import asyncio
import hmac
import json
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import hedwig_view
from .proxy import Guard

STATIC = Path(__file__).parent / "static"
CLIENT_WINDOW_S = 600  # clients seen in the last 10 minutes are drawn
MAX_DOTS = 400
BATCH = 500


def _active(table: dict[str, float], check) -> list[str]:
    return [ip for ip in list(table) if check(ip)]


def _left(table: dict[str, float], ips, now: float) -> list[dict]:
    rows = [{"ip": ip, "left_s": round(table.get(ip, now) - now)} for ip in ips]
    return sorted(rows, key=lambda r: -r["left_s"])[:50]


def snapshot(guard: Guard, *, events: int = 0) -> dict[str, Any]:
    state, stats = guard.state, guard.stats
    now = stats.clock()
    banned = set(_active(state.bans, state.banned))
    trapped = set(_active(state.traps, state.trapped))

    clients = []
    for view in sorted(stats.clients.values(), key=lambda v: v.seen_at, reverse=True):
        if now - view.seen_at > CLIENT_WINDOW_S or len(clients) >= MAX_DOTS:
            break
        client = state.clients.get(view.ip)
        clients.append(
            {
                "ip": view.ip,
                "suspicion": round(state.suspicion(client), 2) if client else 0,
                "ring": view.ring,
                "action": view.action,
                "status": view.status,
                "service": view.service,
                "path": view.path[:120],
                "requests": view.requests,
                "stops": view.stops,
                "age": round(now - view.seen_at, 1),
                "banned": view.ip in banned,
                "trapped": view.ip in trapped,
                "allowlisted": state.allowlisted(view.ip),
                "signals": dict(client.reasons) if client else {},
            }
        )
    suspects = sorted(
        (c for c in clients if c["suspicion"] > 0), key=lambda c: c["suspicion"], reverse=True
    )[:10]
    actions = stats.actions
    data = {
        "level": state.level,
        "mode": guard.config.mode,
        "uptime": round(now - stats.started_at),
        "thresholds": guard.config.suspicion.model_dump(),
        "rates": stats.rates(),
        "totals": {
            "requests": stats.total,
            "allowed": actions["allowed"] + actions["tarpitted"] + actions["login_failed"],
            "stopped": sum(stats.ring_stops.values()),
            "login_failed": actions["login_failed"],
            "errors": actions["guard-error"],
        },
        "ring_stops": dict(stats.ring_stops),
        "challenges": {"issued": actions["challenged"], "solved": actions["challenge_solved"]},
        "tarpitted_now": state.tarpitted,
        "in_flight": state.in_flight,
        "bans": len(banned),
        "traps": len(trapped),
        "passwords": len(stats.passwords),
        "clients": clients,
        "suspects": [
            {k: c[k] for k in ("ip", "suspicion", "signals", "ring", "allowlisted")}
            for c in suspects
        ],
    }
    state_now = state.now()
    data.update(
        {
            "trapped_list": _left(state.traps, trapped, state_now),
            "banned_list": _left(state.bans, banned, state_now),
            "services": {
                name: guard.config.service_mode(svc) for name, svc in guard.config.services.items()
            },
            "alarms": list(guard.alarms),
            "campaigns": guard.campaigns[:20],
            "feed": list(guard.feed)[-30:],
            "agents": guard.agents_status,
            "elk": guard.elk_status,
            "shipper_dropped": getattr(getattr(guard, "shipper", None), "dropped", 0),
        }
    )
    if events:
        data["events"] = guard.bus.recent(events)
    return data


def control(guard: Guard, data: dict[str, Any]) -> tuple[bool, str]:
    """An operator action from the dashboard. Allowlist changes are not among them."""
    action = str(data.get("action", ""))
    ip = str(data.get("ip", ""))[:64]
    if action == "release":
        return guard.release(ip), f"released {ip}"
    if action == "lift_ban":
        return guard.lift_ban(ip), f"lifted the ban on {ip}"
    if action == "level":
        level = str(data.get("level", ""))
        return guard.set_level(level), f"level {level}"
    if action == "mode":
        service, mode = str(data.get("service", "")), str(data.get("mode", ""))
        return guard.set_mode(service, mode), f"{service} {mode}"
    if action == "rotate_tokens" and hasattr(guard, "rotate_tokens"):
        guard.rotate_tokens("Operator")
        return True, "honeytokens rotated"
    return False, f"unknown action {action!r}"


def _sse(kind: str, data: Any) -> str:
    return f"event: {kind}\ndata: {json.dumps(data, separators=(',', ':'), default=str)}\n\n"


async def stream(guard: Guard, *, tick: float = 1.0, limit: int | None = None):
    """Event batches as they happen, a snapshot every `tick` seconds. `limit` is for tests."""
    loop = asyncio.get_running_loop()
    queue = guard.bus.subscribe()
    sent = 0
    try:
        yield _sse("snapshot", snapshot(guard, events=200))
        sent += 1
        next_tick = loop.time() + tick
        while limit is None or sent < limit:
            try:
                first = await asyncio.wait_for(queue.get(), max(next_tick - loop.time(), 0))
            except TimeoutError:
                first = None
            if first is not None:
                batch = [first]
                while len(batch) < BATCH and not queue.empty():
                    batch.append(queue.get_nowait())
                yield _sse("events", batch)
                sent += 1
            if loop.time() >= next_tick:
                yield _sse("snapshot", snapshot(guard))
                sent += 1
                next_tick = loop.time() + tick
    finally:
        guard.bus.unsubscribe(queue)


def create_dashboard(guard: Guard) -> Starlette:
    async def index(request: Request):
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})

    async def api_snapshot(request: Request):
        return JSONResponse(snapshot(guard, events=200))

    async def api_stream(request: Request):
        return StreamingResponse(
            stream(guard),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    async def api_control(request: Request):
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not guard.token or not hmac.compare_digest(supplied.encode(), guard.token.encode()):
            return JSONResponse({"ok": False, "error": "unauthorized"}, 401)
        try:
            data = await request.json()
        except ValueError:
            data = None
        if not isinstance(data, dict):
            return JSONResponse({"ok": False, "error": "expected a JSON object"}, 400)
        ok, message = control(guard, data)
        return JSONResponse({"ok": ok, "message": message}, 200 if ok else 400)

    bank = guard.config.bank_root
    repo = Path(__file__).resolve().parents[3]

    async def api_architecture(request: Request):
        data = await asyncio.to_thread(hedwig_view.architecture, guard.config.services, bank)
        return JSONResponse({"services": data, "infra": await asyncio.to_thread(hedwig_view.infra)})

    async def api_hedwig(request: Request):
        data = await asyncio.to_thread(hedwig_view.hedwig_data, bank)
        data["soc_reports"] = hedwig_view.soc_reports(bank)
        return JSONResponse(data)

    async def api_snippet(request: Request):
        q = request.query_params
        try:
            line = int(q.get("line", "1"))
        except ValueError:
            line = 1
        return JSONResponse(
            hedwig_view.snippet(bank, q.get("service", ""), q.get("file", ""), line)
        )

    async def api_soc_file(request: Request):
        path = hedwig_view.soc_file(bank, request.path_params["name"])
        if path is None:
            return JSONResponse({"error": "not found"}, 404)
        return FileResponse(path, media_type="application/pdf")

    async def api_run(request: Request):
        """Rescan or write the SOC report: starts the hedwig command (token required)."""
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not guard.token or not hmac.compare_digest(supplied.encode(), guard.token.encode()):
            return JSONResponse({"ok": False, "error": "unauthorized"}, 401)
        what = request.path_params["what"]
        args = {"scan": ["scan", "--json"], "soc": ["soc-report", "--since", "30m", "--email"]}.get(
            what
        )
        if args is None:
            return JSONResponse({"ok": False, "error": "unknown action"}, 400)
        ok, output = await asyncio.to_thread(hedwig_view.run_hedwig, bank, args, repo)
        return JSONResponse({"ok": ok, "message": output[-300:]}, 200 if ok else 500)

    async def api_clear_run(request: Request):
        """Delete one fix run's logs: the "Clear" button on the Agents at work panel."""
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not guard.token or not hmac.compare_digest(supplied.encode(), guard.token.encode()):
            return JSONResponse({"ok": False, "error": "unauthorized"}, 401)
        ok = await asyncio.to_thread(hedwig_view.clear_run, bank, request.path_params["run_id"])
        return JSONResponse({"ok": ok}, 200 if ok else 404)

    return Starlette(
        routes=[
            Route("/", index),
            Route("/api/architecture", api_architecture),
            Route("/api/hedwig", api_hedwig),
            Route("/api/snippet", api_snippet),
            Route("/api/soc/{name}", api_soc_file),
            Route("/api/run/{what}", api_run, methods=["POST"]),
            Route("/api/hedwig/runs/{run_id}", api_clear_run, methods=["DELETE"]),
            Route("/api/snapshot", api_snapshot),
            Route("/api/stream", api_stream),
            Route("/api/control", api_control, methods=["POST"]),
            Mount("/static", StaticFiles(directory=STATIC), name="static"),
        ]
    )
