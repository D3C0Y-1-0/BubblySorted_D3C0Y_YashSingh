"""The Chakravyuha dashboard: a page on 127.0.0.1:8090 that shows the formation live.

Plain HTML, CSS and JavaScript from `static/`, no build step and no CDN. The page loads a
snapshot, then follows `/api/stream` (Server-Sent Events): batches of events as they happen
and a fresh snapshot every second.
"""

import asyncio
import json
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .proxy import Guard

STATIC = Path(__file__).parent / "static"
CLIENT_WINDOW_S = 600  # clients seen in the last 10 minutes are drawn
MAX_DOTS = 400
BATCH = 500


def _active(table: dict[str, float], check) -> list[str]:
    return [ip for ip in list(table) if check(ip)]


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
    if events:
        data["events"] = guard.bus.recent(events)
    return data


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

    return Starlette(
        routes=[
            Route("/", index),
            Route("/api/snapshot", api_snapshot),
            Route("/api/stream", api_stream),
            Mount("/static", StaticFiles(directory=STATIC), name="static"),
        ]
    )
