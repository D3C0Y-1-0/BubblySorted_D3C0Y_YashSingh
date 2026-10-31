import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from chakravyuha.challenge import COOKIE
from chakravyuha.config import Config
from chakravyuha.proxy import create_app
from chakravyuha.state import State

TOKEN = "test-token"


@pytest.fixture
def anyio_backend():
    return "asyncio"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class Upstream:
    """A stub bank service that records what reached it."""

    def __init__(self) -> None:
        self.seen: list[dict] = []

    async def echo(self, request: Request) -> Response:
        body = await request.body()
        self.seen.append(
            {
                "method": request.method,
                "path": request.url.path,
                "query": request.url.query,
                "headers": dict(request.headers),
                "body": body,
            }
        )
        if request.url.path == "/login":
            data = await request.json() if body else {}
            ok = data.get("password") == "demo-pass"
            return JSONResponse({"ok": ok}, 200 if ok else 401)
        return Response(body, 200, media_type="application/octet-stream")

    def app(self) -> Starlette:
        return Starlette(routes=[Route("/{p:path}", self.echo, methods=["GET", "POST", "PUT"])])


class Sleeps:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


@pytest.fixture
def make_guard():
    def build(**overrides):
        settings = {
            "data_dir": None,
            "stdout_events": False,
            "challenge": {"difficulty": 4},  # cheap puzzles, so tests can solve them
            "services": {
                "transaction": {
                    "upstream": "http://transaction",
                    "rate": 5,
                    "login_paths": ["/login"],
                }
            },
        }
        settings.update(overrides)
        config = Config.model_validate(settings)
        upstream = Upstream()
        clock = Clock()
        sleeps = Sleeps()
        app = create_app(
            config,
            token=TOKEN,
            transport=httpx.ASGITransport(app=upstream.app()),
            state=State(config, clock=clock),
            sleep=sleeps,
        )
        guard = app.state.guard

        def client(ip: str = "10.0.0.1", session: bool = True) -> httpx.AsyncClient:
            """A client at `ip`. With `session`, it holds a valid ring 3 cookie for that IP, as a
            browser would after solving the challenge (ring 3 itself is in test_challenge.py)."""
            transport = httpx.ASGITransport(app=app, client=(ip, 40000))
            cookies = {COOKIE: guard.challenger.make_session(ip, 1800)} if session else None
            return httpx.AsyncClient(transport=transport, base_url="http://guard", cookies=cookies)

        return guard, upstream, clock, sleeps, client

    return build
