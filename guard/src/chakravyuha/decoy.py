"""Ring 7: the maze. A decoy bank served by the Guard itself to trapped clients.

It answers the same routes as the real bank with the same shapes, behind the same challenge,
with the same cookies and the header set learned from the real services, so nothing in how a
client gets in tells it which side it is on. Its content comes from `guard/decoy/bank.json`
(written by the Illusionist agent before the demo) or, without that file, from a built-in
generator with a fixed seed. Honeytoken placeholders in the content are filled per client.
"""

import json
import mimetypes
import random
import re
import uuid
from dataclasses import dataclass, field
from email.utils import formatdate
from pathlib import Path
from typing import Any

from starlette.responses import Response

from .config import GUARD_ROOT, Config
from .rings import Ctx
from .state import State

DATA_FILE = GUARD_ROOT / "decoy" / "bank.json"
UNLEARNED = {
    "content-length", "content-type", "set-cookie", "etag", "last-modified",
    "transfer-encoding", "content-encoding", "connection", "keep-alive",
}  # fmt: skip
PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")


@dataclass
class Maze:
    """What one trapped client has seen of the decoy."""

    success_at: int  # the login attempt (counted from the trap) that "succeeds"
    attempts: int = 0
    logged_in: bool = False
    balance: float = 0.0
    next_transfer: int = 5001
    sessions: set[str] = field(default_factory=set)


@dataclass
class Answer:
    response: Response
    status: int
    rule: str
    delay: float = 0.0
    login_failed: bool = False
    session: str | None = None  # a decoy session handed out by this answer


# -- the default dataset -------------------------------------------------------------------
FIRST = ["Lena", "Jonas", "Mia", "Felix", "Sara", "Noah", "Emma", "Paul", "Lea", "Ben", "Anna"]
LAST = ["Weber", "Fischer", "Wagner", "Becker", "Hoffmann", "Koch", "Richter", "Klein", "Wolf"]
MERCHANTS = [
    "Grocer GmbH", "City Power", "Rail Pass", "Bookshop Am Markt", "Cafe Linde", "Telecom Plus",
    "Pharmacy Nord", "Cinema Royal", "Hardware Haus", "Bakery Sonne",
]  # fmt: skip


def fake_iban(rng: random.Random) -> str:
    digits = "".join(rng.choice("0123456789") for _ in range(18))
    return f"DE{rng.randint(10, 99)} {' '.join(digits[i : i + 4] for i in range(0, 16, 4))}"


def default_dataset(seed: int = 7) -> dict[str, Any]:
    """Plausible fake customers and history. The Illusionist's rule fallback uses this too."""
    rng = random.Random(seed)
    customers = []
    for i in range(12):
        customers.append(
            {
                "id": 7000 + i,
                "name": f"{rng.choice(FIRST)} {rng.choice(LAST)}",
                "account": fake_iban(rng),
                "balance": round(rng.uniform(800, 25_000), 2),
            }
        )
    history = []
    for n in range(12):
        merchant = rng.choice(MERCHANTS)
        history.append(
            {
                "id": 4100 + n,
                "date": f"2026-10-{n + 18:02d}",
                "to": merchant,
                "amount": -round(rng.uniform(4, 180), 2),
                "memo": f"Card payment {merchant}",
            }
        )
    history.insert(
        5,
        {
            "id": 4099,
            "date": "2026-10-22",
            "from": "Partner settlement",
            "amount": 1840.00,
            "memo": "Settlement API key for partner portal: {{api_key}}",
        },
    )
    main = customers[0]
    return {
        "customers": customers,
        "services": {
            "web": {"static": "bank/web"},
            "transaction": {
                "routes": {
                    "GET /": {"body": {"service": "transaction", "bank": "Hedwig Demo Bank"}},
                    "GET /health": {"body": {"status": "ok"}},
                    "POST /login": {"handler": "login"},
                    "GET /balance": {
                        "handler": "balance",
                        "body": {
                            "account": main["account"],
                            "balance": main["balance"],
                            "currency": "EUR",
                        },
                    },  # fmt: skip
                    "GET /transactions": {
                        "body": {"account": main["account"], "transactions": history}
                    },
                    "POST /transfer": {"handler": "transfer"},
                }
            },
        },
    }


def load_dataset(path: Path = DATA_FILE) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default_dataset()


def _route_regex(path: str) -> re.Pattern:
    parts = [
        f"(?P<{p[1:-1]}>[^/]+)" if p.startswith("{") and p.endswith("}") else re.escape(p)
        for p in path.split("/")
    ]
    return re.compile("/".join(parts) + r"\Z")


class Decoy:
    def __init__(
        self,
        config: Config,
        *,
        dataset: dict[str, Any] | None = None,
        root: Path = GUARD_ROOT,
        rng: random.Random | None = None,
    ) -> None:
        self.config = config
        self.root = root
        self.rng = rng or random.Random()
        self.mazes: dict[str, Maze] = {}
        self.sessions: dict[str, str] = {}  # decoy session -> the IP it was handed to
        self.profiles: dict[str, list[tuple[str, str]]] = {}  # service -> learned headers
        self.fill = lambda kind, ip: f"{{{{{kind}}}}}"  # honeytokens plug in here (C7)
        self.load(dataset or load_dataset())

    def load(self, dataset: dict[str, Any]) -> None:
        self.dataset = dataset
        self.routes: dict[str, list[tuple[str, re.Pattern, dict]]] = {}
        for name, spec in dataset.get("services", {}).items():
            table = []
            for key, route in (spec.get("routes") or {}).items():
                method, _, path = key.partition(" ")
                table.append((method.upper(), _route_regex(path), route))
            self.routes[name] = table

    # -- learning from the real bank -------------------------------------------------------
    def learn(self, service: str, headers: list[tuple[str, str]]) -> None:
        self.profiles[service] = [(k, v) for k, v in headers if k.lower() not in UNLEARNED]

    def _dress(self, response: Response, service: str) -> Response:
        """Add the headers the real service sends (duplicates included), with a fresh date."""
        for key, value in self.profiles.get(service, []):
            value = formatdate(usegmt=True) if key.lower() == "date" else value
            response.raw_headers.append((key.lower().encode("latin-1"), value.encode("latin-1")))
        return response

    # -- the maze --------------------------------------------------------------------------
    def maze(self, ip: str) -> Maze:
        maze = self.mazes.get(ip)
        if maze is None:
            balance = self._customer().get("balance", 2500.0)
            maze = self.mazes[ip] = Maze(success_at=self.rng.randint(3, 10), balance=balance)
        return maze

    def forget(self, ip: str) -> None:
        self.mazes.pop(ip, None)

    def _customer(self) -> dict:
        customers = self.dataset.get("customers") or [{}]
        return customers[0]

    def _render(self, value: Any, ip: str, params: dict[str, str]) -> Any:
        if isinstance(value, str):
            value = PLACEHOLDER.sub(lambda m: self.fill(m.group(1), ip), value)
            for key, param in params.items():
                value = value.replace("{" + key + "}", param)
            return value
        if isinstance(value, dict):
            return {k: self._render(v, ip, params) for k, v in value.items()}
        if isinstance(value, list):
            return [self._render(v, ip, params) for v in value]
        return value

    def _json(self, ctx: Ctx, status: int, body: Any, rule: str, **extra) -> Answer:
        response = Response(
            json.dumps(body, separators=(",", ":")), status, media_type="application/json"
        )
        return Answer(self._dress(response, ctx.service_name or ""), status, rule, **extra)

    def respond(self, ctx: Ctx, state: State) -> Answer:
        name = ctx.service_name or ""
        spec = self.dataset.get("services", {}).get(name, {})
        if static := spec.get("static"):
            return self._static(ctx, self.root / static)
        method = "GET" if ctx.method == "HEAD" else ctx.method
        for route_method, regex, route in self.routes.get(name, []):
            if route_method == method and (match := regex.match(ctx.inner_path)):
                handler = route.get("handler")
                if handler == "login":
                    return self._login(ctx, state)
                if handler == "transfer":
                    return self._transfer(ctx)
                body = self._render(route.get("body", {}), ctx.ip, match.groupdict())
                if handler == "balance" and isinstance(body, dict):
                    body["balance"] = round(self.maze(ctx.ip).balance, 2)
                return self._json(ctx, route.get("status", 200), body, "decoy")
        return self._json(ctx, 404, {"error": "not found"}, "decoy")

    def _static(self, ctx: Ctx, folder: Path) -> Answer:
        name = ctx.inner_path.strip("/") or "index.html"
        path = (folder / name).resolve()
        service = ctx.service_name or ""
        if folder.resolve() not in path.parents or not path.is_file():
            return Answer(self._dress(Response("Not Found", 404), service), 404, "decoy")
        media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        body = b"" if ctx.method == "HEAD" else path.read_bytes()
        response = Response(body, 200, media_type=media_type)
        return Answer(self._dress(response, service), 200, "decoy")

    def _login(self, ctx: Ctx, state: State) -> Answer:
        """After a trap, a random attempt between the 3rd and the 10th "succeeds", with the
        same back-off as before, so it looks like the attacker finally guessed right."""
        maze = self.maze(ctx.ip)
        maze.attempts += 1
        if maze.logged_in or maze.attempts >= maze.success_at:
            maze.logged_in = True
            token = self.fill("session", ctx.ip)
            if token.startswith("{{"):
                token = str(uuid.uuid4())
            maze.sessions.add(token)
            self.sessions[token] = ctx.ip
            answer = self._json(
                ctx, 200, {"ok": True, "user": ctx.username or "demo", "session": token},
                "decoy-login", session=token,
            )  # fmt: skip
            answer.response.headers.append("set-cookie", f"bank_session={token}; Path=/; HttpOnly")
            return answer
        failures = state.note_login_failure(ctx.client)
        login = self.config.login
        delay = min(login.backoff_step_s * failures, login.backoff_max_s)
        return self._json(
            ctx, 401, {"ok": False, "error": "invalid credentials"}, "decoy-login",
            delay=delay, login_failed=True,
        )  # fmt: skip

    def _transfer(self, ctx: Ctx) -> Answer:
        maze = self.maze(ctx.ip)
        try:
            data = json.loads(ctx.body or b"{}")
            amount, to = float(data.get("amount", 0)), str(data.get("to", ""))
        except (ValueError, TypeError, AttributeError):
            amount, to = 0.0, ""
        if amount <= 0 or amount > maze.balance or not to.strip():
            return self._json(ctx, 400, {"ok": False, "error": "invalid transfer"}, "decoy")
        maze.balance -= amount
        maze.next_transfer += 1
        return self._json(ctx, 200, {"ok": True, "id": maze.next_transfer}, "decoy-transfer")
