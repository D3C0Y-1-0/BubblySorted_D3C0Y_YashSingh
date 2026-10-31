"""Honeytokens: fake credentials that only exist inside the decoy bank.

Each trapped client gets its own set, derived from the Guard secret, the client IP and the
current epoch, so any use names the exact client that received it. A request on any ring that
carries one is a certain compromise signal: that value was only ever shown inside the maze.
Rotating starts a new epoch; tokens already handed out stay detectable.

The one exception is a decoy session cookie coming back from the IP it was given to: that is
just the trapped client's own browser or script replaying its cookie, not a stolen credential.
"""

import base64
import hashlib
import hmac
import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote

CANDIDATE = re.compile(r"[A-Za-z0-9_\-\.]{16,}")
KINDS = ("api_key", "jwt", "session", "support_password", "db_password")


@dataclass(frozen=True)
class Token:
    value: str
    kind: str
    ip: str  # the trapped client it was handed to
    epoch: int
    issued: str


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Honeytokens:
    def __init__(self, secret: bytes, path: Path | None = None) -> None:
        self.key = hmac.new(secret, b"chakravyuha-honeytokens", hashlib.sha256).digest()
        self.path = path
        self.epoch = 0
        self.registry: dict[str, Token] = {}
        self._load()

    def _load(self) -> None:
        if not self.path or not self.path.is_file():
            return
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                token = Token(**json.loads(line))
                self.registry[token.value] = token
                self.epoch = max(self.epoch, token.epoch)
        except (OSError, ValueError, TypeError):
            pass

    def _save(self, token: Token) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(token)) + "\n")
        except OSError:
            pass

    def _digest(self, ip: str, kind: str) -> bytes:
        return hmac.new(self.key, f"{self.epoch}|{ip}|{kind}".encode(), hashlib.sha256).digest()

    def make(self, kind: str, ip: str) -> str:
        d = self._digest(ip, kind)
        if kind == "api_key":
            return "hk_live_" + d.hex()[:32]
        if kind == "jwt":
            header = _b64(b'{"alg":"HS256","typ":"JWT"}')
            body = _b64(
                json.dumps(
                    {"sub": "ops-admin", "role": "admin", "iat": 1793404800, "jti": d.hex()[:12]},
                    separators=(",", ":"),
                ).encode()
            )
            return f"{header}.{body}.{_b64(d)}"
        if kind == "session":
            return str(uuid.UUID(bytes=d[:16], version=4))
        if kind == "support_password":
            return "Hedwig-Support-" + base64.b32encode(d[:10]).decode().rstrip("=").lower()
        return "pg_" + d.hex()[:24]  # db_password and anything else

    def fill(self, kind: str, ip: str) -> str:
        """The token of this kind for this client, registered so its use can be recognised."""
        value = self.make(kind, ip)
        if value not in self.registry:
            token = Token(
                value, kind, ip, self.epoch, datetime.now(UTC).isoformat(timespec="seconds")
            )
            self.registry[value] = token
            self._save(token)
        return value

    def rotate(self) -> int:
        self.epoch += 1
        return self.epoch

    def scan(self, *parts: str | bytes) -> list[Token]:
        if not self.registry:
            return []
        found: dict[str, Token] = {}
        for part in parts:
            if isinstance(part, bytes):
                part = part[:1_000_000].decode("utf-8", "replace")
            if not part:
                continue
            for text in {part, unquote(part)}:
                for candidate in CANDIDATE.findall(text):
                    for piece in (candidate, *candidate.split(".")):
                        if token := self.registry.get(piece):
                            found[token.value] = token
        return list(found.values())

    @staticmethod
    def decoded_basic(header: str) -> str:
        """Credentials in a Basic auth header, decoded, so a token used as a password is seen."""
        if not header.lower().startswith("basic "):
            return ""
        try:
            return base64.b64decode(header[6:].strip()).decode("utf-8", "replace")
        except ValueError:
            return ""
