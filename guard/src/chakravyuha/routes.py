"""Ring 4: only known routes exist.

Each service lists the routes it serves as `"METHOD /path"`; a `{name}` segment matches any one
path segment and HEAD is allowed wherever GET is. Anything else gets 404 before it reaches a
service. Paths that scanners probe for (`/.env`, `/wp-admin`, `.git`, ...) score extra.

A service with no route list is left open by ring 4 (the CLI warns about it).
"""

import re
from dataclasses import dataclass

from . import state as signals
from .config import Config, Service
from .rings import Ctx, Stop
from .state import State

PROBE = re.compile(
    r"(?:^|/)(?:\.env|\.git|\.svn|\.hg|\.ds_store|\.aws|\.ssh|\.htaccess|\.htpasswd|\.npmrc|"
    r"wp-admin|wp-login\.php|wp-content|wp-includes|xmlrpc\.php|phpmyadmin|pma|myadmin|admin|"
    r"administrator|manager/html|server-status|server-info|actuator|console|cgi-bin|"
    r"vendor/phpunit|config\.php|configuration\.php|web\.config|settings\.py|backup|backups|"
    r"dump\.sql|db\.sql|database\.sql|etc/passwd|shell\.php|cmd\.php|c99\.php|r57\.php|"
    r"id_rsa|credentials|\.well-known/security\.txt\.bak)(?:/|$|\.|\?)"
    r"|\.(?:bak|old|orig|save|swp|sql|tar|tgz|tar\.gz|zip|7z|rar)$",
    re.I,
)


@dataclass(frozen=True)
class Route:
    method: str
    pattern: re.Pattern


def compile_routes(service: Service) -> list[Route]:
    routes = []
    for entry in service.routes:
        method, _, path = entry.strip().partition(" ")
        parts = [
            "[^/]+" if part.startswith("{") and part.endswith("}") else re.escape(part)
            for part in path.strip().split("/")
        ]
        routes.append(Route(method.upper(), re.compile("/".join(parts) + r"\Z")))
    return routes


def is_probe(path: str) -> bool:
    return bool(PROBE.search(path))


class RouteRing:
    def __init__(self, config: Config) -> None:
        self.tables = {name: compile_routes(svc) for name, svc in config.services.items()}

    def known(self, ctx: Ctx) -> bool:
        if ctx.service is None:
            return False
        table = self.tables.get(ctx.service_name or "")
        if not table:
            return True  # no route list: ring 4 is open for this service
        method = "GET" if ctx.method == "HEAD" else ctx.method
        return any(r.method == method and r.pattern.match(ctx.inner_path) for r in table)

    def classify(self, ctx: Ctx) -> str:
        """ok | unknown | probe. A route the service really lists is never a probe."""
        if self.known(ctx):
            return "ok"
        return "probe" if is_probe(ctx.path) else "unknown"

    def score(self, ctx: Ctx, state: State) -> str:
        """Add ring 4's points without stopping (used when ring 3 stops the request first)."""
        kind = self.classify(ctx)
        if kind == "probe":
            state.add(ctx.client, signals.PROBE_ROUTE)
        elif kind == "unknown":
            state.add(ctx.client, signals.UNKNOWN_ROUTE)
        return kind

    def ring(self, ctx: Ctx, state: State, config: Config) -> Stop | None:
        kind = self.score(ctx, state)
        if kind == "ok":
            return None
        rule = "probe-path" if kind == "probe" else "unknown-route"
        if ctx.service is None and kind == "unknown":
            rule = "no-service"
        return Stop(4, 404, "blocked", rule, category="probe", body="Not Found")
