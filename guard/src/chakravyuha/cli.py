"""`chakravyuha`: start the Guard and its dashboard."""

import argparse
import asyncio
import contextlib
import os
import sys
from pathlib import Path

import uvicorn

from . import __version__, config
from .dashboard import create_dashboard
from .proxy import create_app


async def serve(servers: list[uvicorn.Server]) -> None:
    # Each server catches Ctrl-C on its own; when one stops, stop the others too.
    tasks = [asyncio.create_task(server.serve()) for server in servers]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for server in servers:
        server.should_exit = True
    await asyncio.gather(*tasks, return_exceptions=True)


def load_env(path: Path) -> None:
    """KEY=VALUE lines from guard/.env; variables already set in the environment win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key and not key.startswith("#"):
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["illusion"]:  # the Illusionist builds the decoy content before the demo
        from . import illusionist

        load_env(config.GUARD_ROOT / ".env")
        raise SystemExit(illusionist.main(argv[1:]))
    parser = argparse.ArgumentParser(prog="chakravyuha", description=__doc__)
    parser.add_argument("--config", type=Path, default=config.DEFAULT_CONFIG)
    parser.add_argument("--host", default="127.0.0.1")  # one machine: loopback only
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--dashboard-port", type=int, default=8090)
    parser.add_argument("--no-dashboard", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    settings = config.load(args.config)
    load_env(config.GUARD_ROOT / ".env")
    elk = settings.elk
    elk.logstash = os.environ.get("CHAKRA_LOGSTASH", elk.logstash)
    elk.elastic_url = os.environ.get("CHAKRA_ELASTIC_URL", elk.elastic_url)
    elk.kibana_url = os.environ.get("CHAKRA_KIBANA_URL", elk.kibana_url)
    if os.environ.get("CHAKRA_ELK") == "0":
        elk.enabled = False
    if not settings.services:
        print(f"chakravyuha: no services in {args.config}; every request will get 404.")
    for name, service in settings.services.items():
        has_key = bool(service.api_key_env and os.environ.get(service.api_key_env))
        if not service.challenge and not has_key:
            print(f"chakravyuha: {name} has challenge: false and no API key set; ring 3 is open.")
        if not service.routes:
            print(f"chakravyuha: {name} lists no routes; ring 4 is open for it.")
    app = create_app(settings, token=os.environ.get("CHAKRA_TOKEN"))
    quiet = {"log_level": "warning", "access_log": False}
    servers = [uvicorn.Server(uvicorn.Config(app, host=args.host, port=args.port, **quiet))]
    print(f"chakravyuha: guard on http://{args.host}:{args.port}")
    if not args.no_dashboard:
        # the dashboard is for the laptop screen only, so it never listens beyond loopback
        dashboard = create_dashboard(app.state.guard)
        servers.append(
            uvicorn.Server(
                uvicorn.Config(dashboard, host="127.0.0.1", port=args.dashboard_port, **quiet)
            )
        )
        print(f"chakravyuha: dashboard on http://127.0.0.1:{args.dashboard_port}")
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve(servers))


if __name__ == "__main__":
    main()
