"""`chakravyuha`: start the Guard and its dashboard."""

import argparse
import asyncio
import contextlib
import os
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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="chakravyuha", description=__doc__)
    parser.add_argument("--config", type=Path, default=config.DEFAULT_CONFIG)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--dashboard-port", type=int, default=8090)
    parser.add_argument("--no-dashboard", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    settings = config.load(args.config)
    demo = os.environ.get("CHAKRA_DEMO") == "1"
    if demo:
        print("chakravyuha: DEMO MODE, X-Hedwig-Test-IP is trusted. Never use with real users.")
    if not settings.services:
        print(f"chakravyuha: no services in {args.config}; every request will get 404.")
    for name, service in settings.services.items():
        has_key = bool(service.api_key_env and os.environ.get(service.api_key_env))
        if not service.challenge and not has_key:
            print(f"chakravyuha: {name} has challenge: false and no API key set; ring 3 is open.")
    app = create_app(settings, token=os.environ.get("CHAKRA_TOKEN"), demo=demo)
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
