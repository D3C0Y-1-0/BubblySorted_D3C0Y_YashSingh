"""down and up: stop and start one service of the local Docker Compose bank."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from hedwig.core import actions, deploy, engine

console = Console()

Service = Annotated[str, typer.Argument(help="Service (folder) to act on.")]


def _known(root: Path, service: str) -> None:
    names = [spec.name for spec in engine.resolve_services(root, "medium")]
    if service not in names:
        console.print(f"[red]No service '{service}' here.[/red] Services: {', '.join(names)}")
        raise typer.Exit(1)


def down(service: Service) -> None:
    """Take a service down with `docker compose stop` (container kept, so `up` is instant)."""
    root = Path.cwd()
    _known(root, service)
    note = actions.takedown(root, service, "taken down with hedwig down")
    console.print(f"[bold]{service}[/bold] down ({note})")


def up(service: Service) -> None:
    """Bring a service back up: `docker compose start`."""
    root = Path.cwd()
    _known(root, service)
    note = actions.resume(root, service)
    ok, detail = (
        deploy.smoke(root, service, _health(root, service))
        if note.startswith("started")
        else (False, note)
    )
    mark = "[green]up[/green]" if ok else "[yellow]started, not confirmed[/yellow]"
    console.print(f"[bold]{service}[/bold] {mark} ({detail})")


def _health(root: Path, service: str) -> str:
    specs = {spec.name: spec for spec in engine.resolve_services(root, "medium")}
    return specs[service].health_path


def run_in_app(name: str, args: list[str], root: Path) -> None:
    if len(args) != 1 or args[0].startswith("--"):
        console.print(f"Usage: /{name} <service>")
        return
    try:
        (down if name == "down" else up)(args[0])
    except typer.Exit:
        pass


def register(app: typer.Typer) -> None:
    app.command("down")(down)
    app.command("up")(up)
