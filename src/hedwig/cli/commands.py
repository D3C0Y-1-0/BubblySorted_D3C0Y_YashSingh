"""Command implementations shared by the Typer CLI and the interactive app."""

import shutil
from pathlib import Path

from rich.console import Console
from rich.table import Table

from hedwig import config, settings

console = Console()

TOOLS = {
    "git": "clone and branch fixes",
    "docker": "differential replay (old vs new build)",
    "npm": "Node services",
    "cargo": "Rust services",
    "composer": "PHP services",
    "mvn": "Java services",
    "tectonic": "PDF reports (LaTeX)",
}


def config_wizard() -> None:
    """Prompt for each key. Press Enter to keep the current value."""
    import typer

    console.print(f"Saving to [bold]{settings.CONFIG_PATH}[/bold]\n")
    current = settings.load()
    for name, key in settings.KEYS.items():
        shown = settings.mask(current[name]) if key.secret else current[name]
        answer = typer.prompt(
            f"{name} ({key.description})",
            default=shown,
            show_default=bool(shown),
            hide_input=key.secret,
        )
        if answer and answer != shown:
            settings.save(name, answer)
    console.print("\n[green]Saved.[/green] Run [bold]doctor[/bold] to check your setup.")


def config_set(name: str, value: str) -> bool:
    if name not in settings.KEYS:
        console.print(f"[red]Unknown key '{name}'.[/red] Valid: {', '.join(settings.KEYS)}")
        return False
    settings.save(name, value)
    console.print(f"Set [bold]{name}[/bold].")
    return True


def config_show() -> None:
    table = Table(title=str(settings.CONFIG_PATH))
    table.add_column("key")
    table.add_column("value")
    table.add_column("source")
    for name, (value, source) in settings.load_with_source().items():
        shown = settings.mask(value) if settings.KEYS[name].secret else value
        table.add_row(name, shown, source)
    console.print(table)


def doctor() -> None:
    table = Table(title="hedwig doctor")
    table.add_column("tool")
    table.add_column("status")
    table.add_column("enables")
    for tool, purpose in TOOLS.items():
        found = shutil.which(tool)
        status = f"[green]{found}[/green]" if found else "[yellow]missing[/yellow]"
        table.add_row(tool, status, purpose)
    console.print(table)
    if not settings.get("groq_api_key"):
        console.print("[yellow]groq_api_key is not set.[/yellow] Run: hedwig config")


def init_here(root: Path) -> bool:
    """Set up .hedwig.yml for root. Returns False if no services were found."""
    path, added, kept = config.init_project(root)
    if not added and not kept:
        path.unlink(missing_ok=True)
        console.print(
            f"[yellow]No services found in {root}.[/yellow]\n"
            "Hedwig expects each service in its own folder with a manifest "
            f"({', '.join(config.MANIFESTS)}).\n"
            "cd to the folder that contains your service folders and run init again."
        )
        return False
    table = Table(title=str(path))
    table.add_column("service")
    table.add_column("status")
    for name in added:
        table.add_row(name, "[green]added[/green]")
    for name in kept:
        table.add_row(name, "kept")
    console.print(table)
    console.print("Edit [bold]tier[/bold] and [bold]allow[/bold] in the file to set policy.")
    return True
