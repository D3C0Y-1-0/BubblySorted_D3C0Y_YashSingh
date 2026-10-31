"""Hedwig command line interface."""

import shutil
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from hedwig import __version__, settings
from hedwig.ui.mascot import banner

console = Console()

app = typer.Typer(
    help="Hedwig: developer-native cyber threat early warning.",
    no_args_is_help=False,
    add_completion=False,
)
config_app = typer.Typer(
    help="Store API keys in ~/.hedwig/config.toml.",
    invoke_without_command=True,
)
app.add_typer(config_app, name="config")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"hedwig {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    if ctx.invoked_subcommand is None:
        console.print(banner())
        console.print()
        typer.echo(ctx.get_help())


@config_app.callback()
def config_root(ctx: typer.Context) -> None:
    """Prompt for each key. Press Enter to keep the current value."""
    if ctx.invoked_subcommand is not None:
        return
    console.print(banner())
    console.print(f"\nSaving to [bold]{settings.CONFIG_PATH}[/bold]\n")
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
    console.print("\n[green]Saved.[/green] Run [bold]hedwig doctor[/bold] to check your setup.")


@config_app.command("set")
def config_set(name: str, value: str) -> None:
    """Set one key, e.g. hedwig config set groq_api_key gsk_..."""
    if name not in settings.KEYS:
        console.print(f"[red]Unknown key '{name}'.[/red] Valid: {', '.join(settings.KEYS)}")
        raise typer.Exit(1)
    settings.save(name, value)
    console.print(f"Set [bold]{name}[/bold].")


@config_app.command("show")
def config_show() -> None:
    """Show every key (secrets masked) and where its value comes from."""
    table = Table(title=str(settings.CONFIG_PATH))
    table.add_column("key")
    table.add_column("value")
    table.add_column("source")
    for name, (value, source) in settings.load_with_source().items():
        shown = settings.mask(value) if settings.KEYS[name].secret else value
        table.add_row(name, shown, source)
    console.print(table)


TOOLS = {
    "git": "clone and branch fixes",
    "docker": "differential replay (old vs new build)",
    "npm": "Node services",
    "cargo": "Rust services",
    "composer": "PHP services",
    "mvn": "Java services",
    "tectonic": "PDF reports (LaTeX)",
}


@app.command()
def doctor() -> None:
    """Check which supporting tools are installed and whether keys are configured."""
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
