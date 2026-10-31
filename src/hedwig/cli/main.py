"""Hedwig command line interface."""

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from hedwig import __version__
from hedwig.cli import commands, deploy_cmd, fix_cmd, pr_cmd, scan_cmd, watch_cmd
from hedwig.ui.mascot import banner

console = Console()

app = typer.Typer(
    help="Developer-native cyber threat early warning. Run with no command to open the app.",
    no_args_is_help=False,
    add_completion=False,
)
config_app = typer.Typer(
    help="Store API keys in ~/.hedwig/config.toml.",
    invoke_without_command=True,
)
app.add_typer(config_app, name="config")
scan_cmd.register(app)
fix_cmd.register(app)
deploy_cmd.register(app)
pr_cmd.register(app)
watch_cmd.register(app)


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
    if ctx.invoked_subcommand is not None:
        return
    if sys.stdin.isatty() and sys.stdout.isatty():
        from hedwig.cli import shell

        shell.run()
        return
    console.print(banner())
    console.print()
    typer.echo(ctx.get_help())


@config_app.callback()
def config_root(ctx: typer.Context) -> None:
    """Prompt for each key. Press Enter to keep the current value."""
    if ctx.invoked_subcommand is not None:
        return
    console.print(banner())
    console.print()
    commands.config_wizard()


@config_app.command("set")
def config_set(name: str, value: str) -> None:
    """Set one key, e.g. hedwig config set groq_api_key gsk_..."""
    if not commands.config_set(name, value):
        raise typer.Exit(1)


@config_app.command("show")
def config_show() -> None:
    """Show every key (secrets masked) and where its value comes from."""
    commands.config_show()


@app.command()
def doctor() -> None:
    """Check which supporting tools are installed and whether keys are configured."""
    commands.doctor()


@app.command()
def init() -> None:
    """Create .hedwig.yml for the current folder. Each subfolder with a manifest is a service."""
    if not commands.init_here(Path.cwd()):
        raise typer.Exit(1)
