"""watch: contain pull requests that were merged and introduced vulnerable packages."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from hedwig.cli import scan_cmd
from hedwig.core import github, prcheck, watcher
from hedwig.core.advisories import AdvisorySource

console = Console()


def watch(
    repo: Annotated[
        str | None, typer.Option("--repo", help="owner/name (default: from origin).")
    ] = None,
    branch: Annotated[
        str | None,
        typer.Option(
            "--branch",
            help="Watch this branch of origin for any new commit that introduces vulnerable "
            "packages (a merged PR or a plain push), instead of watching merged PRs.",
        ),
    ] = None,
    interval: Annotated[int, typer.Option("--interval", help="Seconds between checks.")] = 20,
    once: Annotated[bool, typer.Option("--once", help="Check once and exit.")] = False,
    since: Annotated[
        int,
        typer.Option(
            "--since", help="On the first run, also act on PRs merged this many minutes ago."
        ),
    ] = 0,
    min_severity: Annotated[
        str,
        typer.Option("--min-severity", help="Ignore findings below: low, medium, high, critical."),
    ] = "low",
    no_email: Annotated[bool, typer.Option("--no-email", help="Do not email the PM.")] = False,
    offline: scan_cmd.Offline = False,
    advisories: scan_cmd.Advisories = None,
) -> None:
    """Watch GitHub for merged PRs that introduce vulnerable packages, and contain each one."""
    if min_severity not in prcheck.SEVERITY_ORDER:
        raise scan_cmd._fail(
            f"--min-severity must be one of {', '.join(prcheck.SEVERITY_ORDER)}", 2
        )
    console.print("[bold]hedwig watch[/bold]  Ctrl-C to stop")
    source = AdvisorySource(offline=offline, directory=advisories)
    try:
        if branch:
            watcher.watch_branch(
                Path.cwd(), source, lambda text: console.print(text), branch, interval, once,
                min_severity, not no_email,
            )  # fmt: skip
            return
        watcher.watch(
            Path.cwd(),
            source,
            say=lambda text: console.print(text),
            interval=interval,
            once=once,
            since_minutes=since,
            min_severity=min_severity,
            email=not no_email,
            slug=repo,
        )
    except (github.GitHubError, RuntimeError) as err:
        raise scan_cmd._fail(str(err), 1) from err
    except KeyboardInterrupt:
        console.print("\nstopped")


def register(app: typer.Typer) -> None:
    app.command("watch")(watch)
