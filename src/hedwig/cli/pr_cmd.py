"""pr-check: what does a pull request introduce? Used by the GitHub workflow and by hand."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from hedwig.cli import scan_cmd
from hedwig.core import prcheck
from hedwig.core.advisories import AdvisorySource, AdvisoryUnavailable

console = Console()


def _default_base(repo: Path) -> str:
    for ref in ("origin/HEAD", "origin/main", "origin/master"):
        try:
            prcheck.rev(repo, ref)
            return ref
        except RuntimeError:
            continue
    raise scan_cmd._fail("Cannot find the base branch. Pass --base.", 2)


def pr_check(
    base: Annotated[
        str | None, typer.Option("--base", help="Base ref (default: origin/HEAD).")
    ] = None,
    head: Annotated[str, typer.Option("--head", help="Head ref (default: HEAD).")] = "HEAD",
    root: Annotated[
        list[str] | None,
        typer.Option("--root", help="Folder with a .hedwig.yml, from the repo root. Default: all."),
    ] = None,
    fail_on: Annotated[
        str, typer.Option("--fail-on", help="Exit 1 at or above: low, medium, high, critical.")
    ] = "high",
    pr: Annotated[str, typer.Option("--pr", help="Label for the comment, e.g. 'PR #4'.")] = "",
    comment_file: Annotated[
        Path | None, typer.Option("--comment-file", help="Write the markdown comment here.")
    ] = None,
    offline: scan_cmd.Offline = False,
    advisories: scan_cmd.Advisories = None,
    json_output: scan_cmd.AsJson = False,
) -> None:
    """List the vulnerabilities a change introduces (in head, not in base). Exit 1 if any is bad."""
    if fail_on not in prcheck.SEVERITY_ORDER:
        raise scan_cmd._fail(f"--fail-on must be one of {', '.join(prcheck.SEVERITY_ORDER)}", 2)
    try:
        repo = prcheck.toplevel(Path.cwd())
        base_ref = base or _default_base(repo)
        head_sha = prcheck.rev(repo, head)
        base_sha = prcheck.merge_base(repo, prcheck.rev(repo, base_ref), head_sha)
        roots = root or prcheck.hedwig_roots(repo, head_sha) or ["."]
        found = prcheck.introduced(
            repo, base_sha, head_sha, AdvisorySource(offline=offline, directory=advisories), roots
        )
    except (RuntimeError, AdvisoryUnavailable) as err:
        raise scan_cmd._fail(str(err), 2) from err
    comment = prcheck.render_comment(found, pr, base_sha, head_sha)
    if comment_file:
        comment_file.write_text(comment, encoding="utf-8")
    if json_output:
        typer.echo(json.dumps([f.model_dump() for f in found], indent=2))
    else:
        console.print(
            f"[bold]{len(found)}[/bold] vulnerabilities introduced by {head} over {base_ref}"
        )
        for f in found[:10]:
            console.print(f"  {f.severity:<8} {f.service}  {f.package}@{f.version}  {f.id}")
    if prcheck.at_least(found, fail_on):
        raise typer.Exit(1)


def register(app: typer.Typer) -> None:
    app.command("pr-check")(pr_check)
