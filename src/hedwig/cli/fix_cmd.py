"""fix, report and dash: act on findings, tell the PM, and watch it all."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from hedwig import settings
from hedwig.cli import scan_cmd
from hedwig.core import bump, engine, report
from hedwig.core.advisories import AdvisorySource
from hedwig.core.agents import orchestrator
from hedwig.core.models import Decision, Finding, Run, ScanResult, Step

console = Console()

Offline = scan_cmd.Offline
Advisories = scan_cmd.Advisories
Tier = scan_cmd.Tier
AsJson = scan_cmd.AsJson

STATUS_MARK = {
    "ok": "[green]ok[/green]",
    "failed": "[red]failed[/red]",
    "skipped": "[yellow]skip[/yellow]",
}


def _print_step(run: Run, step: Step) -> None:
    if step.status == "running":
        console.print(f"  [dim]… {step.name} {step.detail}[/dim]")
    else:
        mark = STATUS_MARK.get(step.status, step.status)
        console.print(f"  {mark} {step.name}  {step.detail}")


def _groups(result: ScanResult, service: str, package: str | None) -> list[list[Finding]]:
    """The service's findings grouped by package version, the riskiest package first."""
    grouped: dict[tuple[str, str, str], list[Finding]] = {}
    for f in result.findings:  # already sorted by risk
        if f.service == service and (package is None or f.package == package):
            grouped.setdefault((f.ecosystem, f.package, f.version), []).append(f)
    return list(grouped.values())


def _lead(group: list[Finding]) -> Finding:
    return max(group, key=lambda f: (f.evidence_level, f.risk))


def fix(
    service: Annotated[str, typer.Argument(help="Service (folder) to fix.")],
    package: Annotated[str | None, typer.Option("--package", help="Only this package.")] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the plan and decision. Change nothing.")
    ] = False,
    offline: Offline = False,
    advisories: Advisories = None,
    tier: Tier = "medium",
    json_output: AsJson = False,
) -> None:
    """Fix every vulnerable package of a service: bump, adapt, verify, then act as policy says."""
    root = Path.cwd()
    specs = {spec.name: spec for spec in engine.resolve_services(root, tier)}
    if service not in specs:
        raise scan_cmd._fail(
            f"No service '{service}' here. Services: {', '.join(specs) or 'none'}.", 1
        )
    result = scan_cmd._scan(".", offline, advisories, tier)
    groups = _groups(result, service, package)
    if not groups:
        console.print(f"Nothing to fix in {service}.")
        return
    if dry_run:
        _print_plan(specs[service], groups, json_output)
        return
    if any(_lead(g).decision.action == "fix" for g in groups) and not settings.get("groq_api_key"):
        raise scan_cmd._fail("groq_api_key is not set. Run: hedwig config", 1)
    source = AdvisorySource(offline=offline, directory=advisories)
    runs: list[Run] = []
    for group in groups:
        top = group[0]
        console.print(
            f"\n[bold]{service}[/bold] {top.package} {top.version} → {top.package_fix or 'no fix'}"
        )
        try:
            runs.append(
                orchestrator.run_fix(root, group, specs[service], source, on_step=_print_step)
            )
        except Exception as err:  # one package failing must not stop the others
            console.print(f"[red]{type(err).__name__}: {err}[/red]")
    if json_output:
        scan_cmd._print_json(json.dumps([r.model_dump() for r in runs], indent=2))
        return
    table = Table(title=f"Hedwig fix: {service}")
    for column in ("package", "from → to", "state", "outcome", "run"):
        table.add_column(column, overflow="fold")
    for r in runs:
        style = {"verified": "green", "failed": "red"}.get(r.state, "yellow")
        table.add_row(
            r.package,
            f"{r.from_version} → {r.to_version or '-'}",
            f"[{style}]{r.state}[/{style}]",
            r.action,
            r.run_id,
        )
    console.print(table)


def _print_plan(spec: engine.ServiceSpec, groups: list[list[Finding]], json_output: bool) -> None:
    plan = []
    for group in groups:
        top, lead = group[0], _lead(group)
        plan.append(
            {
                "package": top.package,
                "from": top.version,
                "to": top.package_fix,
                "direct": bump.declared(spec.folder, top) is not None,
                "advisories": [f.id for f in group],
                "decision": lead.decision.model_dump(),
            }
        )
    if json_output:
        scan_cmd._print_json(json.dumps(plan, indent=2))
        return
    table = Table(title=f"Hedwig fix plan (dry run): {spec.name}")
    for column in ("package", "from → to", "advisories", "decision"):
        table.add_column(column, overflow="fold")
    for item in plan:
        table.add_row(
            item["package"],
            f"{item['from']} → {item['to'] or 'no fix'}"
            + ("" if item["direct"] else " (transitive)"),
            str(len(item["advisories"])),
            scan_cmd._decision_label(_decision(item)),
        )
    console.print(table)
    console.print("Dry run: no model call, no git, no Docker, nothing changed.")


def _decision(item: dict):
    return Decision(**item["decision"])


def report_cmd(
    target: Annotated[str, typer.Argument(help="A service name or a fix run id.")],
    email: Annotated[bool, typer.Option("--email", help="Email the PDF to the PM.")] = False,
    offline: Offline = False,
    advisories: Advisories = None,
    tier: Tier = "medium",
) -> None:
    """Write the PDF report for the project manager (needs tectonic; --email also needs SMTP)."""
    root = Path.cwd()
    result = engine.load_last(root) or scan_cmd._scan(".", offline, advisories, tier)
    try:
        data = report.build(root, target, result)
        pdf = report.compile_pdf(root, data)
        console.print(f"Report written to [bold]{pdf}[/bold]")
        if email:
            to = report.email_pdf(pdf, f"Hedwig report: {data.name}", f"Hedwig report: {data.name}")
            console.print(f"Emailed to [bold]{to}[/bold]")
    except report.ReportError as err:
        raise scan_cmd._fail(str(err), 1) from err


def dash(offline: Offline = False, advisories: Advisories = None, tier: Tier = "medium") -> None:
    """Open the terminal dashboard: services, alerts, fix runs. Press ? inside for the keys."""
    from hedwig.cli.dashboard import DashApp

    DashApp(Path.cwd(), AdvisorySource(offline=offline, directory=advisories), tier).run()


APP_USAGE = {
    "fix": "/fix <service> [--package NAME] [--dry-run] [--offline] [--advisories DIR] [--json]",
    "report": "/report <service|run-id> [--email]",
    "dash": "/dash [--offline] [--advisories DIR]",
}
_FLAGS = {
    "--dry-run": "dry_run",
    "--offline": "offline",
    "--json": "json_output",
    "--email": "email",
}
_VALUES = {"--package": "package", "--advisories": "advisories", "--tier": "tier"}
_ALLOWED = {
    "fix": {"package", "dry_run", "offline", "advisories", "tier", "json_output"},
    "report": {"email", "offline", "advisories", "tier"},
    "dash": {"offline", "advisories", "tier"},
}
_POSITIONALS = {"fix": 1, "report": 1, "dash": 0}


def run_in_app(name: str, args: list[str], root: Path) -> None:
    """Run one of these commands from a slash command typed in the Hedwig app."""
    positional: list[str] = []
    options: dict = {}
    items = iter(args)
    for item in items:
        if item in _FLAGS:
            options[_FLAGS[item]] = True
        elif item in _VALUES:
            value = next(items, None)
            if value is None:
                console.print(f"[red]{item} needs a value[/red]\nUsage: {APP_USAGE[name]}")
                return
            options[_VALUES[item]] = Path(value) if item == "--advisories" else value
        elif item.startswith("--"):
            console.print(f"[red]unknown option {item}[/red]\nUsage: {APP_USAGE[name]}")
            return
        else:
            positional.append(item)
    if set(options) - _ALLOWED[name] or len(positional) != _POSITIONALS[name]:
        console.print(f"Usage: {APP_USAGE[name]}")
        return
    try:
        if name == "fix":
            fix(positional[0], **options)
        elif name == "report":
            report_cmd(positional[0], **options)
        else:
            dash(**options)
    except typer.Exit:
        pass  # the command already printed its error


def register(app: typer.Typer) -> None:
    app.command("fix")(fix)
    app.command("report")(report_cmd)
    app.command("dash")(dash)
