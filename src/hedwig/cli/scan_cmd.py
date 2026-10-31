"""scan, status and explain: the engine's commands, with --json on each."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from hedwig.core import engine, evidence, inventory
from hedwig.core.advisories import AdvisorySource, AdvisoryUnavailable
from hedwig.core.models import Decision, Finding, ScanResult

console = Console()

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "dim",
}
SEVERITIES = list(SEVERITY_STYLE)
TABLE_ROWS = 40
REASON_ROWS = 5

Offline = Annotated[bool, typer.Option("--offline", help="Use local advisory data only.")]
Advisories = Annotated[
    Path | None,
    typer.Option("--advisories", help="Advisory folder (osv/vulns, kev.json, epss.json)."),
]
Tier = Annotated[str, typer.Option("--tier", help="Tier when there is no .hedwig.yml.")]
AsJson = Annotated[bool, typer.Option("--json", help="Print JSON.")]


def _fail(message: str, code: int = 2) -> typer.Exit:
    console.print(f"[red]{message}[/red]")
    return typer.Exit(code)


def _scan(target: str, offline: bool, advisories: Path | None, tier: str) -> ScanResult:
    source = AdvisorySource(offline=offline, directory=advisories)
    try:
        return engine.scan_target(target, source, tier)
    except (AdvisoryUnavailable, RuntimeError) as err:
        raise _fail(str(err)) from err


def _print_json(model) -> None:
    typer.echo(model if isinstance(model, str) else model.model_dump_json(indent=2))


def _counts(findings: list[Finding]) -> dict[str, int]:
    return {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}


def _fix_label(finding: Finding) -> str:
    if not finding.package_fix:
        return "[red]none[/red]"
    return finding.package_fix + (" [yellow](major)[/yellow]" if finding.needs_major else "")


@dataclass
class _Row:
    """Every finding on one package version, across services. `top` has the highest risk."""

    top: Finding
    services: list[str] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)
    kev: bool = False
    evidence: int = 0

    @property
    def advisories(self) -> str:
        more = len(self.ids) - 1
        return self.top.id + (f" [dim]+{more} more[/dim]" if more else "")


def _rows(findings: list[Finding]) -> list[_Row]:
    """One table row per package version, so a package with 30 advisories is one line.

    Findings stay per service and per advisory in --json, status and explain; only the
    table is grouped. Findings arrive sorted by risk, so each row's first one is its top.
    """
    rows: dict[tuple[str, str, str], _Row] = {}
    for f in findings:
        row = rows.setdefault((f.ecosystem, f.package, f.version), _Row(top=f))
        if f.service not in row.services:
            row.services.append(f.service)
        if f.id not in row.ids:
            row.ids.append(f.id)
        row.kev = row.kev or f.kev
        row.evidence = max(row.evidence, f.evidence_level)
    return list(rows.values())


def _kev_label(row: _Row, result: ScanResult) -> str:
    if row.kev:
        return "[bold red]yes[/bold red]"
    return "no" if result.kev_available else "[yellow]?[/yellow]"


def _render_scan(result: ScanResult) -> None:
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    findings = result.findings
    rows = _rows(findings)
    if findings:
        table = Table(title=f"Hedwig scan: {result.root}")
        for column in (
            "severity", "risk", "service", "package", "advisory", "fix to", "KEV", "ev", "next"
        ):  # fmt: skip
            table.add_column(column, overflow="fold")
        for row in rows[:TABLE_ROWS]:
            f = row.top
            style = SEVERITY_STYLE[f.severity]
            table.add_row(
                f"[{style}]{f.severity}[/{style}]",
                f"{f.risk:.2f}",
                ", ".join(row.services),
                f"{f.package}@{f.version}",
                row.advisories,
                _fix_label(f),
                _kev_label(row, result),
                str(row.evidence),
                f.decision.action,
            )
        console.print(table)
        if len(rows) > TABLE_ROWS:
            console.print(f"... and {len(rows) - TABLE_ROWS} more (use --json for all)")
        if not result.kev_available:
            console.print("[yellow]?[/yellow] = CISA KEV catalog unavailable, so not checked")
        console.print("\n[bold]Why the top findings rank where they do[/bold]")
        for row in rows[:REASON_ROWS]:
            f = row.top
            console.print(
                f"  [bold]{f.id}[/bold] {f.package}@{f.version} ({', '.join(row.services)}): "
                f"{f.reasoning}"
            )
    counts = ", ".join(f"{n} {s}" for s, n in _counts(findings).items() if n)
    console.print(
        f"\n[bold]{result.raw_advisories} raw advisories → {len(findings)} findings[/bold] "
        f"across {len(result.services)} services ({result.packages} packages scanned)"
        + (f": {counts}" if counts else "")
    )
    if len(rows) < len(findings):
        console.print(
            f"[dim]One row per package ({len(rows)} rows). "
            "Run explain <id> or add --json to see every advisory.[/dim]"
        )


def scan(
    target: Annotated[str, typer.Argument(help="Folder or git URL (default: here).")] = ".",
    offline: Offline = False,
    advisories: Advisories = None,
    tier: Tier = "medium",
    json_output: AsJson = False,
) -> None:
    """Find known vulnerabilities in a folder of services or a git repository, ranked by risk."""
    result = _scan(target, offline, advisories, tier)
    if json_output:
        _print_json(result)
    else:
        _render_scan(result)


def status(
    offline: Offline = False,
    advisories: Advisories = None,
    tier: Tier = "medium",
    json_output: AsJson = False,
) -> None:
    """One row per service in this folder: tier, findings by severity, top risk."""
    result = _scan(".", offline, advisories, tier)
    rows = []
    for service in result.services:
        findings = [f for f in result.findings if f.service == service.name]
        rows.append(
            {
                "service": service.name,
                "tier": service.tier,
                "packages": service.packages,
                "findings": _counts(findings),
                "top_risk": max((f.risk for f in findings), default=0.0),
                "max_evidence": max((f.evidence_level for f in findings), default=0),
            }
        )
    if json_output:
        _print_json(json.dumps(rows, indent=2))
        return
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    table = Table(title=f"Hedwig status: {result.root}")
    short = {"critical": "crit", "medium": "med"}
    for column in ("service", "tier", "pkgs", *(short.get(x, x) for x in SEVERITIES), "risk", "ev"):
        table.add_column(column, overflow="fold")
    for row in rows:
        counts = row["findings"]
        table.add_row(
            row["service"],
            row["tier"],
            str(row["packages"]),
            *(str(counts[s]) if counts[s] else "-" for s in SEVERITIES),
            f"{row['top_risk']:.2f}",
            str(row["max_evidence"]),
        )
    console.print(table)


EVIDENCE_TEXT = {
    0: "vulnerable version present",
    1: "the vulnerable code is called",
    2: "exploited in the wild (CISA KEV)",
    3: "attack attempts seen in the service logs",
    4: "signs of compromise in the service logs",
}


def _decision_label(decision: Decision) -> str:
    if decision.action != "fix":
        return decision.action
    return f"fix (if verified: {decision.on_verified}; if not: {decision.on_failed})"


def _action(f: Finding) -> str:
    if not f.package_fix:
        return "No fixed version exists. Isolate the service or remove the dependency."
    note = " This is a major version bump, so the code may need changes." if f.needs_major else ""
    return f"Bump {f.package} from {f.version} to {f.package_fix}.{note}"


def explain(
    advisory_id: Annotated[str, typer.Argument(metavar="ID", help="A CVE or advisory id.")],
    offline: Offline = False,
    advisories: Advisories = None,
    tier: Tier = "medium",
    json_output: AsJson = False,
) -> None:
    """Plain-language reasoning, evidence and recommended action for one finding."""
    wanted = advisory_id.upper()

    def matching(result: ScanResult | None) -> list[Finding]:
        return [f for f in (result.findings if result else []) if wanted in map(str.upper, f.ids)]

    found = matching(engine.load_last(Path.cwd()))
    if not found:
        found = matching(_scan(".", offline, advisories, tier))
    if not found:
        raise _fail(f"{advisory_id} is not a finding in this folder.", 1)
    if json_output:
        _print_json(json.dumps([f.model_dump() for f in found], indent=2))
        return
    for f in found:
        style = SEVERITY_STYLE[f.severity]
        console.print(
            f"\n[bold]{f.id}[/bold] [{style}]{f.severity}[/{style}] (risk {f.risk:.2f})  "
            f"{f.package}@{f.version} in [bold]{f.service}[/bold] ({f.tier} tier)"
        )
        console.print(f"  also known as: {', '.join(i for i in f.ids if i != f.id)}")
        console.print(f"  {f.summary}")
        console.print(f"  [bold]Why:[/bold] {f.reasoning}")
        table = Table(show_header=True, box=None, padding=(0, 2))
        for column in ("exploitability", "impact", "criticality", "confidence"):
            table.add_column(column)
        factors = f.factors
        table.add_row(
            f"{factors.exploitability:.2f}",
            f"{factors.impact:.2f}",
            f"{factors.criticality:.2f}",
            f"{factors.confidence:.2f}",
        )
        console.print(table)
        console.print(f"  Evidence level {f.evidence_level}: {EVIDENCE_TEXT[f.evidence_level]}")
        console.print(f"  Reachability: {f.reachability}")
        for site in f.call_sites:
            console.print(f"    {site.symbol} in {site.function}() at {site.file}:{site.line}")
        for attack in f.attacks:
            console.print(f"  [red]Attack in logs:[/red] {attack}")
        if f.compromise:
            console.print("  [bold red]Signs of compromise in the service logs[/bold red]")
        console.print(f"  [bold]Fix:[/bold] {_action(f)}")
        decision = f.decision
        console.print(f"  [bold]Decision:[/bold] {_decision_label(decision)}: {decision.reason}")


PATTERN_HELP = "Attack to write: " + ", ".join(rule.id for rule in evidence.RULES)


def simulate_attack(
    service: Annotated[str, typer.Argument(help="Service (folder) to attack.")],
    compromise: Annotated[
        bool, typer.Option("--compromise", help="Also write a sign of compromise.")
    ] = False,
    pattern: Annotated[str | None, typer.Option("--pattern", help=PATTERN_HELP)] = None,
) -> None:
    """Write an attack request (and with --compromise, a compromise marker) to a service's log."""
    specs = {spec.name: spec for spec in engine.resolve_services(Path.cwd(), "medium")}
    if service not in specs:
        raise _fail(f"No service '{service}' here. Services: {', '.join(specs) or 'none'}.", 1)
    if pattern and pattern not in {r.id for r in evidence.RULES}:
        raise _fail(f"Unknown pattern '{pattern}'.", 1)
    spec = specs[service]
    packages, _ = inventory.parse_service(spec.folder, service)
    rule = evidence.pick_rule([p.name for p in packages], pattern)
    lines = evidence.write_attack(spec.log_path, rule, compromise)
    console.print(f"Wrote {len(lines)} line(s) to [bold]{spec.log_path}[/bold] ({rule.label}):")
    for line in lines:
        console.print(f"  {line}")
    console.print("Run [bold]scan[/bold] to see the evidence level rise.")


APP_USAGE = {
    "scan": "/scan [path|git-url] [--offline] [--advisories DIR] [--tier TIER] [--json]",
    "status": "/status [--offline] [--advisories DIR] [--tier TIER] [--json]",
    "explain": "/explain <id> [--offline] [--advisories DIR] [--tier TIER] [--json]",
    "simulate-attack": "/simulate-attack <service> [--compromise] [--pattern ID]",
}
_APP_FLAGS = {
    "--offline": "offline",
    "--json": "json_output",
    "--compromise": "compromise",
}
_APP_OPTIONS = {"--advisories": "advisories", "--tier": "tier", "--pattern": "pattern"}
_ALLOWED = {
    "scan": {"offline", "advisories", "tier", "json_output"},
    "status": {"offline", "advisories", "tier", "json_output"},
    "explain": {"offline", "advisories", "tier", "json_output"},
    "simulate-attack": {"compromise", "pattern"},
}
_POSITIONALS = {"scan": (0, 1), "status": (0, 0), "explain": (1, 1)}
_POSITIONALS["simulate-attack"] = (1, 1)


def _parse_app_args(args: list[str]) -> tuple[list[str], dict] | str:
    """Split slash-command arguments into positionals and keyword options, or an error."""
    positional: list[str] = []
    options: dict = {}
    items = iter(args)
    for item in items:
        if item in _APP_FLAGS:
            options[_APP_FLAGS[item]] = True
        elif item in _APP_OPTIONS:
            value = next(items, None)
            if value is None:
                return f"{item} needs a value"
            options[_APP_OPTIONS[item]] = Path(value) if item == "--advisories" else value
        elif item.startswith("--"):
            return f"unknown option {item}"
        else:
            positional.append(item)
    return positional, options


def run_in_app(name: str, args: list[str], root: Path) -> None:
    """Run one of the engine's commands from a slash command typed in the Hedwig app."""
    parsed = _parse_app_args(args)
    if isinstance(parsed, str):
        console.print(f"[red]{parsed}[/red]\nUsage: {APP_USAGE[name]}")
        return
    positional, options = parsed
    unsupported = set(options) - _ALLOWED[name]
    low, high = _POSITIONALS[name]
    if unsupported or not low <= len(positional) <= high:
        flags = {value: flag for flag, value in {**_APP_FLAGS, **_APP_OPTIONS}.items()}
        if unsupported:
            console.print(f"[red]unknown option {flags[sorted(unsupported)[0]]}[/red]")
        console.print(f"Usage: {APP_USAGE[name]}")
        return
    try:
        if name == "scan":
            scan(positional[0] if positional else str(root), **options)
        elif name == "status":
            status(**options)
        elif name == "explain":
            explain(positional[0], **options)
        else:
            simulate_attack(positional[0], **options)
    except typer.Exit:
        pass  # the command already printed its error


def register(app: typer.Typer) -> None:
    app.command("scan")(scan)
    app.command("status")(status)
    app.command("explain")(explain)
    app.command("simulate-attack")(simulate_attack)
