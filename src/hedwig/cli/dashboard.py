"""The terminal dashboard: the architecture with live status, alerts, reports and attacks."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from rich.markup import escape
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Input,
    ProgressBar,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)

from hedwig import settings
from hedwig.core import actions, audit, deploy, engine, evidence, guard_feed, runner, runs
from hedwig.core.advisories import AdvisorySource
from hedwig.core.agents import orchestrator
from hedwig.core.models import CallSite, Finding, Run, ScanResult
from hedwig.core.report import duration

SEVERITY_STYLE = {"critical": "bold red", "high": "dark_orange", "medium": "yellow", "low": "dim"}
OWL = {
    "watching": ("green", '  ,___,\n  (o,o)\n  /)_)\n   " "'),
    "alert": ("red", '  ,___,\n  (O,O)\n  /)_)\n   " "'),
    "asleep": ("grey50", '  ,___,\n  (-,-)\n  /)_)\n   " "'),
}
STATUS_LOOK = {
    "active": ("green", "●"),
    "starting": ("yellow", "◐"),
    "down": ("grey50", "○"),
    "unknown": ("grey50", "?"),
}
# Textual styles do not know Rich's colour names such as grey50
BORDER = {
    "green": "#3fb950", "red": "#f85149", "dark_orange": "#ff8c00",
    "yellow": "#e3b341", "grey50": "#7f7f7f",
}  # fmt: skip
TABS = {"1": "overview", "2": "reports-tab", "3": "attacks-tab"}
HELP = (
    "f fix   t take down (dry run first)   u start a down service   a approve a run   "
    "e/c expand/collapse call sites   1 2 3 tabs   / filter   q quit"
)
GAUGE_FULL = 0.5  # a finding at this risk fills the gauge
SNIPPET_CONTEXT = 3
POLL_SECONDS = 3


@dataclass
class ReportRow:
    key: str
    time: str
    service: str
    kind: str
    outcome: str
    detail: str


class Confirm(ModalScreen[bool]):
    """Shows what an action would do, then asks. Enter confirms, Escape cancels."""

    BINDINGS = [("enter", "yes", "Confirm"), ("escape", "no", "Cancel")]
    DEFAULT_CSS = """
    Confirm { align: center middle; }
    Confirm > Static { width: 70; border: round #b9800f; padding: 1 2; background: #141414; }
    """

    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text

    def compose(self) -> ComposeResult:
        yield Static(f"{self.text}\n\n[b]Enter[/b] confirm   [b]Esc[/b] cancel")

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


class DashApp(App):
    TITLE = "Hedwig"
    CSS = """
    #owl { height: 6; padding: 0 2; }
    #cards { height: 5; }
    .card {
        width: 1fr; border: round #4a3f35; padding: 0 1;
        text-wrap: nowrap; text-overflow: ellipsis;
    }
    .arrow { width: auto; padding: 1 1; color: #b9800f; }
    #infra { height: 1; padding: 0 2; color: #7f7f7f; }
    #tabs { height: 1fr; }
    #alerts { width: 3fr; }
    #right { width: 2fr; }
    #detail { height: auto; max-height: 12; padding: 0 1; }
    #reach { height: 1fr; border: round #4a3f35; }
    #reports { height: 2fr; }
    #report-detail { height: 1fr; border: round #4a3f35; padding: 0 1; overflow-y: auto; }
    #attack-note { height: auto; padding: 0 1; color: #7f7f7f; }
    #filter { display: none; }
    """
    BINDINGS = [
        ("f", "fix", "Fix"),
        ("t", "takedown", "Take down"),
        ("u", "start", "Start"),
        ("a", "approve", "Approve"),
        ("e", "expand", "Expand"),
        ("c", "collapse", "Collapse"),
        ("1", "tab('1')", "Overview"),
        ("2", "tab('2')", "Reports"),
        ("3", "tab('3')", "Attacks"),
        ("/", "filter", "Filter"),
        ("question_mark", "help", "Help"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, root: Path, source: AdvisorySource, tier: str = "medium") -> None:
        super().__init__()
        self.root, self.source, self.tier = root, source, tier
        self.specs = {s.name: s for s in engine.resolve_services(root, tier)}
        self.result: ScanResult | None = None
        self.shown: dict[str, Finding] = {}
        self.needle = ""
        self.fixing: set[str] = set()
        self.status: dict[str, str] = {}
        self.infra: dict[str, str] = {}
        self.attack_rows: list[tuple] = []
        self.report_rows: dict[str, ReportRow] = {}
        self._report_sig: list = []

    # ── layout ────────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        with Horizontal(id="owl"):
            yield Static(id="owl-art")
            with Vertical():
                yield Static(id="status")
                yield ProgressBar(total=100, show_eta=False, id="gauge")
                yield Static(id="clock")
        yield Horizontal(id="cards")
        yield Static(id="infra")
        with TabbedContent(initial="overview", id="tabs"):
            with TabPane("Overview", id="overview"), Horizontal():
                yield DataTable(id="alerts", cursor_type="row")
                with Vertical(id="right"):
                    yield Static("Select an alert.", id="detail")
                    yield Tree("reachability", id="reach")
            with TabPane("Reports", id="reports-tab"), Vertical():
                yield DataTable(id="reports", cursor_type="row")
                yield Static("Select a report.", id="report-detail")
            with TabPane("Attacks", id="attacks-tab"), Vertical():
                yield Static(id="attack-note")
                yield DataTable(id="attacks", cursor_type="row")
        yield Input(placeholder="filter alerts", id="filter")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#alerts", DataTable).add_columns(
            "severity", "risk", "service", "package", "advisory", "ev", "decision"
        )
        self.query_one("#reports", DataTable).add_columns("time", "service", "kind", "outcome")
        self.query_one("#attacks", DataTable).add_columns(
            "time", "source", "category", "action", "detail"
        )
        self.query_one("#reach", Tree).show_root = True
        self.load_scan()
        self.poll()
        self.set_interval(1.0, self.tick)
        self.set_interval(POLL_SECONDS, self.poll)

    # ── background data ───────────────────────────────────────────────────────
    @work(thread=True)
    def load_scan(self) -> None:
        try:
            result = engine.load_last(self.root) or engine.scan(self.root, self.source, self.tier)
        except Exception as err:
            self.call_from_thread(self.notify, f"scan failed: {err}", severity="error")
            return
        self.call_from_thread(self.set_result, result)

    @work(thread=True, exclusive=True, group="poll")
    def poll(self) -> None:
        """Docker status, the Guard's events and the service logs. Slow, so off the UI thread."""
        names = list(self.specs)
        compose = deploy.compose_status(self.root)
        status = (
            {n: compose.get(deploy.compose_name(self.root, n), "unknown") for n in names}
            if compose is not None
            else {n: "unknown" for n in names}
        )
        wanted = {deploy.compose_name(self.root, n) for n in names}
        infra = {k: v for k, v in (compose or {}).items() if k not in wanted}
        events, note = guard_feed.fetch(self.root)
        rows: list[tuple] = [
            (e.time[:19] or "-", e.source or "-", e.category or "-", e.action or "-", e.detail)
            for e in events
        ]
        for name, spec in self.specs.items():
            log = evidence.read_log(spec.log_path)
            for rule in evidence.RULES:
                if rule.id in log.attacks:
                    rows.append(
                        ("-", f"{name} log", rule.label, "seen", f"x{log.attacks[rule.id]}")
                    )
            if log.compromise:
                rows.append(("-", f"{name} log", "compromise marker", "seen", ""))
        self.call_from_thread(self.apply_poll, status, infra, rows, note)

    def apply_poll(self, status: dict, infra: dict, rows: list, note: str) -> None:
        self.status, self.infra = status, infra
        if rows != self.attack_rows:
            self.attack_rows = rows
            table = self.query_one("#attacks", DataTable)
            table.clear()
            for row in rows:
                table.add_row(*row)
        self.query_one("#attack-note", Static).update(
            note or f"{len(rows)} attack report(s) from the Guard and the service logs"
        )
        self.refresh_cards()
        self.refresh_header()

    def set_result(self, result: ScanResult) -> None:
        self.result = result
        self.refresh_alerts()
        self.refresh_cards()

    def findings(self) -> list[Finding]:
        return list(self.result.findings) if self.result else []

    def effective_status(self, name: str) -> str:
        known = self.status.get(name, "unknown")
        if known != "unknown":
            return known
        return "down" if actions.is_down(self.root, name) else "unknown"

    # ── periodic ──────────────────────────────────────────────────────────────
    def tick(self) -> None:
        self.query_one("#clock", Static).update(self.freshness())
        self.refresh_reports()
        self.refresh_cards()
        self.refresh_header()

    def freshness(self) -> str:
        now = datetime.now().strftime("%H:%M:%S")
        if not self.result:
            return f"{now}   scanning…"
        age = datetime.now(UTC) - datetime.fromisoformat(self.result.generated_at)
        minutes = int(age.total_seconds() // 60)
        feed = "advisory data: offline" if self.result.offline else "advisory feed: live"
        return f"{now}   {feed}   last scan {minutes} min ago"

    def state(self) -> str:
        if any(self.effective_status(n) == "down" for n in self.specs):
            return "asleep"
        if any(f.severity == "critical" or f.evidence_level >= 3 for f in self.findings()):
            return "alert"
        return "watching"

    # ── header and architecture ───────────────────────────────────────────────
    def refresh_header(self) -> None:
        state = self.state()
        colour, art = OWL[state]
        self.query_one("#owl-art", Static).update(f"[{colour}]{art}[/{colour}]")
        found = self.findings()
        top = max((f.risk for f in found), default=0.0)
        self.query_one("#status", Static).update(
            f"[{colour}][b]{state}[/b][/{colour}]   {len(found)} findings   top risk {top:.2f}"
        )
        self.query_one("#gauge", ProgressBar).update(progress=min(100, top / GAUGE_FULL * 100))

    def refresh_cards(self) -> None:
        cards = self.query_one("#cards", Horizontal)
        latest = {r.service: r for r in reversed(runs.load_all(self.root))}
        guarded = any("guard" in name for name in self.infra)
        tiles = []
        for name, spec in self.specs.items():
            top = max((f.risk for f in self.findings() if f.service == name), default=0.0)
            risk_colour = (
                "red" if top >= 0.4 else "dark_orange" if top >= 0.25
                else "yellow" if top >= 0.12 else "green"
            )  # fmt: skip
            status = self.effective_status(name)
            colour, dot = STATUS_LOOK[status]
            run = latest.get(name)
            note = ""
            if name in self.fixing:
                note = " · [cyan]fixing[/cyan]"
            elif run and run.action == "review_pr":
                note = " · [yellow]awaiting human[/yellow]"
            body = (
                f"{name}\n{spec.tier} · [{colour}]{dot} {status}[/{colour}]{note}\n"
                f"[{risk_colour}]risk {top:.2f}[/{risk_colour}]"
            )
            tiles.append((body, colour if status != "active" else risk_colour))
        existing = [c for c in cards.children if "card" in c.classes]
        if len(existing) != len(tiles) or bool(cards.query(".arrow")) != guarded:
            for child in list(cards.children):
                child.remove()
            if guarded:
                cards.mount(Static("Guard\n──▶", classes="arrow"))
            cards.mount(*[Static(body, classes="card") for body, _ in tiles])
            existing = []
        for widget, (body, colour) in zip(existing, tiles, strict=False):
            widget.update(body)
            widget.styles.border = ("round", BORDER.get(colour, colour))
        infra = self.query_one("#infra", Static)
        if self.infra:
            parts = []
            for name, state in sorted(self.infra.items()):
                colour, dot = STATUS_LOOK[state]
                parts.append(f"[{colour}]{dot}[/{colour}] {escape(name)}")
            infra.update("infrastructure: " + "   ".join(parts))
        else:
            infra.update("")

    # ── alerts and the reachability tree ──────────────────────────────────────
    def refresh_alerts(self) -> None:
        table = self.query_one("#alerts", DataTable)
        table.clear()
        self.shown = {}
        for f in self.findings():
            haystack = f"{f.id} {f.service} {f.package} {f.severity}".lower()
            if self.needle and self.needle not in haystack:
                continue
            key = f"{f.service}|{f.id}|{f.package}"
            self.shown[key] = f
            style = SEVERITY_STYLE[f.severity]
            table.add_row(
                f"[{style}]{f.severity}[/{style}]",
                f"{f.risk:.2f}",
                f.service,
                f"{f.package}@{f.version}",
                f.id,
                str(f.evidence_level),
                f.decision.action,
                key=key,
            )
        self.refresh_header()

    @staticmethod
    def _selected_key(table: DataTable) -> str | None:
        if not table.row_count:
            return None
        try:
            return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return None

    def selected_finding(self) -> Finding | None:
        key = self._selected_key(self.query_one("#alerts", DataTable))
        return self.shown.get(key) if key else None

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "alerts":
            self.show_detail(self.shown.get(event.row_key.value))
        elif event.data_table.id == "reports":
            row = self.report_rows.get(event.row_key.value)
            self.query_one("#report-detail", Static).update(
                escape(row.detail) if row else "Select a report."
            )

    def show_detail(self, f: Finding | None) -> None:
        pane = self.query_one("#detail", Static)
        if f is None:
            pane.update("Select an alert.")
            self.build_tree(None)
            return
        x = f.factors
        pane.update(
            "\n".join(
                [
                    f"[b]{escape(f.id)}[/b]  {f.severity}  risk {f.risk:.2f}",
                    f"{escape(f.package)}@{escape(f.version)} in "
                    f"[b]{escape(f.service)}[/b] ({f.tier})",
                    escape(f.summary),
                    f"[b]Why[/b] {escape(f.reasoning)}",
                    f"exploitability {x.exploitability:.2f}  impact {x.impact:.2f}  "
                    f"criticality {x.criticality:.2f}  confidence {x.confidence:.2f}",
                    f"fixed version: {f.package_fix or 'none'}"
                    + (" (major)" if f.needs_major else ""),
                    f"[b]Decision[/b] {f.decision.action}: {escape(f.decision.reason)}",
                ]
            )
        )
        self.build_tree(f)

    def snippet(self, service: str, site: CallSite) -> list[Text]:
        spec = self.specs.get(service)
        try:
            lines = (spec.folder / site.file).read_text(encoding="utf-8").splitlines()
        except (AttributeError, OSError, UnicodeDecodeError):
            return [Text("(source not readable)", style="dim")]
        low = max(1, site.line - SNIPPET_CONTEXT)
        high = min(len(lines), site.line + SNIPPET_CONTEXT)
        out = []
        for number in range(low, high + 1):
            hit = number == site.line
            out.append(
                Text(
                    f"{'▶' if hit else ' '} {number:>4} │ {lines[number - 1]}",
                    style="bold #f5bd2a" if hit else "dim",
                )
            )
        return out

    def build_tree(self, f: Finding | None) -> None:
        """Reachability as a tree: files collapsed, each expanding to its call sites and code."""
        tree = self.query_one("#reach", Tree)
        tree.clear()
        if f is None:
            tree.root.set_label("reachability")
            return
        by_file: dict[str, list[CallSite]] = {}
        for site in f.call_sites:
            by_file.setdefault(site.file, []).append(site)
        label = f"reachability: {f.reachability}"
        if f.call_sites:
            label += f" · {len(f.call_sites)} call site(s) in {len(by_file)} file(s)"
        tree.root.set_label(label)
        for file, sites in by_file.items():
            node = tree.root.add(f"{file} ({len(sites)} call site(s))", expand=False)
            for site in sites:
                where = Text(f"{site.function}() line {site.line}: {site.symbol}")
                child = node.add(where, expand=True)
                for line in self.snippet(f.service, site):
                    child.add_leaf(line)
        tree.root.expand()

    def action_expand(self) -> None:
        self.query_one("#reach", Tree).root.expand_all()

    def action_collapse(self) -> None:
        tree = self.query_one("#reach", Tree)
        tree.root.collapse_all()
        tree.root.expand()

    # ── reports ───────────────────────────────────────────────────────────────
    def collect_reports(self) -> list[ReportRow]:
        rows: list[ReportRow] = []
        for run in runs.load_all(self.root):
            step = run.steps[-1] if run.steps else None
            outcome = (
                f"running: {step.name} {step.status}" if run.state == "running" and step
                else f"{run.state}, {run.action or '-'}"
            )  # fmt: skip
            summary = runs.run_dir(self.root, run.run_id) / "summary.txt"
            text = summary.read_text(encoding="utf-8") if summary.is_file() else ""
            steps = "\n".join(f"{s.name}: {s.status} {s.detail}" for s in run.steps)
            rows.append(
                ReportRow(
                    f"run:{run.run_id}",
                    run.started_at,
                    run.service,
                    "fix run",
                    f"{outcome} ({duration(run)})",
                    f"{run.package} {run.from_version} to {run.to_version or '-'}\n"
                    f"{text}\n\n{steps}",
                )
            )
        for number, entry in enumerate(audit.read(self.root)):
            if entry.get("kind") != "action" or entry.get("action") not in ("notify_pm", "report"):
                continue
            ok = entry.get("ok", True)
            rows.append(
                ReportRow(
                    f"audit:{number}",
                    entry["at"],
                    entry.get("service", ""),
                    "PM report" if entry["action"] == "notify_pm" else "PDF report",
                    ("sent" if ok else "NOT sent") + f": {entry.get('message', '')[:60]}",
                    f"{entry.get('message', '')}\nPDF: {entry.get('pdf') or '-'}\n"
                    f"Reason: {entry.get('reason', '-')}",
                )
            )
        return sorted(rows, key=lambda r: r.time, reverse=True)

    def refresh_reports(self) -> None:
        rows = self.collect_reports()
        signature = [(r.key, r.outcome) for r in rows]
        if signature == self._report_sig:
            return
        self._report_sig = signature
        self.report_rows = {r.key: r for r in rows}
        table = self.query_one("#reports", DataTable)
        selected = self._selected_key(table)
        table.clear()
        for r in rows:
            table.add_row(r.time[:19].replace("T", " "), r.service, r.kind, r.outcome, key=r.key)
        if selected in self.report_rows:
            table.move_cursor(row=table.get_row_index(selected))

    # ── actions ───────────────────────────────────────────────────────────────
    def action_help(self) -> None:
        self.notify(HELP, title="Keys", timeout=10)

    def action_tab(self, number: str) -> None:
        self.query_one(TabbedContent).active = TABS[number]

    def action_filter(self) -> None:
        box = self.query_one("#filter", Input)
        box.styles.display = "block"
        box.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.needle = event.value.strip().lower()
        event.input.styles.display = "none"
        self.query_one("#alerts", DataTable).focus()
        self.refresh_alerts()

    def action_fix(self) -> None:
        finding = self.selected_finding()
        if not finding or not self.result:
            return
        key = f"{finding.service}|{finding.package}"
        if key in self.fixing:
            self.notify("already fixing that package")
            return
        if not settings.get("groq_api_key") and finding.decision.action == "fix":
            self.notify("groq_api_key is not set (hedwig config)", severity="error")
            return
        spec = self.specs.get(finding.service)
        if spec is None:
            self.notify(f"no service {finding.service} here", severity="error")
            return
        group = [
            f
            for f in self.findings()
            if f.service == finding.service and f.package == finding.package
        ]
        self.fixing.add(key)
        self.notify(f"fixing {finding.package} in {finding.service}")
        self.run_fix(key, group, spec)

    @work(thread=True)
    def run_fix(self, key: str, group: list[Finding], spec: engine.ServiceSpec) -> None:
        try:
            run = orchestrator.run_fix(self.root, group, spec, self.source)
            sent = actions.notify_pm(self.root, spec.name, "fix finished")
            message = f"{run.package}: {run.state}, {run.action}. {sent.message}"
            severity = "information" if sent.ok else "warning"
        except Exception as err:
            message, severity = f"fix failed: {err}", "error"
        self.fixing.discard(key)
        self.call_from_thread(self.notify, message, severity=severity)

    def action_takedown(self) -> None:
        finding = self.selected_finding()
        if not finding:
            return
        service = finding.service
        real = deploy.compose_file(self.root) is not None
        what = (
            f"run [b]docker compose stop {escape(deploy.compose_name(self.root, service))}[/b]"
            if real
            else "only record the service as down (no compose file found)"
        )
        text = f"[b]Dry run[/b]: take down [b]{escape(service)}[/b]?\n\nHedwig would {what}."

        def done(confirmed: bool | None) -> None:
            if confirmed:
                self.do_takedown(service)

        self.push_screen(Confirm(text), done)

    @work(thread=True)
    def do_takedown(self, service: str) -> None:
        note = actions.takedown(self.root, service, "taken down from the dashboard")
        self.call_from_thread(self.notify, f"{service} taken down ({note})")
        self.call_from_thread(self.poll)

    def action_start(self) -> None:
        finding = self.selected_finding()
        if not finding:
            return
        if self.effective_status(finding.service) not in ("down", "unknown"):
            self.notify(f"{finding.service} is already running")
            return
        self.do_start(finding.service)

    @work(thread=True)
    def do_start(self, service: str) -> None:
        note = actions.resume(self.root, service)
        self.call_from_thread(self.notify, f"{service}: {note}")
        self.call_from_thread(self.poll)

    def action_approve(self) -> None:
        key = self._selected_key(self.query_one("#reports", DataTable)) or ""
        run: Run | None = (
            runs.load(self.root, key.removeprefix("run:")) if key.startswith("run:") else None
        )
        if not run or run.state != "verified" or run.action != "review_pr":
            self.notify("select a verified fix run waiting for review (Reports tab)")
            return
        text = f"Merge branch [b]{escape(run.branch)}[/b] into the current branch?"

        def done(confirmed: bool | None) -> None:
            if not confirmed:
                return
            repo = runner.toplevel(self.root)
            error = (
                actions.merge(self.root, repo, run.branch, run.service) if repo else "no git repo"
            )
            if error:
                self.notify(f"merge failed: {error}", severity="error")
                return
            run.action = "merged"
            runs.save(self.root, run)
            self.notify(f"merged {run.branch}")

        self.push_screen(Confirm(text), done)
