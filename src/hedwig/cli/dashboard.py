"""The terminal dashboard: services, alerts, fix runs and their timing, all in one screen."""

from datetime import UTC, datetime
from pathlib import Path

from rich.markup import escape
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Input, OptionList, ProgressBar, Static

from hedwig import settings
from hedwig.core import actions, engine, runner, runs
from hedwig.core.advisories import REPLAY_DIR, AdvisorySource, replay_names
from hedwig.core.agents import orchestrator
from hedwig.core.models import Finding, Run, ScanResult
from hedwig.core.report import duration

SEVERITY_STYLE = {"critical": "bold red", "high": "dark_orange", "medium": "yellow", "low": "dim"}
OWL = {
    "watching": ("green", '  ,___,\n  (o,o)\n  /)_)\n   " "'),
    "alert": ("red", '  ,___,\n  (O,O)\n  /)_)\n   " "'),
    "asleep": ("grey50", '  ,___,\n  (-,-)\n  /)_)\n   " "'),
}
HELP = (
    "Enter detail   f fix   t takedown (dry run first)   a approve a run   "
    "r replay an advisory   / filter   q quit"
)
GAUGE_FULL = 0.5  # a finding at this risk fills the gauge


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


class PickAdvisory(ModalScreen[str | None]):
    BINDINGS = [("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    PickAdvisory { align: center middle; }
    PickAdvisory > OptionList { width: 40; height: auto; border: round #b9800f; }
    """

    def compose(self) -> ComposeResult:
        yield OptionList(*replay_names())

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(str(event.option.prompt))

    def action_cancel(self) -> None:
        self.dismiss(None)


class DashApp(App):
    TITLE = "Hedwig"
    CSS = """
    #owl { height: 6; padding: 0 2; }
    #cards { height: 5; }
    .card { width: 1fr; border: round #4a3f35; padding: 0 1; }
    #middle { height: 1fr; }
    #alerts { width: 3fr; }
    #detail { width: 2fr; border: round #4a3f35; padding: 0 1; overflow-y: auto; }
    #timeline { height: 9; }
    #filter { display: none; }
    """
    BINDINGS = [
        ("f", "fix", "Fix"),
        ("t", "takedown", "Takedown"),
        ("a", "approve", "Approve"),
        ("r", "replay", "Replay"),
        ("/", "filter", "Filter"),
        ("question_mark", "help", "Help"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, root: Path, source: AdvisorySource, tier: str = "medium") -> None:
        super().__init__()
        self.root, self.source, self.tier = root, source, tier
        self.result: ScanResult | None = None
        self.replayed: list[Finding] = []
        self.shown: dict[str, Finding] = {}
        self.needle = ""
        self.fixing: set[str] = set()

    # ── layout ────────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        with Horizontal(id="owl"):
            yield Static(id="owl-art", classes="owl")
            with Vertical():
                yield Static(id="status")
                yield ProgressBar(total=100, show_eta=False, id="gauge")
                yield Static(id="clock")
        yield Horizontal(id="cards")
        with Horizontal(id="middle"):
            yield DataTable(id="alerts", cursor_type="row")
            yield Static("Select an alert.", id="detail")
        yield DataTable(id="timeline", cursor_type="row")
        yield Input(placeholder="filter alerts", id="filter")
        yield Footer()

    def on_mount(self) -> None:
        alerts = self.query_one("#alerts", DataTable)
        alerts.add_columns("severity", "risk", "service", "package", "advisory", "ev", "decision")
        timeline = self.query_one("#timeline", DataTable)
        timeline.add_columns("run", "service", "package", "fix", "step", "state", "outcome", "time")
        self.load_scan()
        self.set_interval(1.0, self.tick)

    # ── data ──────────────────────────────────────────────────────────────────
    @work(thread=True)
    def load_scan(self) -> None:
        try:
            result = engine.load_last(self.root) or engine.scan(self.root, self.source, self.tier)
        except Exception as err:
            self.call_from_thread(self.notify, f"scan failed: {err}", severity="error")
            return
        self.call_from_thread(self.set_result, result)

    def set_result(self, result: ScanResult) -> None:
        self.result = result
        self.refresh_alerts()
        self.refresh_cards()

    def findings(self) -> list[Finding]:
        real = self.result.findings if self.result else []
        taken = {(f.service, f.id, f.package) for f in real}
        extra = [f for f in self.replayed if (f.service, f.id, f.package) not in taken]
        return sorted([*real, *extra], key=lambda f: -f.risk)

    def tick(self) -> None:
        self.query_one("#clock", Static).update(self.freshness())
        self.refresh_timeline()
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

    # ── rendering ─────────────────────────────────────────────────────────────
    def state(self) -> str:
        down = actions.load_state(self.root).get("down", {})
        found = self.findings()
        if down:
            return "asleep"
        if any(f.severity == "critical" or f.evidence_level >= 3 for f in found):
            return "alert"
        return "watching"

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
        if not self.result:
            return
        down = actions.load_state(self.root).get("down", {})
        latest = {r.service: r for r in reversed(runs.load_all(self.root))}
        text = []
        for service in self.result.services:
            found = [f for f in self.findings() if f.service == service.name]
            top = max((f.risk for f in found), default=0.0)
            colour = (
                "red"
                if top >= 0.4
                else "dark_orange"
                if top >= 0.25
                else "yellow"
                if top >= 0.12
                else "green"
            )
            run = latest.get(service.name)
            if service.name in down:
                health = "[grey50]down[/grey50]"
            elif run and run.action == "review_pr":
                health = "[yellow]awaiting human[/yellow]"
            elif service.name in self.fixing:
                health = "[cyan]fixing[/cyan]"
            else:
                health = "[green]ok[/green]"
            text.append(
                (
                    service.name,
                    f"{service.name}\n{service.tier} · {health}\n"
                    f"[{colour}]risk {top:.2f}[/{colour}]",
                    colour,
                )
            )
        existing = list(cards.children)
        if len(existing) != len(text):
            for child in existing:
                child.remove()
            cards.mount(*[Static(body, classes="card") for _, body, _ in text])
            existing = list(cards.children)
        for widget, (_, body, colour) in zip(existing, text, strict=False):
            widget.update(body)
            widget.styles.border = ("round", colour)

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
            tag = " [cyan](replay)[/cyan]" if f in self.replayed else ""
            table.add_row(
                f"[{style}]{f.severity}[/{style}]",
                f"{f.risk:.2f}",
                f.service,
                f"{f.package}@{f.version}",
                f"{f.id}{tag}",
                str(f.evidence_level),
                f.decision.action,
                key=key,
            )
        self.refresh_header()

    def refresh_timeline(self) -> None:
        table = self.query_one("#timeline", DataTable)
        rows = runs.load_all(self.root)
        selected = self.selected_run_id()
        table.clear()
        for r in rows[:30]:
            step = r.steps[-1] if r.steps else None
            table.add_row(
                r.run_id[-12:],
                r.service,
                r.package,
                f"{r.from_version} → {r.to_version or '-'}",
                f"{step.name} {step.status}" if step else "-",
                r.state,
                r.action or "-",
                duration(r),
                key=r.run_id,
            )
        if selected and selected in {r.run_id for r in rows[:30]}:
            table.move_cursor(row=table.get_row_index(selected))

    def selected_run_id(self) -> str | None:
        table = self.query_one("#timeline", DataTable)
        if not table.row_count:
            return None
        try:
            return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return None

    def selected_finding(self) -> Finding | None:
        table = self.query_one("#alerts", DataTable)
        if not table.row_count:
            return None
        try:
            return self.shown.get(
                table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            )
        except Exception:
            return None

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "alerts":
            return
        self.show_detail(self.shown.get(event.row_key.value))

    def show_detail(self, f: Finding | None) -> None:
        pane = self.query_one("#detail", Static)
        if f is None:
            pane.update("Select an alert.")
            return
        x = f.factors
        lines = [
            f"[b]{escape(f.id)}[/b]  {f.severity}  risk {f.risk:.2f}",
            f"{escape(f.package)}@{escape(f.version)} in [b]{escape(f.service)}[/b] ({f.tier})",
            escape(f.summary),
            "",
            f"[b]Why[/b] {escape(f.reasoning)}",
            f"exploitability {x.exploitability:.2f}  impact {x.impact:.2f}  "
            f"criticality {x.criticality:.2f}  confidence {x.confidence:.2f}",
            f"reachability: {f.reachability}",
            *[f"  {escape(s.symbol)} at {escape(s.file)}:{s.line}" for s in f.call_sites[:3]],
            f"fixed version: {f.package_fix or 'none'}" + (" (major)" if f.needs_major else ""),
            f"[b]Decision[/b] {f.decision.action}: {escape(f.decision.reason)}",
        ]
        pane.update("\n".join(lines))

    # ── actions ───────────────────────────────────────────────────────────────
    def action_help(self) -> None:
        self.notify(HELP, title="Keys", timeout=10)

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
        group = [
            f
            for f in self.findings()
            if f.service == finding.service and f.package == finding.package
        ]
        spec = next(
            (s for s in engine.resolve_services(self.root, self.tier) if s.name == finding.service),
            None,
        )
        if spec is None:
            self.notify(f"no service {finding.service} here", severity="error")
            return
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
        text = (
            f"[b]Dry run[/b]: take down [b]{escape(finding.service)}[/b]?\n\n"
            "Hedwig would mark the service as down and email the PM. The real shutdown arrives "
            "with the deployment executor, so for now it is only recorded."
        )

        def done(confirmed: bool | None) -> None:
            if confirmed:
                actions.takedown(self.root, finding.service, "taken down from the dashboard")
                self.notify(f"{finding.service} taken down (recorded)")

        self.push_screen(Confirm(text), done)

    def action_approve(self) -> None:
        run_id = self.selected_run_id()
        run: Run | None = runs.load(self.root, run_id) if run_id else None
        if not run or run.state != "verified" or run.action != "review_pr":
            self.notify("select a verified run that is waiting for review (timeline)")
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

    def action_replay(self) -> None:
        def chosen(name: str | None) -> None:
            if name:
                self.add_replay(name)

        self.push_screen(PickAdvisory(), chosen)

    @work(thread=True)
    def add_replay(self, name: str) -> None:
        source = AdvisorySource(offline=True, directory=REPLAY_DIR, only={name})
        try:
            result = engine.scan(self.root, source, self.tier, save=False)
        except Exception as err:
            self.call_from_thread(self.notify, f"replay failed: {err}", severity="error")
            return
        self.replayed = [f for f in self.replayed if name not in f.ids] + result.findings
        self.call_from_thread(self.refresh_alerts)
        self.call_from_thread(self.notify, f"replayed {name}: {len(result.findings)} finding(s)")
