"""The interactive Hedwig app: a welcome screen and a slash-command prompt."""

import shlex
from collections.abc import Callable
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.history import FileHistory
from prompt_toolkit.layout.containers import Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from hedwig import __version__, config, settings
from hedwig.cli import commands, scan_cmd
from hedwig.ui.mascot import banner

console = Console()

# ── Hedwig colour tokens ──────────────────────────────────────────────────────
# Separator: muted warm-grey / brown (subtle framing, not bright yellow).
_SEP_COLOUR = "#4a3f35"
# Prompt "> ": golden accent echoing the owl's armor.
_PROMPT_COLOUR = "#f5bd2a"
# Command text in the suggestion menu.
_CMD_COLOUR = "#f5bd2a"

# ── prompt_toolkit Style ──────────────────────────────────────────────────────
# Covers: prompt chrome, completion menu, and the bottom toolbar.
HEDWIG_STYLE = Style.from_dict(
    {
        # Prompt chrome ---------------------------------------------------------
        "separator": _SEP_COLOUR,
        "prompt": f"bold {_PROMPT_COLOUR}",
        # Completion menu body --------------------------------------------------
        # Dark theme neutral charcoal background; commands in gold.
        "completion-menu": f"bg:#141414 {_CMD_COLOUR}",
        "completion-menu.completion": f"bg:#141414 bold {_CMD_COLOUR}",
        # Selected row: golden-yellow selection with readable dark text.
        "completion-menu.completion.current": "bg:#b9800f #141414 bold",
        # Completion meta (description)
        "completion-menu.meta.completion": f"bg:#141414 {_CMD_COLOUR}",
        "completion-menu.meta.completion.current": "bg:#b9800f #141414",
        # Scrollbar -------------------------------------------------------------
        "scrollbar.background": "bg:#1c1c1c",
        "scrollbar.button": "bg:#383838",
        # Bottom toolbar --------------------------------------------------------
        "bottom-toolbar": "bg:#141414 #888888",
        "bottom-toolbar.text": "bg:#141414 #888888",
    }
)


def _terminal_width() -> int:
    """Current terminal width, falling back to 80 when called outside a live app."""
    try:
        from prompt_toolkit.application import get_app

        return get_app().output.get_size().columns
    except Exception:
        return 80


def _sep_line() -> list[tuple[str, str]]:
    """Full-width ─ separator as a FormattedText token list."""
    return [("class:separator", "─" * _terminal_width())]


def _prompt_message() -> FormattedText:
    """Dynamic prompt: top separator then a newline then the '> ' marker.

    Re-evaluated on every redraw so the top line adapts to terminal resizing.
    """
    return FormattedText(
        _sep_line()
        + [
            ("", "\n"),
            ("class:prompt", "> "),
        ]
    )


class HedwigPromptSession(PromptSession):
    """PromptSession with a custom layout positioning horizontal separators around input."""

    def _create_layout(self) -> Layout:
        layout = super()._create_layout()
        # Attach the bottom separator directly below the input buffer in the inner HSplit.
        # This keeps both lines exactly one input row apart, forming a compact three-row box.
        c0 = layout.container.children[0]
        float_container = getattr(c0, "alternative_content", None) or c0.content
        float_container.content.children.append(
            Window(
                FormattedTextControl(_sep_line),
                dont_extend_height=True,
                height=1,
            )
        )
        return layout


class Session:
    """State of one app session. It stays bound to the folder it was launched from."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.running = True

    def welcome(self) -> None:
        console.print(banner())
        project = config.load_project(self.root)
        if project is None:
            project_line = "no .hedwig.yml here, run /init"
        else:
            count = len(project.get("services") or {})
            project_line = f"{count} service{'s' if count != 1 else ''} in .hedwig.yml"
        groq_line = "configured" if settings.get("groq_api_key") else "not set, run /config"
        body = Text()
        body.append(f"Welcome to Hedwig v{__version__}\n\n", style="bold")
        body.append(f"folder   {self.root}\n")
        body.append(f"project  {project_line}\n")
        body.append(f"groq     {groq_line}\n\n")
        body.append("Type /help for commands", style="dim")
        console.print(Panel(body, border_style="gold1", expand=False))

    def toolbar(self) -> str:
        """Single-line status bar anchored at the bottom of the terminal."""
        return f" {self.root} · {settings.get('model')} · /help"


def _help(session: Session, args: list[str]) -> None:
    for name, (description, _) in COMMANDS.items():
        console.print(f"  [bold]{name:<10}[/bold] {description}")


def _init(session: Session, args: list[str]) -> None:
    commands.init_here(session.root)


def _config(session: Session, args: list[str]) -> None:
    if not args:
        commands.config_wizard()
    elif args[0] == "show":
        commands.config_show()
    elif args[0] == "set" and len(args) == 3:
        commands.config_set(args[1], args[2])
    else:
        console.print("Usage: /config | /config show | /config set <key> <value>")


def _scan(session: Session, args: list[str]) -> None:
    scan_cmd.run_in_app("scan", args, session.root)


def _status(session: Session, args: list[str]) -> None:
    scan_cmd.run_in_app("status", args, session.root)


def _explain(session: Session, args: list[str]) -> None:
    scan_cmd.run_in_app("explain", args, session.root)


def _doctor(session: Session, args: list[str]) -> None:
    commands.doctor()


def _clear(session: Session, args: list[str]) -> None:
    console.clear()
    session.welcome()


def _exit(session: Session, args: list[str]) -> None:
    session.running = False


Handler = Callable[[Session, list[str]], None]

COMMANDS: dict[str, tuple[str, Handler]] = {
    "/help": ("List the commands", _help),
    "/init": ("Set up .hedwig.yml for this folder", _init),
    "/scan": ("Find vulnerabilities (this folder, a path or a git URL)", _scan),
    "/status": ("Findings per service in this folder", _status),
    "/explain": ("Explain one finding: /explain <CVE or advisory id>", _explain),
    "/config": ("Set API keys (also: show, set <key> <value>)", _config),
    "/doctor": ("Check installed tools", _doctor),
    "/clear": ("Clear the screen", _clear),
    "/exit": ("Leave Hedwig", _exit),
    "/quit": ("Leave Hedwig", _exit),
}


class SlashCompleter(Completer):
    """Pops up the commands, with descriptions, as soon as you type a slash."""

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text.startswith("/") or " " in text:
            return
        for name, (description, _) in COMMANDS.items():
            if name.startswith(text):
                yield Completion(name, start_position=-len(text), display_meta=description)


def handle(session: Session, line: str) -> None:
    line = line.strip()
    if not line:
        return
    if not line.startswith("/"):
        console.print("Commands start with /. Try /help")
        return
    try:
        parts = shlex.split(line)
    except ValueError as err:
        console.print(f"[red]{err}[/red]")
        return
    command = COMMANDS.get(parts[0])
    if command is None:
        console.print(f"[red]Unknown command {parts[0]}.[/red] Try /help")
        return
    try:
        command[1](session, parts[1:])
    except (KeyboardInterrupt, EOFError):
        console.print("[dim]cancelled[/dim]")
    except Exception as err:  # a failing command must not end the session
        console.print(f"[red]{type(err).__name__}: {err}[/red]")


def run() -> None:
    session = Session(Path.cwd())
    settings.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    prompt = HedwigPromptSession(
        history=FileHistory(str(settings.CONFIG_DIR / "history")),
        completer=SlashCompleter(),
        complete_while_typing=True,
        bottom_toolbar=session.toolbar,
        style=HEDWIG_STYLE,
    )
    session.welcome()
    while session.running:
        try:
            line = prompt.prompt(_prompt_message)
        except KeyboardInterrupt:
            continue
        except EOFError:
            break
        handle(session, line)
