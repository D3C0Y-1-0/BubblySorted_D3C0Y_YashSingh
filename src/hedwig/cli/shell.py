"""The interactive Hedwig app: a welcome screen and a slash-command prompt."""

import shlex
from collections.abc import Callable
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from hedwig import __version__, config, settings
from hedwig.cli import commands, scan_cmd
from hedwig.ui.mascot import banner

console = Console()


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
    prompt = PromptSession(
        history=FileHistory(str(settings.CONFIG_DIR / "history")),
        completer=SlashCompleter(),
        complete_while_typing=True,
        bottom_toolbar=session.toolbar,
    )
    session.welcome()
    while session.running:
        try:
            line = prompt.prompt("> ")
        except KeyboardInterrupt:
            continue
        except EOFError:
            break
        handle(session, line)
