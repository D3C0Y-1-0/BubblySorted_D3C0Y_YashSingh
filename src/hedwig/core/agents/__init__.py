"""The fixing agents. Each is one Groq call with its own strict system prompt."""

from functools import cache
from pathlib import Path

from hedwig.core.models import CallSite, Finding

PROMPTS = Path(__file__).with_name("prompts")
CONTEXT_LINES = 6
MAX_FILE_CHARS = 12_000


@cache
def prompt(name: str) -> str:
    """The shared rules followed by one agent's own prompt."""
    common = (PROMPTS / "common.md").read_text(encoding="utf-8")
    own = (PROMPTS / f"{name}.md").read_text(encoding="utf-8")
    return f"{common}\n{own}"


def advisory_block(finding: Finding) -> str:
    """Advisory text is untrusted. It only ever reaches an agent inside this tag."""
    return (
        "<untrusted_advisory>\n"
        f"ids: {', '.join(finding.ids)}\n"
        f"summary: {finding.summary}\n"
        "</untrusted_advisory>"
    )


def snippets(folder: Path, sites: list[CallSite]) -> str:
    """The lines around each call site, with line numbers."""
    parts = []
    for site in sites:
        try:
            lines = (folder / site.file).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        low = max(0, site.line - 1 - CONTEXT_LINES)
        high = min(len(lines), site.line + CONTEXT_LINES)
        body = "\n".join(f"{n + 1:>4}  {lines[n]}" for n in range(low, high))
        parts.append(f"--- {site.file} in {site.function}() calling {site.symbol}\n{body}")
    return "\n\n".join(parts) or "(no call sites found)"


def file_contents(folder: Path, paths: list[str]) -> str:
    parts = []
    for path in paths:
        try:
            text = (folder / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        parts.append(f"=== {path}\n{text[:MAX_FILE_CHARS]}")
    return "\n\n".join(parts)
