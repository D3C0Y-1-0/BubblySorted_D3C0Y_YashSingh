"""Is the vulnerable package actually used? This only adjusts confidence, never hides a finding."""

from dataclasses import dataclass, field

from hedwig.core.code_index import Usage
from hedwig.core.models import CallSite

MAX_SITES = 5


@dataclass
class Reach:
    state: str  # called | imported | not imported
    call_sites: list[CallSite] = field(default_factory=list)


def _last(name: str) -> str:
    return name.replace("::", ".").rsplit(".", 1)[-1]


def assess(usage: Usage, symbols: list[str]) -> Reach:
    """`symbols` are the functions the advisory (or our hint table) says are dangerous.

    With symbols, only a call to one of them counts as called. Without, any call does.
    """
    calls = usage.calls
    if symbols:
        wanted = {_last(s) for s in symbols}
        calls = [c for c in calls if _last(c.symbol) in wanted]
    if calls:
        return Reach("called", calls[:MAX_SITES])
    return Reach("imported" if usage.imported else "not imported")


def advisory_symbols(records: list[dict], entries_for) -> list[str]:
    """Function names an OSV record lists as affected (RustSec, Go style), if any."""
    names: list[str] = []
    for record in records:
        for entry in entries_for(record):
            specific = entry.get("ecosystem_specific") or {}
            names += specific.get("affected_functions") or []
            names += (specific.get("affects") or {}).get("functions") or []
            for item in specific.get("imports") or []:
                names += item.get("symbols") or []
    return names
