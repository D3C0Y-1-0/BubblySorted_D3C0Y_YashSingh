"""Version comparison and OSV range evaluation, shared by matching and (later) fixing."""

import re
from functools import cmp_to_key

_RELEASE_QUALIFIERS = {"", "release", "final", "ga"}


def _split(version: str) -> tuple[list[int], str]:
    text = version.strip().lstrip("vV")
    match = re.match(r"(\d+(?:\.\d+)*)(.*)$", text)
    if not match:
        return [], text.lower()
    numbers = [int(part) for part in match.group(1).split(".")]
    qualifier = match.group(2).lstrip(".-_+").lower()
    return numbers, "" if qualifier in _RELEASE_QUALIFIERS else qualifier


def compare(a: str, b: str) -> int:
    """-1, 0 or 1. Pre-release qualifiers sort before the plain release."""
    nums_a, qual_a = _split(a)
    nums_b, qual_b = _split(b)
    size = max(len(nums_a), len(nums_b))
    nums_a = nums_a + [0] * (size - len(nums_a))
    nums_b = nums_b + [0] * (size - len(nums_b))
    if nums_a != nums_b:
        return -1 if nums_a < nums_b else 1
    if qual_a == qual_b:
        return 0
    if not qual_a:
        return 1
    if not qual_b:
        return -1
    return -1 if qual_a < qual_b else 1


def major(version: str) -> int:
    numbers, _ = _split(version)
    return numbers[0] if numbers else 0


def _event_version(event: dict) -> str:
    for key in ("introduced", "fixed", "last_affected", "limit"):
        if key in event:
            return event[key]
    return "0"


def in_range(version: str, events: list[dict]) -> bool:
    """Evaluate OSV introduced/fixed/last_affected events for one range."""
    ordered = sorted(
        events, key=cmp_to_key(lambda x, y: compare(_event_version(x), _event_version(y)))
    )
    affected = False
    for event in ordered:
        if "introduced" in event:
            if compare(version, event["introduced"]) >= 0:
                affected = True
        elif "fixed" in event:
            if compare(version, event["fixed"]) >= 0:
                affected = False
        elif "last_affected" in event:
            if compare(version, event["last_affected"]) > 0:
                affected = False
    return affected


def fixed_versions(events: list[dict]) -> list[str]:
    return [event["fixed"] for event in events if "fixed" in event]
