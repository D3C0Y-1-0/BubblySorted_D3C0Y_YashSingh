"""Deterministic checks on what the agents produce. A violation counts as a failed attempt."""

import difflib
import json
import re
import tomllib
from pathlib import Path

from hedwig.core import bump
from hedwig.core.models import Edit, Finding

MAX_CODE_LINES = 30
TEST_MARKERS = re.compile(r"\btest\(|\bit\(|def test_|@Test\b|#\[test\]|function test")
DEPENDENCY_FILES = ("package.json", "composer.json", "Cargo.toml", "requirements.txt", "pom.xml")


def apply_edits(folder: Path, edits: list[Edit], allowed: list[str]) -> list[str]:
    """Apply search/replace edits to the files. Writes nothing if any edit is invalid."""
    violations: list[str] = []
    texts: dict[str, str] = {}
    for edit in edits:
        path = edit.path.replace("\\", "/")
        if path not in allowed:
            violations.append(f"edit to {edit.path} is outside the allowed files")
            continue
        if path not in texts:
            try:
                texts[path] = (folder / path).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                violations.append(f"{edit.path} cannot be read")
                continue
        count = texts[path].count(edit.old) if edit.old else 0
        if count != 1:
            violations.append(f"the text to replace in {edit.path} occurs {count} times, not once")
            continue
        texts[path] = texts[path].replace(edit.old, edit.new, 1)
    if not violations:
        for path, text in texts.items():
            (folder / path).write_text(text, encoding="utf-8")
    return violations


def _dependency_names(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return set()
    try:
        if path.name in ("package.json", "composer.json"):
            data = json.loads(text)
            keys = (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "require",
                "require-dev",
            )
            return {name for key in keys for name in data.get(key, {})}
        if path.name == "Cargo.toml":
            data = tomllib.loads(text)
            return {n for key in ("dependencies", "dev-dependencies") for n in data.get(key, {})}
    except (ValueError, AttributeError):
        return set()
    if path.name == "requirements.txt":
        return {
            m.group(1).lower()
            for line in text.splitlines()
            if (m := re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)", line.split("#", 1)[0]))
        }
    if path.name == "pom.xml":
        return set(re.findall(r"<artifactId>([^<]+)</artifactId>", text))
    return set()


def _is_dependency_file(path: str) -> bool:
    name = Path(path).name
    return name in DEPENDENCY_FILES or name in bump.LOCKFILES


def check_result(
    base: Path, new: Path, finding: Finding, target: str, allowed: list[str], removal: bool = False
) -> list[str]:
    """Compare the fix worktree with the base one and return every rule that was broken."""
    violations: list[str] = []
    manifest = bump.manifest_for(finding)

    spec = bump.declared(new, finding)
    if removal:
        if spec is not None:
            violations.append(f"{manifest} must no longer declare {finding.package}")
    elif spec is None or spec.lstrip("^~=") != target:
        violations.append(f"{manifest} must declare {finding.package} {target}, found {spec}")

    for name in DEPENDENCY_FILES:
        added = _dependency_names(new / name) - _dependency_names(base / name)
        if added:
            violations.append(f"new dependencies in {name}: {', '.join(sorted(added))}")

    changed_lines = 0
    for path in allowed:
        if _is_dependency_file(path):
            continue
        before = _read(base / path)
        after = _read(new / path)
        if before == after:
            continue
        diff = difflib.unified_diff(before.splitlines(), after.splitlines(), lineterm="", n=0)
        changed_lines += sum(
            1 for line in diff if line[:1] in "+-" and not line.startswith(("+++", "---"))
        )
        if len(TEST_MARKERS.findall(after)) < len(TEST_MARKERS.findall(before)):
            violations.append(f"{path} has fewer tests than before")
    if changed_lines > MAX_CODE_LINES:
        violations.append(f"{changed_lines} changed code lines, the limit is {MAX_CODE_LINES}")
    return violations


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
