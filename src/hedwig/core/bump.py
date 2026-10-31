"""Deterministic dependency bump: edit the manifest text, then let the package tool fix the lock.

The Fixer agent never touches versions. Keeping formatting intact keeps the diff minimal.
"""

import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

from hedwig.core.models import Finding

# lockfile or manifest the inventory read -> the file where the version is declared
SOURCE_MANIFEST = {
    "package-lock.json": "package.json",
    "Cargo.lock": "Cargo.toml",
    "composer.lock": "composer.json",
    "pom.xml": "pom.xml",
    "requirements.txt": "requirements.txt",
}
LOCKFILES = {"package-lock.json", "Cargo.lock", "composer.lock"}
TOOL_TIMEOUT = 300


def manifest_for(finding: Finding) -> str:
    return SOURCE_MANIFEST.get(finding.manifest, finding.manifest)


def _flexible(name: str) -> str:
    return r"[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", name))


def _pattern(finding: Finding, text: str) -> re.Pattern | None:
    """A regex whose groups are (before)(version spec)(after), or None if the file has none."""
    name = finding.package
    if finding.ecosystem in ("npm", "Packagist"):
        found = re.compile(rf'("{re.escape(name)}"\s*:\s*")([^"]*)(")', re.I)
    elif finding.ecosystem == "PyPI":
        found = re.compile(
            rf"(?im)^(\s*{_flexible(name)}(?:\[[^\]]*\])?\s*==\s*)([A-Za-z0-9_.\-+!]+)()"
        )
    elif finding.ecosystem == "crates.io":
        found = re.compile(
            rf'(?m)(^\s*{re.escape(name)}\s*=\s*(?:\{{[^}}\n]*?version\s*=\s*)?")([^"]*)(")'
        )
    else:
        return None
    return found if found.search(text) else None


def _maven_block(finding: Finding, text: str) -> tuple[re.Match, str] | None:
    group, _, artifact = finding.package.partition(":")
    for block in re.finditer(r"(?s)<dependency>.*?</dependency>", text):
        body = block.group(0)
        if f"<groupId>{group}</groupId>" in body and f"<artifactId>{artifact}</artifactId>" in body:
            return block, body
    return None


def declared(folder: Path, finding: Finding) -> str | None:
    """The version spec written in the manifest, or None if the package is only transitive."""
    path = folder / manifest_for(finding)
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    if finding.ecosystem == "Maven":
        found = _maven_block(finding, text)
        if not found:
            return None
        version = re.search(r"<version>(.*?)</version>", found[1])
        return version.group(1).strip() if version else None
    pattern = _pattern(finding, text)
    if not pattern:
        return None
    match = pattern.search(text)
    if finding.ecosystem in ("npm", "Packagist"):
        # the key may also be the project's own name; require a dependency section to hold it
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        sections = (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "require",
            "require-dev",
        )
        if not any(
            finding.package.lower() in {k.lower() for k in data.get(s, {})} for s in sections
        ):
            return None
    return match.group(2)


def _prefix(spec: str) -> str:
    match = re.match(r"^[\^~=]+", spec.strip())
    return match.group(0) if match else ""


def apply(folder: Path, finding: Finding, target: str) -> str | None:
    """Rewrite the declared version to `target`. Returns an error message, or None on success."""
    path = folder / manifest_for(finding)
    spec = declared(folder, finding)
    if spec is None:
        return (
            f"{finding.package} is a transitive dependency (not declared in {path.name}); "
            "Hedwig only bumps direct dependencies"
        )
    text = path.read_text(encoding="utf-8")
    if finding.ecosystem == "Maven":
        found = _maven_block(finding, text)
        block, body = found
        version = re.search(r"<version>(.*?)</version>", body).group(1).strip()
        prop = re.fullmatch(r"\$\{([^}]+)\}", version)
        if prop:
            pattern = re.compile(
                rf"(<{re.escape(prop.group(1))}>)(.*?)(</{re.escape(prop.group(1))}>)"
            )
            if not pattern.search(text):
                return f"cannot find the property {prop.group(1)} in {path.name}"
            text = pattern.sub(lambda m: f"{m.group(1)}{target}{m.group(3)}", text, count=1)
        else:
            new_body = re.sub(
                r"(<version>)(.*?)(</version>)", rf"\g<1>{target}\g<3>", body, count=1
            )
            text = text[: block.start()] + new_body + text[block.end() :]
    else:
        pattern = _pattern(finding, text)
        text = pattern.sub(
            lambda m: f"{m.group(1)}{_prefix(m.group(2))}{target}{m.group(3)}", text, count=1
        )
    path.write_text(text, encoding="utf-8")
    return None if declared(folder, finding) else f"could not rewrite {path.name}"


def remove(folder: Path, finding: Finding) -> str | None:
    """Delete the package's declaration from the manifest. Returns an error, or None."""
    path = folder / manifest_for(finding)
    if declared(folder, finding) is None:
        return f"{finding.package} is not declared in {path.name}"
    text = path.read_text(encoding="utf-8")
    name = re.escape(finding.package)
    if finding.ecosystem == "Maven":
        found = _maven_block(finding, text)
        block = found[0]
        text = text[: block.start()].rstrip(" \t") + text[block.end() :].lstrip(" \t").lstrip("\n")
    elif finding.ecosystem in ("npm", "Packagist"):
        line = re.compile(rf'^[ \t]*"{name}"\s*:\s*"[^"]*"\s*,?[ \t]*\n', re.M | re.I)
        text = line.sub("", text, count=1)
        text = re.sub(r",(\s*\n\s*\})", r"\1", text)  # a comma left behind by the last entry
        try:
            json.loads(text)
        except json.JSONDecodeError:
            return f"removing {finding.package} would break {path.name}"
    elif finding.ecosystem == "PyPI":
        line = re.compile(
            rf"^[ \t]*{_flexible(finding.package)}(?:\[[^\]]*\])?\s*==.*\n?", re.M | re.I
        )
        text = line.sub("", text, count=1)
    elif finding.ecosystem == "crates.io":
        line = re.compile(rf"^[ \t]*{name}\s*=.*\n", re.M)
        text = line.sub("", text, count=1)
    else:
        return f"cannot remove a {finding.ecosystem} package"
    path.write_text(text, encoding="utf-8")
    return None if declared(folder, finding) is None else f"could not remove it from {path.name}"


def _run(command: list[str], folder: Path) -> str | None:
    if not shutil.which(command[0]):
        return f"{command[0]} is not installed, so the lockfile cannot be updated"
    try:
        done = subprocess.run(
            command, cwd=folder, capture_output=True, text=True, timeout=TOOL_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return f"`{' '.join(command)}` timed out"
    if done.returncode != 0:
        return f"`{' '.join(command)}` failed: {(done.stderr or done.stdout).strip()[-400:]}"
    return None


def regenerate_lock(
    folder: Path, finding: Finding, target: str, removal: bool = False
) -> str | None:
    """Let the package tool rewrite the lockfile. Never done by the LLM."""
    if finding.manifest not in LOCKFILES:
        return None  # Maven and requirements.txt have no lockfile
    name = finding.package
    if removal and finding.ecosystem == "crates.io":
        command = ["cargo", "metadata", "--format-version", "1"]  # rewrites the lock without it
    elif finding.ecosystem == "npm":
        command = [
            "npm",
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ]
    elif finding.ecosystem == "crates.io":
        command = ["cargo", "update", "-p", name, "--precise", target]
    else:
        command = ["composer", "update", name, "--no-install", "--no-scripts", "--no-interaction"]
    return _run(command, folder)


def pinned_version(folder: Path, finding: Finding) -> str | None:
    """The version the lockfile resolves for the package now (used to check the bump took)."""
    lock = folder / finding.manifest
    if not lock.is_file():
        return None
    if finding.manifest == "package-lock.json":
        data = json.loads(lock.read_text(encoding="utf-8"))
        entry = (data.get("packages") or {}).get(f"node_modules/{finding.package}")
        return (entry or {}).get("version")
    if finding.manifest == "Cargo.lock":
        data = tomllib.loads(lock.read_text(encoding="utf-8"))
        return next(
            (p["version"] for p in data.get("package", []) if p["name"] == finding.package), None
        )
    if finding.manifest == "composer.lock":
        data = json.loads(lock.read_text(encoding="utf-8"))
        items = (data.get("packages") or []) + (data.get("packages-dev") or [])
        return next(
            (i["version"].lstrip("vV") for i in items if i["name"].lower() == finding.package), None
        )
    return None
