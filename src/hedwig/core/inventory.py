"""Read lockfiles into a flat package list. One small parser per format."""

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path

from hedwig.core.models import Package


def _package(ecosystem: str, name: str, version: str, service: str, manifest: str) -> Package:
    return Package(
        ecosystem=ecosystem, name=name, version=version, service=service, manifest=manifest
    )


def parse_package_lock(path: Path, service: str) -> list[Package]:
    data = json.loads(path.read_text(encoding="utf-8"))
    found: dict[tuple[str, str], Package] = {}

    def add(name: str, version: str | None) -> None:
        if name and version and (name, version) not in found:
            found[(name, version)] = _package("npm", name, version, service, path.name)

    for key, entry in (data.get("packages") or {}).items():  # lockfile v2 and v3
        if key and not entry.get("link"):
            add(entry.get("name") or key.split("node_modules/")[-1], entry.get("version"))

    def walk(dependencies: dict) -> None:  # lockfile v1
        for name, entry in dependencies.items():
            add(name, entry.get("version"))
            walk(entry.get("dependencies") or {})

    walk(data.get("dependencies") or {})
    return list(found.values())


def parse_cargo_lock(path: Path, service: str) -> list[Package]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return [
        _package("crates.io", item["name"], item["version"], service, path.name)
        for item in data.get("package", [])
        if item.get("source")  # the project's own crate has no source
    ]


def parse_composer_lock(path: Path, service: str) -> list[Package]:
    data = json.loads(path.read_text(encoding="utf-8"))
    result = []
    for item in (data.get("packages") or []) + (data.get("packages-dev") or []):
        version = item["version"].lstrip("vV")
        result.append(_package("Packagist", item["name"].lower(), version, service, path.name))
    return result


def parse_pom(path: Path, service: str) -> list[Package]:
    """Direct dependencies only. Properties like ${log4j.version} are resolved when defined."""
    root = ET.parse(path).getroot()

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    def child(node: ET.Element, name: str) -> str | None:
        for item in node:
            if local(item.tag) == name:
                return (item.text or "").strip()
        return None

    properties: dict[str, str] = {}
    for node in root:
        if local(node.tag) == "properties":
            properties = {local(p.tag): (p.text or "").strip() for p in node}
    for key in ("groupId", "version"):
        if (value := child(root, key)) is not None:
            properties[f"project.{key}"] = value

    def resolve(value: str | None) -> str | None:
        if value is None:
            return None
        resolved = re.sub(r"\$\{([^}]+)\}", lambda m: properties.get(m.group(1), m.group(0)), value)
        return None if "${" in resolved else resolved

    result = []
    for node in root:
        if local(node.tag) != "dependencies":
            continue
        for dep in node:
            group = resolve(child(dep, "groupId"))
            artifact = resolve(child(dep, "artifactId"))
            version = resolve(child(dep, "version"))
            if group and artifact and version and not version.startswith(("[", "(")):
                result.append(_package("Maven", f"{group}:{artifact}", version, service, path.name))
    return result


_REQUIREMENT = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)"
)


def parse_requirements(path: Path, service: str) -> list[Package]:
    result = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _REQUIREMENT.match(line.split("#", 1)[0].strip())
        if match:
            result.append(_package("PyPI", match.group(1), match.group(2), service, path.name))
    return result


PARSERS: dict[str, Callable[[Path, str], list[Package]]] = {
    "package-lock.json": parse_package_lock,
    "Cargo.lock": parse_cargo_lock,
    "composer.lock": parse_composer_lock,
    "pom.xml": parse_pom,
    "requirements.txt": parse_requirements,
}

# manifests that need a lockfile before Hedwig can read exact versions
LOCKFILE_HINTS = {
    "package.json": ("package-lock.json", "npm install --package-lock-only"),
    "Cargo.toml": ("Cargo.lock", "cargo generate-lockfile"),
    "composer.json": ("composer.lock", "composer update --no-install"),
}


def parse_service(folder: Path, service: str) -> tuple[list[Package], list[str]]:
    """Packages for one service folder, plus warnings for manifests without a lockfile."""
    packages: list[Package] = []
    warnings: list[str] = []
    for filename, parser in PARSERS.items():
        path = folder / filename
        if path.is_file():
            try:
                packages.extend(parser(path, service))
            except (ValueError, KeyError, ET.ParseError) as err:
                warnings.append(f"{service}: could not read {filename}: {err}")
    for manifest, (lockfile, command) in LOCKFILE_HINTS.items():
        if (folder / manifest).is_file() and not (folder / lockfile).is_file():
            warnings.append(f"{service}: {manifest} has no {lockfile}; run `{command}`")
    return packages, warnings
