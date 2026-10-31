"""Scan a folder (or git repo): inventory, match, enrich, score, rank."""

import re
import shutil
import subprocess
import tempfile
from functools import cmp_to_key
from pathlib import Path

from hedwig import config
from hedwig.core import inventory, score, versions
from hedwig.core.advisories import AdvisorySource, affected_entries, norm_name
from hedwig.core.models import Finding, Package, ScanResult, ServiceInfo

GIT_URL = re.compile(r"^(https?://|git@|ssh://)|\.git$")
LAST_SCAN = Path(".hedwig") / "last-scan.json"


def is_git_url(target: str) -> bool:
    return bool(GIT_URL.search(target))


def resolve_services(root: Path, default_tier: str) -> list[tuple[str, Path, str]]:
    """(name, folder, tier) for each service. Services are folders."""
    project = config.load_project(root)
    if project and project.get("services"):
        return [
            (name, root / name, (spec or {}).get("tier", default_tier))
            for name, spec in project["services"].items()
            if (root / name).is_dir()
        ]
    if any((root / manifest).is_file() for manifest in config.MANIFESTS):
        return [(root.name, root, default_tier)]
    return [(name, root / name, default_tier) for name in config.discover_services(root)]


def _groups(records: list[dict]) -> list[list[dict]]:
    """Merge records that share an id or alias (GHSA, PYSEC and RUSTSEC for one CVE)."""
    parent: dict[str, str] = {}

    def find(item: str) -> str:
        parent.setdefault(item, item)
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for record in records:
        tokens = [record["id"], *record.get("aliases", [])]
        for token in tokens[1:]:
            parent[find(token)] = find(tokens[0])
    grouped: dict[str, list[dict]] = {}
    for record in records:
        grouped.setdefault(find(record["id"]), []).append(record)
    return list(grouped.values())


def _fixed_version(records: list[dict], package: Package) -> str | None:
    """Smallest fixed version above the installed one, from ranges that contain it."""
    candidates: list[str] = []
    for record in records:
        for entry in affected_entries(record, package):
            ranges = [
                r for r in entry.get("ranges", []) if r.get("type") in ("SEMVER", "ECOSYSTEM")
            ]
            containing = [r for r in ranges if versions.in_range(package.version, r["events"])]
            for item in containing or ranges:
                candidates += versions.fixed_versions(item["events"])
    above = [v for v in candidates if versions.compare(v, package.version) > 0]
    return min(above, key=_version_key) if above else None


_version_key = cmp_to_key(versions.compare)


def _draft(group: list[dict], package: Package) -> dict:
    ids = list(dict.fromkeys(i for r in group for i in [r["id"], *r.get("aliases", [])]))
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    sevs = [score.pick_severity(r) for r in group]
    with_vector = sorted(
        (s for s in sevs if s.vector), key=lambda s: not s.vector.startswith("CVSS:3")
    )
    severity = (with_vector or [s for s in sevs if s.label] or [score.Severity()])[0]
    summary = next((r.get("summary") for r in group if r.get("summary")), "") or next(
        (r["details"].strip().splitlines()[0] for r in group if r.get("details")), ""
    )
    return {
        "id": cves[0] if cves else ids[0],
        "ids": ids,
        "cves": cves,
        "summary": summary,
        "severity": severity,
        "fixed": _fixed_version(group, package),
    }


def scan(root: Path, source: AdvisorySource, tier: str = "medium", save: bool = True) -> ScanResult:
    root = root.resolve()
    services = resolve_services(root, tier)
    warnings: list[str] = []
    packages: list[Package] = []
    infos: list[ServiceInfo] = []
    tiers: dict[str, str] = {}
    for name, folder, service_tier in services:
        found, notes = inventory.parse_service(folder, name)
        packages += found
        warnings += notes
        tiers[name] = service_tier
        infos.append(ServiceInfo(name=name, tier=service_tier, packages=len(found)))
    if not services:
        warnings.append(f"no services found in {root}; run `hedwig init` in the folder of services")

    matches = source.match(packages) if packages else {}
    raw = 0
    drafts: list[tuple[Package, list[dict], str | None]] = []
    seen: set[tuple] = set()
    for package in packages:
        key = (package.service, package.ecosystem, package.name, package.version)
        records = matches.get(
            (package.ecosystem, norm_name(package.ecosystem, package.name), package.version), []
        )
        if key in seen or not records:
            continue
        seen.add(key)
        raw += len(records)
        package_drafts = [_draft(group, package) for group in _groups(records)]
        fixes = [d["fixed"] for d in package_drafts if d["fixed"]]
        package_fix = max(fixes, key=_version_key) if fixes else None
        drafts.append((package, package_drafts, package_fix))

    all_cves = sorted({c for _, ds, _ in drafts for d in ds for c in d["cves"]})
    kev = source.kev_cves() if drafts else set()
    epss = source.epss(all_cves) if all_cves else {}

    findings: list[Finding] = []
    for package, package_drafts, package_fix in drafts:
        for d in package_drafts:
            is_kev = any(c in kev for c in d["cves"])
            scores = [epss[c] for c in d["cves"] if c in epss]
            top_epss = max(scores) if scores else None
            level = 2 if is_kev else 0
            tier_name = tiers[package.service]
            factors, risk, severity = score.score(d["severity"], tier_name, level, is_kev, top_epss)
            findings.append(
                Finding(
                    id=d["id"],
                    ids=d["ids"],
                    cves=d["cves"],
                    summary=d["summary"],
                    service=package.service,
                    tier=tier_name,
                    ecosystem=package.ecosystem,
                    package=package.name,
                    version=package.version,
                    manifest=package.manifest,
                    fixed_version=d["fixed"],
                    package_fix=package_fix,
                    needs_major=bool(
                        package_fix
                        and versions.major(package_fix) > versions.major(package.version)
                    ),
                    kev=is_kev,
                    epss=top_epss,
                    evidence_level=level,
                    factors=factors,
                    risk=risk,
                    severity=severity,
                    reasoning=score.reasoning(
                        d["severity"],
                        severity,
                        tier_name,
                        is_kev,
                        top_epss,
                        d["fixed"],
                        package_fix,
                    ),
                )
            )
    findings.sort(key=lambda f: (-f.risk, f.service, f.id))
    result = ScanResult(
        root=str(root),
        offline=source.offline,
        packages=len(packages),
        raw_advisories=raw,
        services=infos,
        findings=findings,
        warnings=warnings + source.warnings,
    )
    if save:
        save_last(root, result)
    return result


def scan_target(target: str, source: AdvisorySource, tier: str = "medium") -> ScanResult:
    """Scan a local folder or clone a git URL (shallow) into a temp folder and scan that."""
    if not is_git_url(target):
        return scan(Path(target), source, tier)
    if not shutil.which("git"):
        raise RuntimeError("git is required to scan a repository URL")
    name = re.sub(r"\.git$", "", target.rstrip("/")).rsplit("/", 1)[-1] or "repo"
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        folder = Path(tmp) / name
        done = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", target, str(folder)],
            capture_output=True,
            text=True,
        )
        if done.returncode != 0:
            raise RuntimeError(f"git clone failed: {done.stderr.strip()}")
        return scan(folder, source, tier, save=False)


def save_last(root: Path, result: ScanResult) -> None:
    path = root / LAST_SCAN
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")


def load_last(root: Path) -> ScanResult | None:
    path = root / LAST_SCAN
    if not path.is_file():
        return None
    return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
