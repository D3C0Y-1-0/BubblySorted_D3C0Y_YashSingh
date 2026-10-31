"""Scan a folder (or git repo): inventory, match, enrich, score, rank."""

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from functools import cmp_to_key
from pathlib import Path

from pydantic import ValidationError

from hedwig import config
from hedwig.core import (
    evidence,
    inventory,
    policy,
    reachability,
    score,
    supplychain,
    versions,
)
from hedwig.core.advisories import AdvisorySource, affected_entries, norm_name
from hedwig.core.code_index import CodeIndex, hinted_symbols
from hedwig.core.models import Factors, Finding, Package, ScanResult, ServiceInfo

GIT_URL = re.compile(r"^(https?://|git@|ssh://)|\.git$")
LAST_SCAN = Path(".hedwig") / "last-scan.json"


def is_git_url(target: str) -> bool:
    return bool(GIT_URL.search(target))


DEFAULT_ALLOW = ["open_fix_pr"]


@dataclass
class ServiceSpec:
    name: str
    folder: Path
    tier: str
    allow: list[str]  # what Hedwig may do on its own: open_fix_pr, auto_merge_if_verified, ...
    log_path: Path  # access log read for attack evidence
    test_cmd: str = ""  # run by the fixing pipeline; guessed per language when not set
    port: int = 3000
    health_path: str = "/health"


def _exposed_port(folder: Path) -> int | None:
    """The first port a service's Dockerfile EXPOSEs."""
    try:
        text = (folder / "Dockerfile").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    match = re.search(r"^\s*EXPOSE\s+(\d+)", text, flags=re.M | re.I)
    return int(match.group(1)) if match else None


def _spec(root: Path, name: str, folder: Path, tier: str, raw: dict | None) -> ServiceSpec:
    raw = raw or {}
    log = raw.get("log_path")
    guess = next(
        (cmd for manifest, (_, cmd) in config.MANIFESTS.items() if (folder / manifest).is_file()),
        "",
    )
    return ServiceSpec(
        name=name,
        folder=folder,
        tier=raw.get("tier", tier),
        allow=list(DEFAULT_ALLOW if raw.get("allow") is None else raw["allow"]),
        log_path=root / log if log else folder / "logs" / "access.log",
        test_cmd=raw.get("test_cmd") or guess,
        port=int(raw.get("port") or _exposed_port(folder) or 3000),
        health_path=raw.get("health_path") or "/health",
    )


def resolve_services(root: Path, default_tier: str) -> list[ServiceSpec]:
    """The services of a folder. Services are folders."""
    project = config.load_project(root)
    if project and project.get("services"):
        return [
            _spec(root, name, root / name, default_tier, raw)
            for name, raw in project["services"].items()
            if (root / name).is_dir()
        ]
    if any((root / manifest).is_file() for manifest in config.MANIFESTS):
        return [_spec(root, root.name, root, default_tier, None)]
    return [
        _spec(root, name, root / name, default_tier, None)
        for name in config.discover_services(root)
    ]


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
        "malicious": supplychain.is_malicious(group, summary),
        "fixed": _fixed_version(group, package),
        "symbols": reachability.advisory_symbols(group, lambda r: affected_entries(r, package)),
    }


def scan(root: Path, source: AdvisorySource, tier: str = "medium", save: bool = True) -> ScanResult:
    root = root.resolve()
    services = resolve_services(root, tier)
    specs = {spec.name: spec for spec in services}
    warnings: list[str] = []
    packages: list[Package] = []
    infos: list[ServiceInfo] = []
    for spec in services:
        found, notes = inventory.parse_service(spec.folder, spec.name)
        packages += found
        warnings += notes
        infos.append(ServiceInfo(name=spec.name, tier=spec.tier, packages=len(found)))
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
    kev_available = kev is not None
    kev = kev or set()
    epss = source.epss(all_cves) if all_cves else {}

    logs = {spec.name: evidence.read_log(spec.log_path) for spec in services}
    indexes = {spec.name: CodeIndex(spec.folder) for spec in services}
    findings: list[Finding] = []
    for package, package_drafts, package_fix in drafts:
        usage = indexes[package.service].usage(package)
        log = logs[package.service]
        spec = specs[package.service]
        for d in package_drafts:
            is_kev = any(c in kev for c in d["cves"])
            scores = [epss[c] for c in d["cves"] if c in epss]
            top_epss = max(scores) if scores else None
            reach = reachability.assess(usage, d["symbols"] or hinted_symbols(package))
            attacks = evidence.attacks_on(log, package.name)
            level = max(
                evidence.level(log, package.name),
                2 if is_kev else 0,
                1 if reach.state == "called" else 0,
            )
            tier_name = spec.tier
            factors, risk, severity = score.score(d["severity"], tier_name, level, is_kev, top_epss)
            malicious = d["malicious"]
            if malicious:  # malware outranks any CVSS: it is hostile code, not a mistake
                risk, severity = max(risk, 0.6), "critical"
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
                    reachability=reach.state,
                    call_sites=reach.call_sites,
                    attacks=attacks,
                    compromise=log.compromise,
                    decision=policy.decide(level, spec.allow),
                    kind="malicious-package" if malicious else "vulnerability",
                    factors=factors,
                    risk=risk,
                    severity=severity,
                    reasoning=("Known malicious package. " if malicious else "")
                    + score.reasoning(
                        d["severity"],
                        severity,
                        tier_name,
                        is_kev,
                        top_epss,
                        d["fixed"],
                        package_fix,
                        _evidence_notes(reach, attacks, log.compromise),
                    ),
                )
            )
    for spec in services:
        findings += _heuristic_findings(spec)
    findings.sort(key=lambda f: (-f.risk, f.service, f.id))
    for index in indexes.values():
        warnings += index.warnings
    result = ScanResult(
        root=str(root),
        offline=source.offline,
        packages=len(packages),
        raw_advisories=raw,
        kev_available=kev_available,
        services=infos,
        findings=findings,
        warnings=warnings + source.warnings,
    )
    if save:
        save_last(root, result)
    return result


def _heuristic_findings(spec: ServiceSpec) -> list[Finding]:
    """Typosquats and dropper-like install scripts: worth a human look, never auto-fixed."""
    flags = [
        (
            "typosquat",
            f"HEDWIG-TYPOSQUAT-{name}",
            name,
            f"{name} is one letter away from the popular package {real}: a possible typosquat",
        )
        for name, real in supplychain.typosquats(spec.folder)
    ] + [
        (
            "install-script",
            f"HEDWIG-SCRIPT-{script}",
            script,
            f"the {script} script looks like a dropper: {command[:80]}",
        )
        for script, command in supplychain.install_script_droppers(spec.folder)
    ]
    ecosystem = "PyPI" if (spec.folder / "requirements.txt").is_file() else "npm"
    manifest = "requirements.txt" if ecosystem == "PyPI" else "package.json"
    found = []
    for kind, flag_id, package, summary in flags:
        criticality = score.CRITICALITY.get(spec.tier, 0.5)
        factors = Factors(exploitability=0.6, impact=0.8, criticality=criticality, confidence=0.5)
        risk = round(factors.exploitability * factors.impact * criticality * factors.confidence, 3)
        found.append(
            Finding(
                id=flag_id,
                ids=[flag_id],
                cves=[],
                summary=summary,
                service=spec.name,
                tier=spec.tier,
                ecosystem=ecosystem,
                package=package,
                version="",
                manifest=manifest,
                fixed_version=None,
                package_fix=None,
                needs_major=False,
                kev=False,
                epss=None,
                evidence_level=0,
                reachability="imported",
                decision=policy.decide(0, spec.allow),
                kind=kind,
                factors=factors,
                risk=risk,
                severity="critical" if kind == "install-script" else "high",
                reasoning=f"Heuristic: {summary}. Review before merging; Hedwig does not fix this.",
            )
        )
    return found


def _evidence_notes(reach: reachability.Reach, attacks: list[str], compromise: bool) -> list[str]:
    notes = {
        "called": f"called in code ({reach.call_sites[0].symbol})" if reach.call_sites else "",
        "imported": "imported, but no vulnerable call found",
        "not imported": "not imported by this service's code",
    }[reach.state]
    result = [notes]
    if attacks:
        result.append(f"attack seen in logs ({', '.join(attacks)})")
    if compromise:
        result.append("signs of compromise in logs")
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
    try:
        return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
    except ValidationError:
        return None  # saved by an older version; the caller rescans
