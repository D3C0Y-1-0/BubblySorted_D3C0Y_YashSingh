"""Data models. `--json` output is `model_dump_json()` of these."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class Package(BaseModel):
    ecosystem: str  # OSV ecosystem: npm, PyPI, Maven, crates.io, Packagist
    name: str
    version: str
    service: str
    manifest: str  # lockfile or manifest the package came from, relative to the service


class Factors(BaseModel):
    exploitability: float
    impact: float
    criticality: float
    confidence: float


class Finding(BaseModel):
    id: str  # CVE if there is one, else the first advisory id
    ids: list[str]  # every advisory id and alias merged into this finding
    cves: list[str]
    summary: str
    service: str
    tier: str
    ecosystem: str
    package: str
    version: str
    manifest: str
    fixed_version: str | None  # smallest fix for this finding alone
    package_fix: str | None  # smallest single bump that clears every finding on the package
    needs_major: bool
    kev: bool
    epss: float | None
    evidence_level: int
    factors: Factors
    risk: float
    severity: str  # critical | high | medium | low
    reasoning: str


class ServiceInfo(BaseModel):
    name: str
    tier: str
    packages: int


class ScanResult(BaseModel):
    root: str
    offline: bool
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    packages: int
    raw_advisories: int
    kev_available: bool = True  # False when the CISA KEV catalog couldn't be loaded
    services: list[ServiceInfo]
    findings: list[Finding]
    warnings: list[str] = Field(default_factory=list)
