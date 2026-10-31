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


class CallSite(BaseModel):
    file: str  # relative to the service folder
    line: int
    function: str  # enclosing function, or <module>
    symbol: str  # what was called, e.g. yaml.load


class Decision(BaseModel):
    """What the policy gate does with a finding. Fixing itself arrives in Phase 3."""

    action: str  # fix | takedown | notify
    reason: str
    on_verified: str | None = None  # merge | review_pr (only when action is fix)
    on_failed: str | None = None  # takedown | failed_pr (only when action is fix)


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
    evidence_level: int  # 0 version present, 1 called, 2 KEV, 3 attack in logs, 4 compromise
    reachability: str  # called | imported | not imported
    call_sites: list[CallSite] = Field(default_factory=list)
    attacks: list[str] = Field(default_factory=list)  # attack patterns seen in the service logs
    compromise: bool = False  # a compromise marker was seen in the service logs
    decision: Decision
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


class Edit(BaseModel):
    """One search/replace edit proposed by the Fixer. `old` must occur exactly once."""

    path: str  # relative to the service folder
    old: str
    new: str


class Step(BaseModel):
    name: str  # plan | fixer | tester | run | verifier | reporter | act
    status: str  # running | ok | failed | skipped
    detail: str = ""
    at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class Run(BaseModel):
    """One pass of the fixing pipeline for one package of one service. Saved as run.json."""

    run_id: str
    service: str
    package: str
    ecosystem: str
    from_version: str
    to_version: str | None
    advisories: list[str]
    branch: str = ""
    pr_url: str = ""  # the pull request opened for this fix, if any
    verification: str = ""  # passed | failed | unavailable
    state: str = "running"  # running | verified | failed | skipped
    action: str = ""  # merged | review_pr | failed_pr | takedown | notify | none
    decision: Decision | None = None
    violations: list[str] = Field(default_factory=list)
    failed_step: str = ""
    attempts: int = 0
    steps: list[Step] = Field(default_factory=list)
    started_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    finished_at: str = ""
