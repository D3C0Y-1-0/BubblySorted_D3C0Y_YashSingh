"""Risk = exploitability x impact x asset criticality x evidence confidence, each 0 to 1."""

from dataclasses import dataclass

from hedwig.core.models import Factors

CRITICALITY = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
CONFIDENCE = {0: 0.6, 1: 0.8, 2: 0.9, 3: 0.95, 4: 1.0}
BANDS = [(0.40, "critical"), (0.25, "high"), (0.12, "medium"), (0.0, "low")]

# GHSA severity labels, used when an advisory has no CVSS vector
LABEL_SCORE = {"LOW": 0.3, "MODERATE": 0.5, "HIGH": 0.7, "CRITICAL": 0.9}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62, "P": 0.75, "A": 0.62}  # R is v3, P and A are v4
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_MAX_EXPLOITABILITY = 3.887
_MAX_IMPACT = 6.05  # the largest impact subscore CVSS v3.1 can produce (scope changed)


@dataclass
class Severity:
    """What one advisory says about severity: a CVSS vector, a label, or neither."""

    vector: str | None = None
    label: str | None = None


def parse_vector(vector: str) -> dict[str, str]:
    return dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)


def pick_severity(record: dict) -> Severity:
    """Prefer a CVSS v3 vector, then v4, then the GHSA label."""
    vectors = {s.get("type"): s.get("score") for s in record.get("severity", [])}
    vector = vectors.get("CVSS_V3") or vectors.get("CVSS_V4")
    label = (record.get("database_specific") or {}).get("severity")
    return Severity(vector=vector, label=label.upper() if label else None)


def cvss_scores(vector: str) -> tuple[float, float] | None:
    """(exploitability, impact), both normalised to 0 to 1. None if the vector is unusable."""
    m = parse_vector(vector)
    v4 = vector.startswith("CVSS:4")
    try:
        privileges = m["PR"]
        changed = m.get("S") == "C"
        pr_weight = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_weight[privileges] * _UI[m["UI"]]
        keys = ("VC", "VI", "VA") if v4 else ("C", "I", "A")
        c, i, a = (_CIA[m[key]] for key in keys)
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    return (
        min(exploitability / _MAX_EXPLOITABILITY, 1.0),
        min(max(impact, 0.0) / _MAX_IMPACT, 1.0),
    )


def exploitability_and_impact(sev: Severity) -> tuple[float, float]:
    if sev.vector and (scores := cvss_scores(sev.vector)):
        return scores
    fallback = LABEL_SCORE.get(sev.label or "", 0.5)
    return fallback, fallback


def band(risk: float) -> str:
    return next(name for floor, name in BANDS if risk >= floor)


def score(
    sev: Severity, tier: str, evidence_level: int, kev: bool, epss: float | None
) -> tuple[Factors, float, str]:
    exploitability, impact = exploitability_and_impact(sev)
    exploitability = 1.0 if kev else max(exploitability, epss or 0.0)
    factors = Factors(
        exploitability=round(exploitability, 3),
        impact=round(impact, 3),
        criticality=CRITICALITY.get(tier, CRITICALITY["medium"]),
        confidence=CONFIDENCE[evidence_level],
    )
    risk = factors.exploitability * factors.impact * factors.criticality * factors.confidence
    return factors, round(risk, 3), band(risk)


def reasoning(
    sev: Severity,
    severity: str,
    tier: str,
    kev: bool,
    epss: float | None,
    fixed: str | None,
    package_fix: str | None,
    notes: list[str] | None = None,
) -> str:
    parts: list[str] = []
    if kev:
        parts.append("actively exploited (KEV)")
    elif epss is not None and epss >= 0.1:
        parts.append(f"high exploitation probability (EPSS {epss:.0%})")
    metrics = parse_vector(sev.vector) if sev.vector else {}
    if metrics.get("AV") == "N":
        parts.append("network-exploitable")
    if metrics.get("AC") == "L" and metrics.get("PR") in ("N", None):
        parts.append("low complexity, no privileges needed")
    scores = cvss_scores(sev.vector) if sev.vector else None
    impact = scores[1] if scores else exploitability_and_impact(sev)[1]
    if impact >= 0.8:
        parts.append("high impact")
    elif impact < 0.4:
        parts.append("limited impact")
    parts.extend(notes or [])
    parts.append(f"{tier}-tier service")
    if not kev and not notes:
        parts.append("version present")
    text = f"{severity.capitalize()} because: {', '.join(parts)}."
    if fixed:
        text += f" Fixed in {fixed}"
        text += f"; bump the package to {package_fix}." if package_fix != fixed else "."
    else:
        text += " No fixed version is available."
    return text
