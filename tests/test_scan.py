import json

from hedwig.core import engine, versions
from hedwig.core.advisories import AdvisorySource


def _scan(fixtures, folder="projects"):
    source = AdvisorySource(offline=True, directory=fixtures / "advisories")
    return engine.scan(fixtures / folder, source, save=False)


def _projection(result):
    rows = [
        {
            "service": f.service,
            "package": f.package,
            "version": f.version,
            "id": f.id,
            "cves": f.cves,
            "fixed_version": f.fixed_version,
            "package_fix": f.package_fix,
            "kev": f.kev,
            "severity": f.severity,
        }
        for f in result.findings
    ]
    return sorted(rows, key=lambda r: (r["service"], r["id"]))


def _find(result, service, cve):
    return next(f for f in result.findings if f.service == service and cve in f.cves)


def test_matches_expected_results(fixtures):
    expected = json.loads((fixtures / "expected" / "scan-offline.json").read_text())
    assert _projection(_scan(fixtures)) == expected


def test_log4shell(fixtures):
    finding = _find(_scan(fixtures), "maven-log4j", "CVE-2021-44228")
    assert finding.fixed_version == "2.15.0"
    # later advisories need a higher bump than Log4Shell's own fix
    assert versions.compare(finding.package_fix, finding.fixed_version) > 0
    assert finding.kev and finding.severity == "critical"
    assert "actively exploited (KEV)" in finding.reasoning


def test_known_fixes(fixtures):
    result = _scan(fixtures)
    assert _find(result, "cargo-regex", "CVE-2022-24713").fixed_version == "1.5.5"
    assert _find(result, "composer-phpmailer", "CVE-2021-34551").fixed_version == "6.5.0"
    assert _find(result, "composer-phpmailer", "CVE-2021-3603").fixed_version == "6.5.0"
    assert _find(result, "node-lodash", "CVE-2020-8203").fixed_version == "4.17.19"


def test_aliases_merge_into_one_finding(fixtures):
    result = _scan(fixtures)
    pyyaml = [f for f in result.findings if f.service == "py-yaml"]
    assert len(pyyaml) == 1
    assert {"GHSA-8q59-q68h-6hv4", "PYSEC-2021-142", "CVE-2020-14343"} <= set(pyyaml[0].ids)
    assert result.raw_advisories > len(result.findings)


def test_findings_are_ranked_by_risk(fixtures):
    risks = [f.risk for f in _scan(fixtures).findings]
    assert risks == sorted(risks, reverse=True)


def test_missing_advisory_data_is_reported(tmp_path, fixtures):
    import pytest

    from hedwig.core.advisories import AdvisoryUnavailable

    source = AdvisorySource(offline=True, directory=tmp_path / "nothing")
    with pytest.raises(AdvisoryUnavailable):
        engine.scan(fixtures / "projects", source, save=False)
