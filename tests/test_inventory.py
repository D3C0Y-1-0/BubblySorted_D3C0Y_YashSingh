import json

from hedwig.core import inventory


def _versions(packages):
    return {p.name: p.version for p in packages}


def test_fixture_lockfiles_have_the_seeded_versions(fixtures):
    projects = fixtures / "projects"
    cases = {
        "node-lodash": ("lodash", "4.17.15"),
        "cargo-regex": ("regex", "1.5.4"),
        "composer-phpmailer": ("phpmailer/phpmailer", "6.4.1"),
        "maven-log4j": ("org.apache.logging.log4j:log4j-core", "2.14.1"),
        "py-yaml": ("PyYAML", "5.3.1"),
    }
    for service, (name, version) in cases.items():
        packages, warnings = inventory.parse_service(projects / service, service)
        assert _versions(packages)[name] == version, service
        assert warnings == []


def test_cargo_lock_skips_the_project_crate(fixtures):
    packages, _ = inventory.parse_service(fixtures / "projects" / "cargo-regex", "cargo-regex")
    assert "cargo-regex" not in _versions(packages)


def test_package_lock_v1_and_nested_node_modules(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}
                }
            }
        )
    )
    packages, _ = inventory.parse_service(tmp_path, "svc")
    assert _versions(packages) == {"a": "1.0.0", "b": "2.0.0"}

    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root", "version": "1.0.0"},
                    "node_modules/a": {"version": "1.0.0"},
                    "node_modules/a/node_modules/b": {"version": "2.0.0"},
                },
            }
        )
    )
    packages, _ = inventory.parse_service(tmp_path, "svc")
    assert _versions(packages) == {"a": "1.0.0", "b": "2.0.0"}


def test_pom_resolves_properties_and_skips_unresolved(tmp_path):
    (tmp_path / "pom.xml").write_text(
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>${log4j.version}</version></dependency>
    <dependency><groupId>g</groupId><artifactId>b</artifactId><version>${missing}</version></dependency>
    <dependency><groupId>g</groupId><artifactId>c</artifactId></dependency>
  </dependencies>
</project>"""
    )
    packages, _ = inventory.parse_service(tmp_path, "svc")
    assert _versions(packages) == {"g:a": "2.14.1"}


def test_requirements_only_reads_pins(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# comment\nflask==2.0.1  # pinned\nrequests>=2.0\n-r other.txt\nPyYAML[extra]==5.3.1\n"
    )
    packages, _ = inventory.parse_service(tmp_path, "svc")
    assert _versions(packages) == {"flask": "2.0.1", "PyYAML": "5.3.1"}


def test_manifest_without_lockfile_warns(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    packages, warnings = inventory.parse_service(tmp_path, "svc")
    assert packages == []
    assert "package-lock.json" in warnings[0]
