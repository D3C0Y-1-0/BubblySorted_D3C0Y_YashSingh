"""Phase B3: the demo bank contract, checked offline.

These assertions cover the parts of the contract that hold without Docker or the hedwig
package: the four services exist with the right language manifests, each pins its seeded
vulnerable version, each ships a hedwig.requests.json with at least three requests, every
service's routes are listed in chakravyuha.yml, and the estate tiers in .hedwig.yml match the
plan. The live replay/respond outcomes need the running stack and the main track.
"""

import json
from pathlib import Path

import yaml

GUARD = Path(__file__).resolve().parents[1]
BANK = GUARD / "bank"

# service -> (manifest, lockfile, seeded package -> version)
SERVICES = {
    "transaction": ("pom.xml", None, {"log4j-core": "2.14.1"}),
    "account": ("Cargo.toml", "Cargo.lock", {"regex": "1.5.4"}),
    "support": ("composer.json", "composer.lock", {"phpmailer": "6.4.1"}),
    "notifications": (
        "package.json",
        "package-lock.json",
        {"lodash": "4.17.15", "jsonwebtoken": "8.5.1"},
    ),
}


def test_every_service_folder_has_its_manifest_and_requests():
    for name, (manifest, _, _) in SERVICES.items():
        folder = BANK / name
        assert (folder / manifest).is_file(), f"{name} missing {manifest}"
        requests = json.loads((folder / "hedwig.requests.json").read_text())
        assert len(requests) >= 3, f"{name} needs >= 3 replay requests"
        assert {"method", "path"} <= set(requests[0])
        assert (folder / "Dockerfile").is_file()


def test_web_home_page_is_not_a_service():
    assert (BANK / "web").is_dir() and not list((BANK / "web").glob("package.json"))


def test_each_service_pins_its_seeded_vulnerable_version():
    for name, (manifest, lockfile, seeds) in SERVICES.items():
        text = (BANK / name / (lockfile or manifest)).read_text(encoding="utf-8")
        for package, version in seeds.items():
            assert package in text, f"{name}: {package} not found"
            assert version in text, f"{name}: {package} not pinned to {version}"


def test_estate_tiers_and_allow_match_the_plan():
    config = yaml.safe_load((BANK / ".hedwig.yml").read_text(encoding="utf-8"))
    services = config["services"]
    assert set(services) == set(SERVICES)
    demo = {"open_fix_pr", "auto_merge_if_verified", "rollback", "takedown"}  # the demo policy
    expected = {
        "transaction": ("critical", demo),
        "account": ("high", demo),
        "support": ("medium", demo),
        "notifications": ("low", demo),
    }
    for name, (tier, allow) in expected.items():
        assert services[name]["tier"] == tier, f"{name} tier"
        assert set(services[name]["allow"]) == allow, f"{name} allow"
        assert (
            services[name]["language"]
            == {
                "transaction": "java",
                "account": "rust",
                "support": "php",
                "notifications": "node",
            }[name]
        )


def test_every_bank_service_is_guarded_with_a_route_list():
    config = yaml.safe_load((GUARD / "chakravyuha.yml").read_text(encoding="utf-8"))
    guarded = config["services"]
    for name in SERVICES:
        assert name in guarded, f"{name} is not behind the Guard"
        routes = guarded[name]["routes"]
        assert "GET /health" in routes
        # the guard's route list is the contract for the decoy too: it must cover the replay set
        listed = {f"{r.split()[0]} {r.split()[1]}" for r in routes}
        for request in json.loads((BANK / name / "hedwig.requests.json").read_text()):
            route = f"{request['method']} {request['path'].split('?')[0]}"
            assert route in listed, f"{name}: {route} not in the guard route list"
