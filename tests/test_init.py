from hedwig import config


def test_init_discovers_folder_services_and_keeps_edits(tmp_path):
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "package.json").write_text("{}")
    (tmp_path / "docs").mkdir()  # no manifest, so not a service

    path, added, kept = config.init_project(tmp_path)
    assert path == tmp_path / ".hedwig.yml"
    assert added == ["api"] and kept == []

    text = path.read_text().replace("tier: medium", "tier: critical")
    path.write_text(text)
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "Cargo.toml").write_text("")

    _, added, kept = config.init_project(tmp_path)
    assert added == ["web"] and kept == ["api"]
    services = config.load_project(tmp_path)["services"]
    assert services["api"]["tier"] == "critical"
    assert services["web"]["language"] == "rust"
