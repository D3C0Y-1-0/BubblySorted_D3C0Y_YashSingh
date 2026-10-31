from typer.testing import CliRunner

from hedwig import __version__, settings
from hedwig.cli.main import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"hedwig {__version__}"


def test_config_set_and_show(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(settings, "CONFIG_PATH", tmp_path / "config.toml")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = runner.invoke(app, ["config", "set", "groq_api_key", "gsk_abcdefgh1234"])
    assert result.exit_code == 0
    shown = runner.invoke(app, ["config", "show"])
    assert "1234" in shown.output
    assert "gsk_abcdefgh1234" not in shown.output
