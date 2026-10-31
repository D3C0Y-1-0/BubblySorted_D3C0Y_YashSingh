import json
import shlex
import shutil

import pytest

from hedwig.cli import shell


@pytest.fixture
def session(tmp_path, fixtures, monkeypatch):
    shutil.copytree(fixtures / "projects" / "node-lodash", tmp_path / "node-lodash")
    monkeypatch.chdir(tmp_path)  # status and explain work on the folder the app runs in
    return shell.Session(tmp_path)


@pytest.fixture
def offline(fixtures) -> str:
    return f"--offline --advisories {shlex.quote(str(fixtures / 'advisories'))}"


def test_commands_are_in_the_menu():
    for name in ("/scan", "/status", "/explain"):
        assert name in shell.COMMANDS


def test_scan_runs_in_the_app(session, offline, capsys):
    shell.handle(session, f"/scan {offline} --json")
    data = json.loads(capsys.readouterr().out)
    assert {f["service"] for f in data["findings"]} == {"node-lodash"}


def test_scan_accepts_a_path(session, offline, capsys, tmp_path):
    shell.handle(session, f"/scan {tmp_path} {offline} --json")
    assert json.loads(capsys.readouterr().out)["findings"]


def test_status_and_explain_use_the_last_scan(session, offline, capsys):
    shell.handle(session, f"/status {offline} --json")
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["service"] == "node-lodash"

    shell.handle(session, f"/explain CVE-2020-8203 {offline} --json")
    found = json.loads(capsys.readouterr().out)
    assert found[0]["fixed_version"] == "4.17.19"


def test_explain_unknown_id_does_not_end_the_session(session, offline, capsys):
    shell.handle(session, f"/explain CVE-0000-0000 {offline}")
    assert "not a finding" in capsys.readouterr().out
    assert session.running


def test_bad_arguments_print_usage(session, capsys):
    shell.handle(session, "/scan --bogus")
    assert "unknown option" in capsys.readouterr().out
    shell.handle(session, "/explain")
    assert "Usage: /explain" in capsys.readouterr().out
    shell.handle(session, "/scan --advisories")
    assert "needs a value" in capsys.readouterr().out


def test_split_args_keeps_windows_backslashes():
    line = r"/scan C:\Users\me\shop --json"
    assert shell.split_args(line, windows=True) == ["/scan", r"C:\Users\me\shop", "--json"]
    quoted = r'/scan "C:\My Projects\shop"'
    assert shell.split_args(quoted, windows=True) == ["/scan", r"C:\My Projects\shop"]
    assert shell.split_args("/scan 'a b' --json", windows=False) == ["/scan", "a b", "--json"]
