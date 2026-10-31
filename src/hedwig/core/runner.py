"""Everything that touches git, subprocesses and Docker for the fixing pipeline."""

import json
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx

from hedwig.core.models import Finding

TEST_TIMEOUT = 600
BUILD_TIMEOUT = 900
HEALTH_WAIT = 60
REQUEST_TIMEOUT = 10
BOT = ["-c", "user.name=Hedwig", "-c", "user.email=hedwig@users.noreply.github.com"]


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    ran: bool = True  # False when the check had nothing to run (it passes, but proves nothing)

    def line(self) -> str:
        verdict = "pass" if self.ok else "FAIL"
        if not self.ran:
            verdict = "skipped"
        return f"{self.name}: {verdict}" + (f" ({self.detail})" if self.detail else "")


def git(cwd: Path, *args: str, check: bool = False) -> subprocess.CompletedProcess:
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {done.stderr.strip()}")
    return done


def toplevel(folder: Path) -> Path | None:
    if not shutil.which("git"):
        return None
    done = git(folder, "rev-parse", "--show-toplevel")
    return Path(done.stdout.strip()) if done.returncode == 0 else None


def has_commits(top: Path) -> bool:
    return git(top, "rev-parse", "--verify", "--quiet", "HEAD").returncode == 0


def hide_state_dir(top: Path, root: Path) -> None:
    """Keep Hedwig's .hedwig/ folder out of `git status` without touching the repo's files."""
    exclude = git(top, "rev-parse", "--git-path", "info/exclude").stdout.strip()
    if not exclude:
        return
    path = (top / exclude) if not Path(exclude).is_absolute() else Path(exclude)
    relative = root.resolve().relative_to(top).as_posix()
    line = f"/{relative}/.hedwig/" if relative != "." else "/.hedwig/"
    try:
        existing = path.read_text(encoding="utf-8") if path.is_file() else ""
        if line not in existing.splitlines():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                existing + ("" if existing.endswith("\n") or not existing else "\n") + line + "\n",
                encoding="utf-8",
            )
    except OSError:
        pass


def is_dirty(top: Path, relative: str) -> bool:
    return bool(git(top, "status", "--porcelain", "--", relative).stdout.strip())


def new_run_id(service: str) -> str:
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{service}-{uuid.uuid4().hex[:4]}"


def _on_origin(top: Path, name: str) -> bool:
    try:
        done = subprocess.run(
            ["git", "ls-remote", "--exit-code", "--heads", "origin", name],
            cwd=top, capture_output=True, text=True, timeout=20,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )  # fmt: skip
    except (subprocess.TimeoutExpired, OSError):
        return False
    return done.returncode == 0


def free_branch(top: Path, wanted: str) -> str:
    """A branch name used neither locally nor on origin, so the push can never collide."""
    name, n = wanted, 1
    while git(
        top, "rev-parse", "--verify", "--quiet", f"refs/heads/{name}"
    ).returncode == 0 or _on_origin(top, name):
        n += 1
        name = f"{wanted}-{n}"
    return name


def add_worktree(top: Path, path: Path, branch: str | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if branch:
        git(top, "worktree", "add", "-q", "-b", branch, str(path), "HEAD", check=True)
    else:
        git(top, "worktree", "add", "-q", "--detach", str(path), "HEAD", check=True)


def remove_worktree(top: Path, path: Path) -> None:
    git(top, "worktree", "remove", "--force", str(path))
    shutil.rmtree(path, ignore_errors=True)
    git(top, "worktree", "prune")


def reset_service(top: Path, worktree: Path, relative: str) -> None:
    """Back to the committed state of the service folder, for a retry."""
    git(worktree, "checkout", "-q", "--", relative)
    git(worktree, "clean", "-fdq", "--", relative)


def commit(worktree: Path, paths: list[str], message: str) -> None:
    git(worktree, "add", "--", *paths, check=True)
    git(worktree, *BOT, "commit", "-q", "-m", message, check=True)


def diff_text(worktree: Path, relative: str, paths: list[str] | None = None) -> str:
    args = ["diff", "--", *(paths or [relative])]
    return git(worktree, *args).stdout


def diff_stat(worktree: Path, relative: str) -> str:
    return git(worktree, "diff", "--stat", "--", relative).stdout.strip()


def _sh(
    command: str, folder: Path, timeout: int, env: dict | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        shlex.split(command, posix=os.name != "nt"),
        cwd=folder,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=os.name == "nt",
        env=env,
    )


PYTEST_NO_TESTS = 5  # pytest's exit code when it collected nothing
REQUIREMENT_FILES = ("requirements.txt", "requirements-dev.txt", "requirements-test.txt")


def _python_env(folder: Path, venv: Path) -> tuple[dict | None, str]:
    """Create a venv outside the service folder and install its requirements into it.

    Returns the environment to run tests in, or (None, error).
    """
    python = shutil.which("python3") or shutil.which("python")
    if not python:
        return None, "python is not installed"
    made = subprocess.run([python, "-m", "venv", str(venv)], capture_output=True, text=True)
    if made.returncode != 0:
        return None, f"could not create a virtualenv: {made.stderr.strip()[-300:]}"
    bin_dir = venv / ("Scripts" if os.name == "nt" else "bin")
    pip = [str(bin_dir / "python"), "-m", "pip", "install", "-q", "--disable-pip-version-check"]
    files = [name for name in REQUIREMENT_FILES if (folder / name).is_file()]
    for name in files:
        done = subprocess.run(
            [*pip, "-r", name], cwd=folder, capture_output=True, text=True, timeout=BUILD_TIMEOUT
        )
        if done.returncode != 0:
            return None, f"pip install -r {name} failed: {done.stderr.strip()[-400:]}"
    probe = subprocess.run(
        [str(bin_dir / "python"), "-c", "import pytest"], capture_output=True, text=True
    )
    if probe.returncode != 0:
        subprocess.run([*pip, "pytest"], capture_output=True, text=True, timeout=BUILD_TIMEOUT)
    env = {
        **os.environ,
        "VIRTUAL_ENV": str(venv),
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
    }
    return env, ""


def _npm_scripts(folder: Path) -> dict:
    try:
        return json.loads((folder / "package.json").read_text(encoding="utf-8")).get("scripts", {})
    except (OSError, json.JSONDecodeError):
        return {}


def run_tests(folder: Path, finding: Finding, test_cmd: str) -> Check:
    """Install dependencies as locked, then run the service's tests.

    A Node service without a test script is built instead. A service with neither has nothing
    to run, which passes but does not count as verification.
    """
    name = "tests"
    if finding.ecosystem == "npm":
        scripts = _npm_scripts(folder)
        if "test" not in scripts:
            if "build" not in scripts:
                return Check(
                    "tests", True, "the service defines no test or build script", ran=False
                )
            name, test_cmd = "build", "npm run build"
    if not test_cmd:
        return Check(name, False, "no test_cmd for this service")
    if finding.ecosystem == "PyPI":
        with tempfile.TemporaryDirectory(prefix="hedwig-venv-", ignore_cleanup_errors=True) as tmp:
            env, error = _python_env(folder, Path(tmp) / "venv")
            if env is None:
                return Check(name, False, error)
            return _run_command(name, folder, test_cmd, env)
    try:
        if finding.ecosystem == "npm" and shutil.which("npm"):
            install = "npm ci --ignore-scripts --no-audit --no-fund"
            if not (folder / "package-lock.json").is_file():
                install = "npm install --ignore-scripts --no-audit --no-fund"
            done = _sh(install, folder, BUILD_TIMEOUT)
            if done.returncode != 0:
                return Check(name, False, f"npm install failed: {done.stderr.strip()[-300:]}")
    except FileNotFoundError as err:
        return Check(name, False, f"cannot run `{test_cmd}`: {err}")
    except subprocess.TimeoutExpired:
        return Check(name, False, f"`{test_cmd}` timed out")
    return _run_command(name, folder, test_cmd)


def _run_command(name: str, folder: Path, command: str, env: dict | None = None) -> Check:
    try:
        done = _sh(command, folder, TEST_TIMEOUT, env)
    except FileNotFoundError as err:
        return Check(name, False, f"cannot run `{command}`: {err}")
    except subprocess.TimeoutExpired:
        return Check(name, False, f"`{command}` timed out")
    if done.returncode == 0:
        return Check(name, True, command)
    if done.returncode == PYTEST_NO_TESTS and "pytest" in command:
        return Check(name, True, "the service has no tests", ran=False)
    return Check(name, False, f"`{command}` failed:\n{(done.stdout + done.stderr).strip()[-600:]}")


def docker_ready(folder: Path) -> str | None:
    if not shutil.which("docker"):
        return "docker is not installed, so the old-vs-new comparison cannot run"
    if not (folder / "Dockerfile").is_file():
        return "the service has no Dockerfile, so the old-vs-new comparison cannot run"
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        return "the docker daemon is not running"
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def container(folder: Path, tag: str, port: int):
    """Build the service image, run it on a free local port and always clean up."""
    host_port = _free_port()
    name = f"hedwig-{tag}"
    try:
        built = subprocess.run(
            ["docker", "build", "-q", "-t", name, str(folder)],
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT,
        )
        if built.returncode != 0:
            raise RuntimeError(f"docker build failed: {built.stderr.strip()[-400:]}")
        started = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "-p",
                f"127.0.0.1:{host_port}:{port}",
                name,
            ],
            capture_output=True,
            text=True,
        )
        if started.returncode != 0:
            raise RuntimeError(f"docker run failed: {started.stderr.strip()[-400:]}")
        yield f"http://127.0.0.1:{host_port}"
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        subprocess.run(["docker", "rmi", "-f", name], capture_output=True)


def wait_healthy(base: str, path: str) -> bool:
    deadline = time.monotonic() + HEALTH_WAIT
    while time.monotonic() < deadline:
        try:
            if httpx.get(base + path, timeout=2).status_code < 500:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(1)
    return False


def _send(base: str, request: dict) -> tuple[int | None, list[str] | None]:
    """Status code and top-level JSON keys of one response (None status = no answer)."""
    try:
        response = httpx.request(
            request.get("method", "GET").upper(),
            base + request["path"],
            json=request.get("body"),
            headers=request.get("headers") or {},
            timeout=REQUEST_TIMEOUT,
        )
    except httpx.HTTPError:
        return None, None
    try:
        data = response.json()
    except ValueError:
        return response.status_code, None
    return response.status_code, sorted(data) if isinstance(data, dict) else None


def differential(
    old_dir: Path, new_dir: Path, run_id: str, port: int, health: str, requests: list[dict]
) -> tuple[Check, list[dict]]:
    """Replay the same requests on the old and new build. Returns the check and the kept cases.

    A case that gets no answer or a 5xx from the old build says nothing about the fix, so it is
    dropped.
    """
    kept: list[dict] = []
    dropped = 0
    mismatches: list[str] = []
    try:
        with ExitStack() as stack:
            try:
                old = stack.enter_context(container(old_dir, f"{run_id}-old", port))
            except RuntimeError as err:
                old, old_error = None, str(err)
            new = stack.enter_context(container(new_dir, f"{run_id}-new", port))
            if old is None:
                # The merged code may not build any more (for example a malicious package was
                # pulled from the registry). Nothing to compare with, so the new build alone
                # has to come up healthy.
                if not wait_healthy(new, health):
                    return Check("differential", False, "the new build never became healthy"), []
                note = (
                    f"the old build could not be built ({old_error[:100]}); the new one is healthy"
                )
                return Check("differential", True, note), []
            for label, base in (("old", old), ("new", new)):
                if not wait_healthy(base, health):
                    return Check(
                        "differential", False, f"the {label} build never became healthy"
                    ), []
            for request in requests:
                before = _send(old, request)
                if before[0] is None or before[0] >= 500:
                    dropped += 1
                    continue
                kept.append(request)
                after = _send(new, request)
                if after != before:
                    where = f"{request.get('method', 'GET')} {request['path']}"
                    mismatches.append(f"{where}: old {before}, new {after}")
    except (RuntimeError, subprocess.TimeoutExpired) as err:
        return Check("differential", False, str(err)), []
    if mismatches:
        return Check("differential", False, "; ".join(mismatches)), kept
    if not kept:
        return Check("differential", False, "no request could be compared (all dropped)"), kept
    note = f"{len(kept)} requests identical" + (f", {dropped} dropped" if dropped else "")
    return Check("differential", True, note), kept


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
