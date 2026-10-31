"""Everything that touches git, subprocesses and Docker for the fixing pipeline."""

import json
import os
import shlex
import shutil
import socket
import subprocess
import time
import uuid
from contextlib import contextmanager
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

    def line(self) -> str:
        return f"{self.name}: {'pass' if self.ok else 'FAIL'}" + (
            f" ({self.detail})" if self.detail else ""
        )


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


def is_dirty(top: Path, relative: str) -> bool:
    return bool(git(top, "status", "--porcelain", "--", relative).stdout.strip())


def new_run_id(service: str) -> str:
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{service}-{uuid.uuid4().hex[:4]}"


def free_branch(top: Path, wanted: str) -> str:
    name, n = wanted, 1
    while git(top, "rev-parse", "--verify", "--quiet", f"refs/heads/{name}").returncode == 0:
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


def _sh(command: str, folder: Path, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        shlex.split(command, posix=os.name != "nt"),
        cwd=folder,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=os.name == "nt",
    )


def run_tests(folder: Path, finding: Finding, test_cmd: str) -> Check:
    """Install dependencies as locked, then run the service's test command."""
    if not test_cmd:
        return Check("tests", False, "no test_cmd for this service")
    try:
        if finding.ecosystem == "npm" and shutil.which("npm"):
            install = "npm ci --ignore-scripts --no-audit --no-fund"
            if not (folder / "package-lock.json").is_file():
                install = "npm install --ignore-scripts --no-audit --no-fund"
            done = _sh(install, folder, BUILD_TIMEOUT)
            if done.returncode != 0:
                return Check("tests", False, f"npm install failed: {done.stderr.strip()[-300:]}")
        done = _sh(test_cmd, folder, TEST_TIMEOUT)
    except FileNotFoundError as err:
        return Check("tests", False, f"cannot run `{test_cmd}`: {err}")
    except subprocess.TimeoutExpired:
        return Check("tests", False, f"`{test_cmd}` timed out")
    if done.returncode == 0:
        return Check("tests", True, test_cmd)
    return Check(
        "tests", False, f"`{test_cmd}` failed:\n{(done.stdout + done.stderr).strip()[-600:]}"
    )


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
        with (
            container(old_dir, f"{run_id}-old", port) as old,
            container(new_dir, f"{run_id}-new", port) as new,
        ):
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
