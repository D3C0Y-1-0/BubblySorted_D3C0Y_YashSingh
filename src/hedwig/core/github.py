"""GitHub through the logged-in `gh` CLI: push a branch and open a pull request.

Works from any git repository whose `origin` is on github.com (https or ssh). Every `gh` call
names the repository explicitly, so nothing depends on `gh repo set-default` or on a terminal.
"""

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

TIMEOUT = 90
LABELS = {
    "hedwig:needs-review": ("0e8a16", "Hedwig fix, verified, waiting for a human"),
    "hedwig:unverified": ("fbca04", "Hedwig fix; verification could not run"),
    "hedwig:verification-failed": ("d93f0b", "Hedwig fix; verification ran and failed"),
}
SLUG = re.compile(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?\s*$")


class GitHubError(Exception):
    pass


@dataclass
class PullRequest:
    url: str
    number: int


def _run(cwd: Path, command: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1"}
    try:
        return subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT, env=env
        )
    except subprocess.TimeoutExpired as err:
        raise GitHubError(f"`{' '.join(command[:3])}` timed out") from err


def _origin_url(cwd: Path) -> str:
    done = _run(cwd, ["git", "config", "--get", "remote.origin.url"])
    return done.stdout.strip() if done.returncode == 0 else ""


def origin_slug(cwd: Path) -> str | None:
    """owner/repo of origin when it is on github.com, in https or ssh form."""
    match = SLUG.search(_origin_url(cwd))
    return f"{match.group(1)}/{match.group(2)}" if match else None


def unavailable(cwd: Path) -> str | None:
    """Why a PR cannot be opened from this folder, or None when it can."""
    if not shutil.which("gh"):
        return "the GitHub CLI (gh) is not installed (https://cli.github.com)"
    if _run(cwd, ["gh", "auth", "status"]).returncode != 0:
        return "gh is not logged in (run: gh auth login)"
    url = _origin_url(cwd)
    if not url:
        return "this repository has no 'origin' remote (git remote add origin <url>)"
    if origin_slug(cwd) is None:
        return f"origin is not on GitHub ({url})"
    return None


def default_branch(cwd: Path, slug: str) -> str:
    done = _run(cwd, ["gh", "repo", "view", slug, "--json", "defaultBranchRef"])
    if done.returncode != 0:
        raise GitHubError(
            f"could not read {slug} (does your gh account have access?): "
            f"{done.stderr.strip()[-200:]}"
        )
    return json.loads(done.stdout)["defaultBranchRef"]["name"]


def pick_base(cwd: Path, slug: str) -> str:
    """The branch the PR targets: the branch you are on if origin has it, else the default."""
    current = _run(cwd, ["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    if current and current != "HEAD":
        on_origin = _run(cwd, ["git", "ls-remote", "--heads", "origin", current])
        if on_origin.returncode == 0 and on_origin.stdout.strip():
            return current
    return default_branch(cwd, slug)


def ensure_label(cwd: Path, slug: str, name: str) -> None:
    color, description = LABELS.get(name, ("ededed", ""))
    _run(cwd, ["gh", "label", "create", name, "-R", slug, "--force", "--color", color,
               "-d", description])  # fmt: skip


def push(cwd: Path, branch: str) -> None:
    command = ["git"]
    if _origin_url(cwd).startswith("https://"):
        # use gh's login for https remotes, so no password prompt can appear
        command += [
            "-c", "credential.https://github.com.helper=",
            "-c", "credential.https://github.com.helper=!gh auth git-credential",
        ]  # fmt: skip
    done = _run(cwd, [*command, "push", "--set-upstream", "origin", branch])
    if done.returncode != 0:
        raise GitHubError(
            f"git push failed (do you have push access to origin?): {done.stderr.strip()[-300:]}"
        )


def _ahead(cwd: Path, base: str, branch: str) -> int:
    _run(cwd, ["git", "fetch", "origin", base])
    done = _run(cwd, ["git", "rev-list", "--count", f"origin/{base}..{branch}"])
    return int(done.stdout.strip()) if done.returncode == 0 and done.stdout.strip() else 0


def create_pr(
    cwd: Path, branch: str, title: str, body: str, label: str, draft: bool
) -> PullRequest:
    """Push the branch and open a PR (or return the one that already exists)."""
    slug = origin_slug(cwd)
    if slug is None:
        raise GitHubError("origin is not on GitHub")
    base = pick_base(cwd, slug)
    push(cwd, branch)
    extra = _ahead(cwd, base, branch) - 1  # the fix commit itself is expected
    if extra > 0:
        body += f"\n\n> This branch also carries {extra} local commit(s) that are not on `{base}`."
    ensure_label(cwd, slug, label)
    command = [
        "gh", "pr", "create", "-R", slug, "--base", base, "--head", branch,
        "--title", title, "--body", body,
    ]  # fmt: skip
    if draft:
        command.append("--draft")
    done = _run(cwd, [*command, "--label", label])
    if done.returncode != 0 and "label" in done.stderr.lower():
        done = _run(cwd, command)  # no permission to label: open it without
    if done.returncode != 0:
        existing = _run(cwd, ["gh", "pr", "view", branch, "-R", slug, "--json", "url,number"])
        if existing.returncode == 0:
            data = json.loads(existing.stdout)
            return PullRequest(data["url"], data["number"])
        raise GitHubError(f"gh pr create failed: {done.stderr.strip()[-300:]}")
    url = done.stdout.strip().splitlines()[-1]
    return PullRequest(url, int(url.rstrip("/").rsplit("/", 1)[-1]))
