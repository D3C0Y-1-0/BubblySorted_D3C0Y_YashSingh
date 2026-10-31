"""What does a pull request introduce? Scan the base and the head and keep the difference."""

import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from hedwig import config
from hedwig.core import engine
from hedwig.core.advisories import AdvisorySource
from hedwig.core.models import Finding

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
MARKER = "<!-- hedwig-pr-check -->"
MAX_ROWS = 25


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)


def toplevel(folder: Path) -> Path:
    done = _git(folder, "rev-parse", "--show-toplevel")
    if done.returncode != 0:
        raise RuntimeError("not inside a git repository")
    return Path(done.stdout.strip())


def merge_base(repo: Path, base: str, head: str) -> str:
    done = _git(repo, "merge-base", base, head)
    return done.stdout.strip() if done.returncode == 0 else base


def rev(repo: Path, ref: str) -> str:
    done = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if done.returncode != 0:
        raise RuntimeError(f"unknown git ref '{ref}'")
    return done.stdout.strip()


def hedwig_roots(repo: Path, sha: str) -> list[str]:
    """Folders (relative to the repo) that hold a .hedwig.yml at this commit."""
    done = _git(repo, "ls-tree", "-r", "--name-only", sha)
    roots = []
    for name in done.stdout.splitlines():
        if Path(name).name == config.CONFIG_NAME:
            roots.append(Path(name).parent.as_posix())
    return sorted(roots)


@contextmanager
def checkout(repo: Path, sha: str) -> Iterator[Path]:
    """A temporary detached worktree of one commit."""
    with tempfile.TemporaryDirectory(prefix="hedwig-pr-", ignore_cleanup_errors=True) as tmp:
        folder = Path(tmp) / "tree"
        added = _git(repo, "worktree", "add", "--detach", "-q", str(folder), sha)
        if added.returncode != 0:
            raise RuntimeError(f"git worktree add failed: {added.stderr.strip()[-200:]}")
        try:
            yield folder
        finally:
            _git(repo, "worktree", "remove", "--force", str(folder))
            _git(repo, "worktree", "prune")


def _key(f: Finding) -> tuple[str, str, str, str, str]:
    return (f.service, f.ecosystem, f.package, f.version, f.id)


def _scan_at(repo: Path, sha: str, relative: str, source: AdvisorySource) -> list[Finding]:
    with checkout(repo, sha) as tree:
        folder = tree / relative if relative != "." else tree
        if not folder.is_dir():
            return []  # the folder did not exist yet at this commit
        return engine.scan(folder, source, save=False).findings


def introduced(
    repo: Path, base_sha: str, head_sha: str, source: AdvisorySource, roots: list[str] | None = None
) -> list[Finding]:
    """Findings present at head and not at base, across every Hedwig root, riskiest first."""
    chosen = roots if roots is not None else hedwig_roots(repo, head_sha)
    found: list[Finding] = []
    for relative in chosen:
        before = {_key(f) for f in _scan_at(repo, base_sha, relative, source)}
        found += [f for f in _scan_at(repo, head_sha, relative, source) if _key(f) not in before]
    return sorted(found, key=lambda f: (-f.risk, f.service, f.id))


def at_least(findings: list[Finding], severity: str) -> list[Finding]:
    floor = SEVERITY_ORDER.index(severity)
    return [f for f in findings if SEVERITY_ORDER.index(f.severity) >= floor]


def render_comment(found: list[Finding], pr: str = "", base: str = "", head: str = "") -> str:
    title = f"Hedwig scan{f' of {pr}' if pr else ''}"
    lines = [MARKER, f"### {title}", ""]
    if not found:
        lines.append("This change introduces **no new known vulnerabilities**.")
    else:
        services = sorted({f.service for f in found})
        malware = [f for f in found if f.kind == "malicious-package"]
        lines += [
            f"This change introduces **{len(found)} "
            f"{'finding' if len(found) == 1 else 'findings'}** in "
            f"{', '.join(f'`{s}`' for s in services)}.",
        ]
        if malware:
            names = ", ".join(f"`{f.package}@{f.version}`" for f in malware)
            lines += ["", f"> **MALWARE: {names} is a known malicious package.** Do not merge."]
        lines += [
            "",
            "| severity | risk | service | package | advisory | reachable | fix to |",
            "|---|---|---|---|---|---|---|",
        ]
        for f in found[:MAX_ROWS]:
            tag = {
                "malicious-package": " (MALICIOUS)",
                "typosquat": " (possible typosquat)",
                "install-script": " (dropper-like script)",
            }.get(f.kind, "")
            name = f"{f.package}@{f.version}" if f.version else f.package
            lines.append(
                f"| {f.severity} | {f.risk:.2f} | `{f.service}` | `{name}`{tag} | "
                f"{f.id} | {f.reachability} | {f.package_fix or 'none'} |"
            )
        if len(found) > MAX_ROWS:
            lines.append(f"\n...and {len(found) - MAX_ROWS} more.")
        lines += [
            "",
            "If this is merged, Hedwig's watcher takes the affected service down, fixes it"
            + (" (the malicious package is removed)" if malware else "")
            + " and brings it back up.",
        ]
    if base and head:
        lines += ["", f"<sub>compared `{base[:7]}` (base) with `{head[:7]}` (head)</sub>"]
    return "\n".join(lines) + "\n"
