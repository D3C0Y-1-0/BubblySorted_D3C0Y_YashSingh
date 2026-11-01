"""Open the demo pull requests on the bank, unmerged, against one or many `test` branches.

    uv run python tools/demo_prs.py create [simple] [verified] [malware] [--base test] [--no-push]
    uv run python tools/demo_prs.py create [simple] [verified] --count 10 [--base-prefix test]
    uv run python tools/demo_prs.py status [--base-prefix test]
    uv run python tools/demo_prs.py comment <i> [--base-prefix test]
    uv run python tools/demo_prs.py merge <i> simple|verified [--base-prefix test] [--dry-run]
    uv run python tools/demo_prs.py reset <i> [simple] [verified] [--base-prefix test]
    uv run python tools/demo_prs.py clean [--delete-base] [--base test] [--base-prefix test]

Each PR comes from its own branch, cut from the default branch on origin in a temporary
worktree, so your checkout is never touched. The base branch(es) are created from the default
branch on origin if they do not exist yet, so `main` never gets the vulnerable code.

    simple    notifications: adds minimist 1.2.0. A version jump alone fixes it.
    verified  transaction: adds a small fee-schedule feature that reads YAML with SnakeYAML 1.33
              (CVE-2022-1471) and a JUnit test. SnakeYAML 2.x changed its constructors, so after
              the bump the code does not compile until it is edited (about 15 to 20 lines), and
              the test that tries to plant an object through YAML passes only once it is fixed.
    malware   notifications: adds ua-parser-js 0.7.29, a known malicious release (hand-written
              lockfile entry, nothing installs it). Hedwig flags it and removes it.

With no names, `create` and `reset` use `simple` and `verified`.

`create --count N` makes `<base-prefix>1` .. `<base-prefix>N` (default `test1`..`test10`), builds
each demo branch **once**, and opens two pull requests against every base (so 10 bases make 20
PRs) — the demo branches are identical everywhere, so one head branch can target many bases. The
plain `test` branch and its PRs are untouched unless you pass `--base test` yourself.

`status`, `comment`, `merge` and `reset` are for the demo itself: a table of what is open, posting
the bot comment, the forced merge (`gh pr merge --merge --admin`, since these branches stay
unprotected), and recreating one base and its two PRs for another run. `merge --dry-run` prints
the command instead of running it. Needs git and gh.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BANK = "guard/bank"
PREFIX = "demo/"
FILES = Path(__file__).resolve().parent / "demo_pr_files"
FOLDER = {"simple": "notifications", "verified": "transaction", "malware": "notifications"}
TITLE = {
    "simple": "Add minimist 1.2.0 to notifications",
    "verified": "Add fee schedules (SnakeYAML 1.33) to transaction",
    "malware": "Add ua-parser-js 0.7.29 (a known malicious release) to notifications",
}
BODY = {
    "simple": "Adds `minimist` 1.2.0, which has known advisories. A version bump alone fixes it.",
    "verified": (
        "Adds a small fee-schedule feature that loads YAML with SnakeYAML 1.33 (CVE-2022-1471) and "
        "a JUnit test. Fixing it needs SnakeYAML 2.x and a few code changes."
    ),
    "malware": "Adds `ua-parser-js` 0.7.29, a release known to contain embedded malware.",
}
PR_FOOTER = "\n\nComment `/hedwig scan` to see what Hedwig finds. Do not merge into `main`."


def run(command: list[str], cwd: Path = REPO, check: bool = True) -> subprocess.CompletedProcess:
    done = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise SystemExit(f"`{' '.join(command[:4])}` failed: {(done.stderr or done.stdout)[-400:]}")
    return done


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, data: dict, indent: int = 2) -> None:
    path.write_text(json.dumps(data, indent=indent) + "\n", encoding="utf-8")


def simple(folder: Path) -> None:
    data = _json(folder / "package.json")
    data["dependencies"]["minimist"] = "1.2.0"
    _write(folder / "package.json", data)
    if shutil.which("npm"):
        run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit",
             "--no-fund"], folder)  # fmt: skip


def malware(folder: Path) -> None:
    data = _json(folder / "package.json")
    data["dependencies"]["ua-parser-js"] = "0.7.29"
    _write(folder / "package.json", data)
    lock = _json(folder / "package-lock.json")
    lock["packages"][""]["dependencies"]["ua-parser-js"] = "0.7.29"
    lock["packages"]["node_modules/ua-parser-js"] = {
        "version": "0.7.29",
        "resolved": "https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.29.tgz",
        "license": "MIT",
    }
    _write(folder / "package-lock.json", lock)


def verified(folder: Path) -> None:
    pom = folder / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    dependency = (
        "    <dependency>\n"
        "      <groupId>org.yaml</groupId>\n"
        "      <artifactId>snakeyaml</artifactId>\n"
        "      <version>1.33</version>\n"
        "    </dependency>\n"
    )
    marker = "    <dependency>\n      <groupId>org.junit.jupiter</groupId>"
    pom.write_text(text.replace(marker, dependency + marker, 1), encoding="utf-8")
    for kind, root in (("main", "src/main/java"), ("test", "src/test/java")):
        target = folder / root / "bank" / "transaction" / "fees"
        target.mkdir(parents=True, exist_ok=True)
        for source in (FILES / "transaction" / kind).glob("*.java"):
            shutil.copy(source, target / source.name)


EDITORS = {"simple": simple, "verified": verified, "malware": malware}


def default_branch() -> str:
    done = run(["gh", "repo", "view", "--json", "defaultBranchRef"])
    return json.loads(done.stdout)["defaultBranchRef"]["name"]


def ensure_base(base: str, default: str) -> None:
    """Create the base branch on origin from the default branch, if it is not there."""
    run(["git", "fetch", "-q", "origin", default])
    if run(["git", "ls-remote", "--exit-code", "--heads", "origin", base], check=False).returncode:
        run(["git", "push", "-q", "origin", f"origin/{default}:refs/heads/{base}"])
        print(f"created origin/{base} from {default}")
    run(["git", "fetch", "-q", "origin", base])


def _build_branch(name: str, start: str, push: bool) -> str:
    """Builds (and, if `push`, pushes) the one branch for `name`. Returns its name."""
    branch = f"{PREFIX}{name}-{FOLDER[name]}"
    with tempfile.TemporaryDirectory(prefix="hedwig-demo-") as tmp:
        tree = Path(tmp) / "tree"
        run(["git", "worktree", "add", "-q", "-B", branch, str(tree), start])
        try:
            EDITORS[name](tree / BANK / FOLDER[name])
            run(["git", "add", "-A", "--", f"{BANK}/{FOLDER[name]}"], tree)
            identity = ["-c", "user.name=Hedwig demo", "-c", "user.email=demo@hedwig.local"]
            run(["git", *identity, "commit", "-q", "-m", TITLE[name]], tree)
            print(f"{name}: branch {branch}")
            if push:
                run(["git", "push", "-q", "--force", "origin", branch], tree)
        finally:
            run(["git", "worktree", "remove", "--force", str(tree)], check=False)
    if not push:
        print(f"  (not pushed; inspect with: git diff {start}...{branch})")
    return branch


def _open_pr(branch: str, base: str, name: str, title: str) -> None:
    done = run(
        ["gh", "pr", "create", "--base", base, "--head", branch, "--title", title,
         "--body", BODY[name] + PR_FOOTER],
        check=False,
    )
    print(f"  {base} {name}: {done.stdout.strip() or done.stderr.strip()[-150:]}")


def create(names: list[str], base: str, push: bool, count: int, base_prefix: str) -> None:
    default = default_branch()
    if count > 1:
        bases = [f"{base_prefix}{i}" for i in range(1, count + 1)]
        if push:
            for b in bases:
                ensure_base(b, default)
        start = f"origin/{default}"
        run(["git", "fetch", "-q", "origin", default])
        branches = {name: _build_branch(name, start, push) for name in names}
        if push:
            for b in bases:
                for name in names:
                    _open_pr(branches[name], b, name, f"[{b}] {TITLE[name]}")
        return

    if push:
        ensure_base(base, default)
        start = f"origin/{base}"
    else:
        run(["git", "fetch", "-q", "origin", default])
        start = f"origin/{default}"
    for name in names:
        branch = _build_branch(name, start, push)
        if push:
            _open_pr(branch, base, name, TITLE[name])


def _test_bases(prefix: str) -> list[str]:
    """Every base branch on origin that looks like `<prefix><digits>`, in order."""
    done = run(["git", "ls-remote", "--heads", "origin"], check=False)
    pattern = re.compile(rf"refs/heads/({re.escape(prefix)}(\d+))$")
    found = []
    for line in done.stdout.splitlines():
        if m := pattern.search(line):
            found.append((int(m.group(2)), m.group(1)))
    return [name for _, name in sorted(found)]


def status(base_prefix: str) -> None:
    bases = _test_bases(base_prefix)
    if not bases:
        print(f"no {base_prefix}<N> branches found; run `create --count N` first")
        return
    done = run(
        ["gh", "pr", "list", "--state", "all", "--json",
         "number,title,headRefName,baseRefName,state", "--limit", "500"],
    )  # fmt: skip
    by_base: dict[str, list[dict]] = {}
    for pr in json.loads(done.stdout):
        if pr["baseRefName"] in bases:
            by_base.setdefault(pr["baseRefName"], []).append(pr)
    for base in bases:
        rows = sorted(by_base.get(base, []), key=lambda r: r["number"])
        if not rows:
            print(f"{base}: no PRs")
            continue
        parts = ", ".join(
            f"#{r['number']} {r['headRefName'].removeprefix(PREFIX).split('-', 1)[0]}"
            f" [{r['state']}]"
            for r in rows
        )
        print(f"{base}: {parts}")


def comment(i: int, base_prefix: str) -> None:
    base = f"{base_prefix}{i}"
    done = run(
        ["gh", "pr", "list", "--base", base, "--state", "open", "--json", "number,headRefName"]
    )
    prs = json.loads(done.stdout)
    if not prs:
        print(f"no open PRs on {base}")
        return
    for pr in prs:
        run(["gh", "pr", "comment", str(pr["number"]), "--body", ":hedwig scan"])
        print(f"commented on #{pr['number']} ({pr['headRefName']})")


def merge_pr(i: int, name: str, base_prefix: str, dry_run: bool) -> None:
    base = f"{base_prefix}{i}"
    branch = f"{PREFIX}{name}-{FOLDER[name]}"
    done = run(
        ["gh", "pr", "list", "--base", base, "--head", branch, "--state", "open",
         "--json", "number"]  # fmt: skip
    )
    prs = json.loads(done.stdout)
    if not prs:
        raise SystemExit(f"no open PR for {branch} -> {base}")
    number = prs[0]["number"]
    if dry_run:
        print(f"would run: gh pr merge {number} --merge --admin   ({branch} -> {base})")
        return
    run(["gh", "pr", "merge", str(number), "--merge", "--admin"])
    print(f"merged #{number} ({branch} -> {base})")


def reset_one(i: int, names: list[str], base_prefix: str) -> None:
    """Closes base <i>'s PRs (its demo branches are shared, so they are not deleted), deletes and
    recreates the base from the default branch, and reopens the two PRs against it."""
    base = f"{base_prefix}{i}"
    done = run(
        ["gh", "pr", "list", "--base", base, "--state", "open", "--json", "number"], check=False
    )
    for pr in json.loads(done.stdout or "[]"):
        run(["gh", "pr", "close", str(pr["number"])], check=False)
        print(f"closed #{pr['number']} on {base}")
    run(["git", "push", "-q", "origin", "--delete", base], check=False)
    default = default_branch()
    ensure_base(base, default)
    for name in names:
        branch = f"{PREFIX}{name}-{FOLDER[name]}"
        _open_pr(branch, base, name, f"[{base}] {TITLE[name]}")


def clean(delete_base: bool, base: str, base_prefix: str, count: int) -> None:
    done = run(["gh", "pr", "list", "--state", "open", "--json", "number,headRefName"])
    for pr in json.loads(done.stdout):
        if pr["headRefName"].startswith(PREFIX):
            run(["gh", "pr", "close", str(pr["number"]), "--delete-branch"], check=False)
            print(f"closed #{pr['number']} ({pr['headRefName']})")
    heads = run(["git", "ls-remote", "--heads", "origin", f"{PREFIX}*"]).stdout.splitlines()
    for line in heads:
        run(["git", "push", "-q", "origin", "--delete", line.split("refs/heads/")[-1]], check=False)
    for name in FOLDER:
        run(["git", "branch", "-D", f"{PREFIX}{name}-{FOLDER[name]}"], check=False)
    if delete_base:
        explicit = [f"{base_prefix}{n}" for n in range(1, count + 1)] if count else [base]
        for b in sorted(set(explicit) | set(_test_bases(base_prefix))):
            run(["git", "push", "-q", "origin", "--delete", b], check=False)
            print(f"deleted origin/{b}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create")
    p_create.add_argument("names", nargs="*", choices=list(FOLDER))
    p_create.add_argument("--base", default="test", help="branch the PRs target (default: test)")
    p_create.add_argument("--no-push", action="store_true", help="make the branches only")
    p_create.add_argument(
        "--count", type=int, default=1, help="make <base-prefix>1..N instead of one"
    )
    p_create.add_argument("--base-prefix", default="test")

    p_clean = sub.add_parser("clean")
    p_clean.add_argument("--base", default="test")
    p_clean.add_argument(
        "--delete-base", action="store_true", help="also delete the base branch(es)"
    )
    p_clean.add_argument("--base-prefix", default="test")
    p_clean.add_argument(
        "--count", type=int, default=0, help="with --delete-base: also <prefix>1..N"
    )

    p_status = sub.add_parser("status")
    p_status.add_argument("--base-prefix", default="test")

    p_comment = sub.add_parser("comment")
    p_comment.add_argument("i", type=int)
    p_comment.add_argument("--base-prefix", default="test")

    p_merge = sub.add_parser("merge")
    p_merge.add_argument("i", type=int)
    p_merge.add_argument("name", choices=["simple", "verified", "malware"])
    p_merge.add_argument("--base-prefix", default="test")
    p_merge.add_argument("--dry-run", action="store_true")

    p_reset = sub.add_parser("reset")
    p_reset.add_argument("i", type=int)
    p_reset.add_argument("names", nargs="*", choices=list(FOLDER))
    p_reset.add_argument("--base-prefix", default="test")

    args = parser.parse_args()
    if args.command == "clean":
        clean(args.delete_base, args.base, args.base_prefix, args.count)
    elif args.command == "status":
        status(args.base_prefix)
    elif args.command == "comment":
        comment(args.i, args.base_prefix)
    elif args.command == "merge":
        merge_pr(args.i, args.name, args.base_prefix, args.dry_run)
    elif args.command == "reset":
        reset_one(args.i, args.names or ["simple", "verified"], args.base_prefix)
    else:
        create(args.names or ["simple", "verified"], args.base, push=not args.no_push,
               count=args.count, base_prefix=args.base_prefix)  # fmt: skip
    return 0


if __name__ == "__main__":
    sys.exit(main())
