"""Open the demo pull requests on the bank, unmerged, against the `test` branch.

    uv run python tools/demo_prs.py create [simple] [verified] [malware] [--base test] [--no-push]
    uv run python tools/demo_prs.py clean [--delete-base]

Each PR comes from its own branch, cut from the base branch in a temporary worktree, so your
checkout is never touched. The base branch (default `test`) is created from the default branch
on origin if it does not exist yet, so `main` never gets the vulnerable code.

    simple    notifications: adds minimist 1.2.0. A version jump alone fixes it.
    verified  transaction: adds a small fee-schedule feature that reads YAML with SnakeYAML 1.33
              (CVE-2022-1471) and a JUnit test. SnakeYAML 2.x changed its constructors, so after
              the bump the code does not compile until it is edited (about 15 to 20 lines), and
              the test that tries to plant an object through YAML passes only once it is fixed.
    malware   notifications: adds ua-parser-js 0.7.29, a known malicious release (hand-written
              lockfile entry, nothing installs it). Hedwig flags it and removes it.

With no names it creates `simple` and `verified`. Needs git and gh.
"""

import argparse
import json
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


def create(names: list[str], base: str, push: bool) -> None:
    default = default_branch()
    if push:
        ensure_base(base, default)
        start = f"origin/{base}"
    else:
        run(["git", "fetch", "-q", "origin", default])
        start = f"origin/{default}"
    for name in names:
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
                    done = run(
                        ["gh", "pr", "create", "--base", base, "--head", branch,
                         "--title", TITLE[name], "--body", BODY[name]
                         + "\n\nComment `/hedwig scan` to see what Hedwig finds. Do not merge "
                         "into `main`."],
                        check=False,
                    )  # fmt: skip
                    print(f"  {done.stdout.strip() or done.stderr.strip()[-150:]}")
            finally:
                run(["git", "worktree", "remove", "--force", str(tree)], check=False)
        if not push:
            print(f"  (not pushed; inspect with: git diff {start}...{branch})")


def clean(delete_base: bool, base: str) -> None:
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
        run(["git", "push", "-q", "origin", "--delete", base], check=False)
        print(f"deleted origin/{base}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["create", "clean"])
    parser.add_argument("names", nargs="*", choices=list(FOLDER))
    parser.add_argument("--base", default="test", help="branch the PRs target (default: test)")
    parser.add_argument("--no-push", action="store_true", help="make the branches only")
    parser.add_argument("--delete-base", action="store_true", help="clean: also delete the base")
    args = parser.parse_args()
    if args.command == "clean":
        clean(args.delete_base, args.base)
    else:
        create(args.names or ["simple", "verified"], args.base, push=not args.no_push)
    return 0


if __name__ == "__main__":
    sys.exit(main())
