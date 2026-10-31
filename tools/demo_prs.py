"""Open one demo pull request per bank service, each adding a package with a known advisory.

    uv run python tools/demo_prs.py create [service ...] [--no-push]
    uv run python tools/demo_prs.py clean

Each PR comes from its own branch `demo/vuln-<service>`, cut from the default branch in a
temporary worktree, so your checkout is never touched. Merging one makes `hedwig watch` take that
service down, fix it and bring it back up. The packages (each checked on osv.dev) are:

    transaction    org.apache.commons:commons-text 1.9   (GHSA-599f-7c49-w659)
    account        time 0.1.43                           (RUSTSEC-2020-0071)
    support        guzzlehttp/guzzle 6.3.0               (14 advisories)
    notifications  minimist 1.2.0                        (2 advisories)
    malware        ua-parser-js 0.7.29 into notifications (embedded malware, GHSA-pjwm-rvh2-c87w)

`malware` is not in the default set; ask for it by name. The registry has pulled that release, so
its lockfile entry is written by hand (nothing installs it): Hedwig reads it, flags it as malware
and removes it.

Needs git and gh. The lockfiles are regenerated with npm, cargo and (for PHP) a composer Docker
image; a missing tool leaves that lockfile untouched and says so.
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
PREFIX = "demo/vuln-"
SERVICES = ["transaction", "account", "support", "notifications"]
PACKAGE = {
    "malware": "ua-parser-js 0.7.29 (a known malicious release)",
    "transaction": "commons-text 1.9",
    "account": "time 0.1.43",
    "support": "guzzlehttp/guzzle 6.3.0",
    "notifications": "minimist 1.2.0",
}


def run(command: list[str], cwd: Path = REPO, check: bool = True) -> subprocess.CompletedProcess:
    done = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise SystemExit(f"`{' '.join(command[:4])}` failed: {(done.stderr or done.stdout)[-400:]}")
    return done


def maven(folder: Path) -> str:
    pom = folder / "pom.xml"
    text = pom.read_text(encoding="utf-8")
    dependency = (
        "    <dependency>\n"
        "      <groupId>org.apache.commons</groupId>\n"
        "      <artifactId>commons-text</artifactId>\n"
        "      <version>1.9</version>\n"
        "    </dependency>\n"
    )
    index = text.index("</dependencies>")
    pom.write_text(text[:index] + dependency + "  " + text[index:].lstrip(), encoding="utf-8")
    return "pom.xml has no lockfile"


def cargo(folder: Path) -> str:
    toml = folder / "Cargo.toml"
    toml.write_text(toml.read_text(encoding="utf-8").rstrip() + '\ntime = "=0.1.43"\n')
    if not shutil.which("cargo"):
        return "cargo is not installed: Cargo.lock was not updated"
    done = run(["cargo", "metadata", "--format-version", "1"], folder, check=False)
    return "" if done.returncode == 0 else f"cargo failed: {done.stderr[-200:]}"


def composer(folder: Path) -> str:
    path = folder / "composer.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("require", {})["guzzlehttp/guzzle"] = "6.3.0"
    path.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")
    if not shutil.which("docker"):
        return "docker is not installed: composer.lock was not updated"
    done = run(
        ["docker", "run", "--rm", "-v", f"{folder}:/app", "-w", "/app", "composer:2.7", "update",
         "guzzlehttp/guzzle", "--no-install", "--no-scripts", "--no-interaction",
         "--ignore-platform-reqs"],
        check=False,
    )  # fmt: skip
    return "" if done.returncode == 0 else f"composer failed: {done.stderr[-200:]}"


def npm(folder: Path) -> str:
    path = folder / "package.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["dependencies"]["minimist"] = "1.2.0"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if not shutil.which("npm"):
        return "npm is not installed: package-lock.json was not updated"
    done = run(
        ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
        folder, check=False,
    )  # fmt: skip
    return "" if done.returncode == 0 else f"npm failed: {done.stderr[-200:]}"


def malware(folder: Path) -> str:
    path = folder / "package.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["dependencies"]["ua-parser-js"] = "0.7.29"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    lock_path = folder / "package-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["packages"][""]["dependencies"]["ua-parser-js"] = "0.7.29"
    lock["packages"]["node_modules/ua-parser-js"] = {
        "version": "0.7.29",
        "resolved": "https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.29.tgz",
        "license": "MIT",
    }
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    return ""


FOLDER = {"malware": "notifications"}
EDITORS = {
    "malware": malware,
    "transaction": maven,
    "account": cargo,
    "support": composer,
    "notifications": npm,
}


def default_branch() -> str:
    done = run(["gh", "repo", "view", "--json", "defaultBranchRef"])
    return json.loads(done.stdout)["defaultBranchRef"]["name"]


def create(services: list[str], push: bool) -> None:
    base = default_branch()
    run(["git", "fetch", "-q", "origin", base])
    for service in services:
        branch = PREFIX + service
        with tempfile.TemporaryDirectory(prefix="hedwig-demo-") as tmp:
            tree = Path(tmp) / "tree"
            run(["git", "worktree", "add", "-q", "-B", branch, str(tree), f"origin/{base}"])
            try:
                folder = FOLDER.get(service, service)
                note = EDITORS[service](tree / BANK / folder)
                run(["git", "add", "-A", "--", f"{BANK}/{folder}"], tree)
                message = f"Add {PACKAGE[service]} to {service}"
                identity = ["-c", "user.name=Hedwig demo", "-c", "user.email=demo@hedwig.local"]
                run(["git", *identity, "commit", "-q", "-m", message], tree)
                print(
                    f"{service}: branch {branch} ({PACKAGE[service]})"
                    + (f"  NOTE: {note}" if note else "")
                )
                if push:
                    run(["git", "push", "-q", "--force", "origin", branch], tree)
                    body = (
                        f"Demo change: adds `{PACKAGE[service]}` to the `{service}` service, a "
                        "package with a known advisory. Comment `/hedwig scan` to see what Hedwig "
                        "finds. If this is merged anyway, `hedwig watch` takes the service down, "
                        "fixes it and brings it back up."
                    )
                    done = run(
                        ["gh", "pr", "create", "--base", base, "--head", branch, "--title",
                         f"Add {PACKAGE[service]} to {service}", "--body", body],
                        check=False,
                    )  # fmt: skip
                    print(f"  {done.stdout.strip() or done.stderr.strip()[-150:]}")
            finally:
                run(["git", "worktree", "remove", "--force", str(tree)], check=False)
        if not push:
            print(f"  (not pushed; inspect with: git diff {base}...{branch})")


def clean() -> None:
    done = run(["gh", "pr", "list", "--state", "open", "--json", "number,headRefName"])
    for pr in json.loads(done.stdout):
        if pr["headRefName"].startswith(PREFIX):
            run(["gh", "pr", "close", str(pr["number"]), "--delete-branch"], check=False)
            print(f"closed #{pr['number']} ({pr['headRefName']})")
    heads = run(["git", "ls-remote", "--heads", "origin", f"{PREFIX}*"]).stdout.splitlines()
    for line in heads:
        run(
            ["git", "push", "-q", "origin", "--delete", re.sub(r".*refs/heads/", "", line)],
            check=False,
        )
    for service in [*SERVICES, "malware"]:
        run(["git", "branch", "-D", PREFIX + service], check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["create", "clean"])
    parser.add_argument("services", nargs="*", choices=[*SERVICES, "malware"])
    parser.add_argument("--no-push", action="store_true", help="make the branches only")
    args = parser.parse_args()
    if args.command == "clean":
        clean()
    else:
        create(args.services or SERVICES, push=not args.no_push)
    return 0


if __name__ == "__main__":
    sys.exit(main())
