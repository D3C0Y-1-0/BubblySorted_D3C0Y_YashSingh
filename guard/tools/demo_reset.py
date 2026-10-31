"""Restore the demo to its seeded state.

    uv run --project guard python guard/tools/demo_reset.py

Empties every service access log, clears the Guard's persisted state (event files, honeytoken
registry; the signed-session key is kept) and, with --versions, restores the seeded dependency
manifests and lockfiles from git. In-memory traps, bans and suspicion live in the running Guard,
so restart it (or use the dashboard's release/lift-ban) to clear those.

Backed by Python so it runs on Windows without `make`; the Makefile's `demo-reset` calls it.
"""

import argparse
import subprocess
import sys
from pathlib import Path

GUARD = Path(__file__).resolve().parents[1]
BANK = GUARD / "bank"
DATA = GUARD / "data"
# git-tracked files that hold the seeded (vulnerable) versions
SEEDED = [
    "bank/transaction/pom.xml",
    "bank/account/Cargo.toml",
    "bank/account/Cargo.lock",
    "bank/support/composer.json",
    "bank/support/composer.lock",
    "bank/notifications/package.json",
    "bank/notifications/package-lock.json",
]


def empty_logs() -> int:
    count = 0
    for log in BANK.glob("*/logs/access.log"):
        log.write_text("", encoding="utf-8")
        count += 1
    return count


def clear_state() -> list[str]:
    cleared = []
    tokens = DATA / "honeytokens.jsonl"
    if tokens.exists():
        tokens.unlink()
        cleared.append(tokens.name)
    events = DATA / "events"
    if events.is_dir():
        held = 0
        for jsonl in events.glob("*.jsonl"):
            try:
                jsonl.unlink()
            except PermissionError:  # the running Guard holds today's file open on Windows
                held += 1
        cleared.append("events/*.jsonl" + (f" ({held} held by the running Guard)" if held else ""))
    return cleared


def restore_versions() -> bool:
    paths = [p for p in SEEDED if (GUARD / p).exists()]
    result = subprocess.run(
        ["git", "checkout", "--", *[str(GUARD / p) for p in paths]],
        cwd=GUARD.parent, capture_output=True, text=True,
    )  # fmt: skip
    if result.returncode != 0:
        print(f"demo-reset: could not restore versions: {result.stderr.strip()}", file=sys.stderr)
    return result.returncode == 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--versions",
        action="store_true",
        help="also git-restore the seeded dependency manifests and lockfiles",
    )
    args = parser.parse_args(argv)
    logs = empty_logs()
    cleared = clear_state()
    print(f"demo-reset: emptied {logs} access logs; cleared {', '.join(cleared) or 'no state'}")
    if args.versions and restore_versions():
        print("demo-reset: restored seeded dependency versions from git")
    print("demo-reset: restart the Guard to clear in-memory traps, bans and suspicion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
