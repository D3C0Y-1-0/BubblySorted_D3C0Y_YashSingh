"""The whole attack in one go, for the demo.

1. A distributed brute force on the bank's login page: hundreds of addresses, one attempt each,
   so no per-address counter trips. The Scout names the campaign and the Commander raises the
   alert level.
2. Malware and ransomware planted through the ticket attachment route by a determined attacker:
   ring 6 catches each sample, the attacker is drawn into the decoy bank (the honeypot), finds
   a planted API key there and uses it, so the honeytoken alarm bans it and emails the PM.
3. The SOC report (a PDF built from the attack's events) is written and emailed with Hedwig.

Everything is simulated from loopback addresses with harmless stand-ins. The Guard must be
running, and the PM digest goes out about 30 seconds after the first stop.

    uv run --project guard python guard/tools/attacks/full_attack.py [--n 300] [--no-soc-report]
"""

import argparse
import shutil
import subprocess
import time
from pathlib import Path

import distributed
import malware

REPO = Path(__file__).resolve().parents[3]


def hedwig_command() -> list[str]:
    """The installed `hedwig` if it has soc-report, else the one in this checkout (via uv)."""
    if shutil.which("hedwig"):
        probe = subprocess.run(["hedwig", "soc-report", "--help"], capture_output=True)
        if probe.returncode == 0:
            return ["hedwig"]
    return ["uv", "run", "--project", str(REPO), "hedwig"]


def soc_report(since: str) -> None:
    command = hedwig_command()
    bank = REPO / "guard" / "bank"
    print("\n== 3. SOC report ==")
    done = subprocess.run(
        [*command, "soc-report", "--since", since, "--email"], cwd=bank, text=True
    )
    if done.returncode:
        print("the SOC report could not be built; run `hedwig soc-report --email` in guard/bank")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--n", type=int, default=300, help="addresses in the brute force")
    parser.add_argument("--user", default="demo")
    parser.add_argument("--ip", default="127.0.0.77", help="the malware attacker's address")
    parser.add_argument("--since", default="15m", help="window of the SOC report")
    parser.add_argument("--no-soc-report", action="store_true")
    args = parser.parse_args()

    print("== 1. Distributed brute force on the login page ==")
    distributed.run(args.n, args.user)
    print("the Scout should name a campaign within seconds (see the dashboard)")
    time.sleep(6)

    print("\n== 2. Malware and ransomware through the attachment route ==")
    malware.run(args.ip)

    print("\nThe Guard's PM digest goes out in about 30 seconds; the honeytoken email already did.")
    if not args.no_soc_report:
        time.sleep(5)  # let the last events reach Elasticsearch
        soc_report(args.since)


if __name__ == "__main__":
    main()
