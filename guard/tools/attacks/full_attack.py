"""Every attack in one go, for the demo.

Runs, in a visual order that builds from reconnaissance to a full breach:

1. **Scanner**: well-known paths a real bank never serves (`/wp-admin`, `/.env`, ...), probing
   for a way in. Ring 4 answers 404 until the client crosses the trap threshold.
2. **Flood**: a burst of requests from one address, past the rate limit and into a ban (ring 2).
3. **Brute force**: one address, many passwords, one username (ring 5), ending inside the decoy.
4. **Log4Shell payload**: a JNDI lookup string in a request, caught by ring 6 and logged as
   evidence for Hedwig.
5. **Distributed brute force**: hundreds of addresses, one attempt each, so no per-address
   counter trips; the Scout names the campaign and the alert level rises.
6. **Malware and ransomware**: pushed through the ticket attachment route. Ring 6 catches each
   sample, the attacker is drawn into the decoy bank, finds a planted API key and uses it, so
   the honeytoken alarm bans it and emails the PM.
7. **SOC report**: a PDF built from everything above is written and emailed with Hedwig.

Everything is simulated from loopback addresses with harmless stand-ins. The Guard must be
running, and the PM digest goes out about 30 seconds after the first takedown.

    uv run --project guard python guard/tools/attacks/full_attack.py
    uv run --project guard python guard/tools/attacks/full_attack.py --only flood,payload
    uv run --project guard python guard/tools/attacks/full_attack.py --skip distributed,malware
"""

import argparse
import shutil
import subprocess
import time
from pathlib import Path

import bruteforce
import distributed
import flood
import malware
import payload
import scanner

REPO = Path(__file__).resolve().parents[3]
STAGES = ("scanner", "flood", "bruteforce", "payload", "distributed", "malware")


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
    print("\n== 7. SOC report ==")
    done = subprocess.run(
        [*command, "soc-report", "--since", since, "--email"], cwd=bank, text=True
    )
    if done.returncode:
        print("the SOC report could not be built; run `hedwig soc-report --email` in guard/bank")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--n", type=int, default=300, help="addresses in the distributed brute force"
    )
    parser.add_argument("--user", default="demo")
    parser.add_argument("--scanner-ip", default="127.0.0.5")
    parser.add_argument("--flood-ip", default="127.0.0.4")
    parser.add_argument("--bruteforce-ip", default="127.0.0.6")
    parser.add_argument("--payload-ip", default="127.0.0.8")
    parser.add_argument("--malware-ip", default="127.0.0.7")
    parser.add_argument("--since", default="15m", help="window of the SOC report")
    parser.add_argument("--only", help="comma-separated stages to run, e.g. flood,payload")
    parser.add_argument("--skip", help="comma-separated stages to leave out")
    parser.add_argument("--no-soc-report", action="store_true")
    args = parser.parse_args()

    only = set(args.only.split(",")) if args.only else set(STAGES)
    skip = set(args.skip.split(",")) if args.skip else set()
    run = {s for s in STAGES if s in only and s not in skip}
    summary: dict[str, str] = {}

    if "scanner" in run:
        print("== 1. Scanner: probing well-known paths ==")
        hits = scanner.run(args.scanner_ip)
        summary["scanner"] = f"{sum(1 for v in hits.values() if v != 404)} path(s) not 404"
        time.sleep(2)

    if "flood" in run:
        print("\n== 2. Flood: a burst from one address ==")
        codes = flood.run(args.flood_ip)
        summary["flood"] = f"{codes.get(429, 0)} rate-limited of {sum(codes.values())}"
        time.sleep(2)

    if "bruteforce" in run:
        print("\n== 3. Brute force: one address, many passwords ==")
        attempts = bruteforce.run(args.bruteforce_ip, args.user)
        summary["bruteforce"] = f"{attempts} attempt(s)"
        time.sleep(2)

    if "payload" in run:
        print("\n== 4. Log4Shell payload ==")
        payload.run(args.payload_ip)
        summary["payload"] = "sent"
        time.sleep(2)

    if "distributed" in run:
        print("\n== 5. Distributed brute force on the login page ==")
        codes = distributed.run(args.n, args.user)
        summary["distributed"] = f"{sum(codes.values())} attempt(s) from {args.n} address(es)"
        print("the Scout should name a campaign within seconds (see the dashboard)")
        time.sleep(6)

    if "malware" in run:
        print("\n== 6. Malware and ransomware through the attachment route ==")
        malware.run(args.malware_ip)
        summary["malware"] = "samples sent; honeytoken use expected"
        time.sleep(2)

    print("\n== Summary ==")
    for stage in STAGES:
        if stage in summary:
            print(f"  {stage:<12} {summary[stage]}")

    if run:
        print(
            "\nThe Guard's PM digest goes out in about 30 seconds; "
            "any honeytoken email already did."
        )
    if not args.no_soc_report:
        time.sleep(5)  # let the last events reach Elasticsearch
        soc_report(args.since)


if __name__ == "__main__":
    main()
