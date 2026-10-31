"""Demo step 2: drive ring 4 (routes) and the probe scoring from one loopback address.

Requests a list of well-known paths that the bank does not serve. Ring 4 answers 404 and the
probe paths add suspicion; after enough of them the client crosses the trap threshold and the
decoy answers instead. Shows the dot on the dashboard climbing from calm to trapped.

    uv run --project guard python guard/tools/attacks/scanner.py [--ip 127.0.0.5]
"""

import argparse

from common import client

PROBE_PATHS = [
    "/.env",
    "/.git/config",
    "/wp-admin",
    "/admin",
    "/phpmyadmin",
    "/.aws/credentials",
    "/backup.zip",
    "/config.php",
    "/server-status",
    "/.ssh/id_rsa",
    "/xmlrpc.php",
    "/shell.php",
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ip", default="127.0.0.5")
    args = parser.parse_args()
    with client(args.ip) as c:
        for path in PROBE_PATHS:
            r = c.get(path)
            print(f"{path:<24} {r.status_code}")
    print(f"done; watch {args.ip} on the dashboard")


if __name__ == "__main__":
    main()
