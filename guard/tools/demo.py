"""Check the local demo stack and print where everything is.

Run: uv run --project guard python guard/tools/demo.py

Checks every bank service's health through its Compose port, the Guard and its dashboard,
Elasticsearch, Logstash and Kibana, and that every port Compose publishes is bound to
127.0.0.1 only. Exits non-zero when something is down.
"""

import json
import socket
import subprocess
import sys
from pathlib import Path

import httpx

GUARD = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GUARD / "src"))

from chakravyuha import config as chakra_config  # noqa: E402

COMPOSE = GUARD / "deploy" / "docker-compose.yml"


def http_ok(url: str) -> bool:
    try:
        return httpx.get(url, timeout=3).status_code < 500
    except httpx.HTTPError:
        return False


def tcp_ok(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def published_ports() -> list[tuple[str, str, int]]:
    """(service, host ip, port) for every port Compose publishes."""
    try:
        out = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE), "ps", "--format", "json"],
            capture_output=True, text=True, timeout=30, check=True,
        ).stdout  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        items = json.loads(line)
        for item in items if isinstance(items, list) else [items]:
            for pub in item.get("Publishers") or []:
                if pub.get("PublishedPort"):
                    rows.append((item["Service"], pub.get("URL", ""), pub["PublishedPort"]))
    return rows


def main() -> int:
    settings = chakra_config.load()
    checks: list[tuple[str, bool, str]] = []
    for name, svc in settings.services.items():
        url = svc.upstream.rstrip("/") + svc.health_path
        checks.append((f"bank: {name}", http_ok(url), url))
    checks += [
        ("guard", http_ok("http://127.0.0.1:8080/__hedwig/health"), "http://127.0.0.1:8080"),
        ("dashboard", http_ok("http://127.0.0.1:8090/api/snapshot"), "http://127.0.0.1:8090"),
        ("elasticsearch", http_ok("http://127.0.0.1:9200"), "http://127.0.0.1:9200"),
        ("logstash", tcp_ok("127.0.0.1", 5000), "tcp 127.0.0.1:5000"),
        ("kibana", http_ok("http://127.0.0.1:5601/api/status"), "http://127.0.0.1:5601"),
    ]
    width = max(len(name) for name, *_ in checks)
    for name, ok, where in checks:
        print(f"  {'ok  ' if ok else 'DOWN'}  {name:<{width}}  {where}")

    ports = published_ports()
    exposed = [(svc, ip, port) for svc, ip, port in ports if ip not in ("127.0.0.1", "")]
    print(f"\n  {len(ports)} published ports, all on 127.0.0.1" if ports and not exposed else "")
    for svc, ip, port in exposed:
        print(f"  EXPOSED  {svc} is published on {ip}:{port}, not 127.0.0.1")

    print("\n  Open the bank:   http://127.0.0.1:8080   (demo / demo-pass)")
    print("  Dashboard:       http://127.0.0.1:8090")
    print("  Kibana:          http://127.0.0.1:5601/app/dashboards")
    print("  Attacks:         uv run --project guard python guard/tools/attacks/<script>.py")
    down = [name for name, ok, _ in checks if not ok]
    return 1 if down or exposed else 0


if __name__ == "__main__":
    raise SystemExit(main())
