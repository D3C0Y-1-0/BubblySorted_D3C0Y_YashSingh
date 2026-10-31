"""Shared helpers for the demo attack scripts. Every simulated attacker sends from its own
loopback address (127.0.0.2 and up), so the Guard sees a real, distinct connection address.

These scripts only ever talk to the local Guard on 127.0.0.1:8080 (override with GUARD_URL).
"""

import os
import sys
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from chakravyuha.challenge import COOKIE, solve  # noqa: E402

GUARD = os.environ.get("GUARD_URL", "http://127.0.0.1:8080")
SCRIPT_UA = {"user-agent": "python-attack/1.0"}
LOCAL = ("127.0.0.1", "localhost")

if not any(host in GUARD for host in LOCAL):
    sys.exit("attack scripts only run against the local Guard (127.0.0.1)")


def client(ip: str, timeout: float = 30) -> httpx.Client:
    """A client whose connections come from loopback address `ip`."""
    transport = httpx.HTTPTransport(local_address=ip)
    return httpx.Client(base_url=GUARD, transport=transport, timeout=timeout, headers=SCRIPT_UA)


def puzzle(ip: str) -> tuple[str, int] | None:
    with client(ip) as c:
        r = c.get("/transaction/")
    if "x-hedwig-challenge" not in r.headers:
        return None
    return r.headers["x-hedwig-challenge"], int(r.headers["x-hedwig-difficulty"])


def _solve(args: tuple[str, int]) -> str:
    return solve(*args)


def sessions(ips: list[str], workers: int | None = None) -> dict[str, str]:
    """Solve the ring 3 challenge for every IP: puzzles fetched and redeemed over many threads,
    the proof-of-work spread across processes. ip -> session cookie."""
    with ThreadPoolExecutor(max_workers=64) as net:
        fetched = list(net.map(lambda ip: (ip, puzzle(ip)), ips))
    puzzles = {ip: p for ip, p in fetched if p}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        nonces = dict(zip(puzzles, pool.map(_solve, puzzles.values()), strict=True))

    def redeem(ip: str) -> tuple[str, str | None]:
        token, _ = puzzles[ip]
        with client(ip) as c:
            r = c.post("/__hedwig/challenge", json={"token": token, "nonce": nonces[ip]})
            return ip, (r.cookies[COOKIE] if r.status_code == 200 else None)

    with ThreadPoolExecutor(max_workers=64) as net:
        return {ip: cookie for ip, cookie in net.map(redeem, puzzles) if cookie}


def with_session(ip: str) -> httpx.Client:
    """A loopback client that has solved the challenge, like a determined bot."""
    cookie = sessions([ip], workers=1).get(ip)
    c = client(ip)
    if cookie:
        c.cookies.set(COOKIE, cookie)
    return c
