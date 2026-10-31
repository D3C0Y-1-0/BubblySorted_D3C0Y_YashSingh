"""Demo step 4: distributed login attempts, one per loopback address, against one username.

Each address first solves the ring 3 challenge (done in parallel, like a botnet that runs a real
browser engine), then makes a single login attempt. No per-IP counter trips, because each
address tries only once. Within a few seconds the Scout names the campaign from the spread of
login failures, traps the IPs and throttles the username, and the Commander raises the level.
Use a few hundred addresses from 127.0.1.x upward.

    uv run --project guard python guard/tools/attacks/distributed.py [--n 500] [--user demo]
"""

import argparse
from concurrent.futures import ThreadPoolExecutor

from common import COOKIE, client, sessions


def ips(n: int) -> list[str]:
    # 127.0.1.1 upward, so these never collide with the single-IP scripts
    return [f"127.0.{1 + i // 250}.{1 + i % 250}" for i in range(n)]


def one_attempt(args) -> int:
    ip, cookie, user, i = args
    with client(ip, timeout=15) as c:
        if cookie:
            c.cookies.set(COOKIE, cookie)
        r = c.post("/transaction/login", json={"username": user, "password": f"pw{i}"})
        return r.status_code


def run(n: int = 500, user: str = "demo", workers: int = 32) -> dict[int, int]:
    """The attack: returns how many attempts got each status code."""
    addresses = ips(n)
    print(f"solving {len(addresses)} challenges...")
    cookies = sessions(addresses)
    jobs = [(ip, cookies.get(ip), user, i) for i, ip in enumerate(addresses)]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        codes = list(pool.map(one_attempt, jobs))
    seen: dict[int, int] = {}
    for code in codes:
        seen[code] = seen.get(code, 0) + 1
    print(f"{len(codes)} attempts from {len(jobs)} addresses: {seen}")
    return seen


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--n", type=int, default=500)
    parser.add_argument("--user", default="demo")
    parser.add_argument("--workers", type=int, default=32)
    args = parser.parse_args()
    run(args.n, args.user, args.workers)
    print("watch the Scout name the campaign within a few seconds")


if __name__ == "__main__":
    main()
