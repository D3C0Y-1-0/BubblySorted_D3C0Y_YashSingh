"""Demo: a request flood from one address, to trip ring 2 (flood) and earn a ban.

Fires requests at the bank as fast as it can from a single loopback address, no challenge
solved first (ring 2 sits ahead of ring 3). Once the per-IP token bucket is empty the Guard
answers 429; `ban_after` such answers inside `ban_window_s` (defaults: 20 within 10s) earn a
ban, so sending well past that in one burst trips both the rate limit and the ban.

    uv run --project guard python guard/tools/attacks/flood.py [--ip 127.0.0.4] [--n 150]
"""

import argparse
from concurrent.futures import ThreadPoolExecutor

from common import client


def one(args: tuple) -> int:
    ip, path = args
    with client(ip, timeout=10) as c:
        return c.get(path).status_code


def run(
    ip: str = "127.0.0.4", n: int = 150, path: str = "/transaction/", workers: int = 32
) -> dict[int, int]:
    """Fires `n` requests from one address as fast as possible. Returns status -> count."""
    jobs = [(ip, path)] * n
    with ThreadPoolExecutor(max_workers=workers) as pool:
        codes = list(pool.map(one, jobs))
    seen: dict[int, int] = {}
    for code in codes:
        seen[code] = seen.get(code, 0) + 1
    print(f"{n} requests from {ip}: {seen}")
    return seen


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ip", default="127.0.0.4")
    parser.add_argument("--n", type=int, default=150)
    parser.add_argument("--path", default="/transaction/")
    args = parser.parse_args()
    run(args.ip, args.n, args.path)
    print(f"watch {args.ip} on the dashboard: rate-limited, then banned")


if __name__ == "__main__":
    main()
