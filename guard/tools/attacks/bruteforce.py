"""Demo step 3: single-IP login attempts against one username, to trip ring 5.

Solves the ring 3 challenge once (like a determined bot), then tries a list of passwords on
/transaction/login. Each failure is answered more slowly (progressive back-off); after the
threshold ring 5 trips and the client is drawn into the decoy. A few attempts later one
"succeeds" inside the maze, so it looks like the attacker finally guessed right.

    uv run --project guard python guard/tools/attacks/bruteforce.py [--ip 127.0.0.6] [--n 500]
"""

import argparse

from common import with_session


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ip", default="127.0.0.6")
    parser.add_argument("--user", default="demo")
    parser.add_argument("--n", type=int, default=500)
    args = parser.parse_args()
    c = with_session(args.ip)
    try:
        for i in range(args.n):
            body = {"username": args.user, "password": f"guess-{i:04d}"}
            r = c.post("/transaction/login", json=body)
            if i < 12 or r.status_code == 200:
                print(f"attempt {i:>3}: {r.status_code}")
            if r.status_code == 200:
                print(f"'succeeded' at attempt {i} (inside the decoy)")
                break
    finally:
        c.close()


if __name__ == "__main__":
    main()
