"""Replay the Guard's daily JSONL event files into Logstash, so nothing is lost from the record
while Logstash was down.

Run: uv run --project guard python guard/tools/backfill.py [--since 2026-10-31]
         [--logstash host:port]

Safe to run more than once: every event's `event.id` is its Elasticsearch document id, so a
replayed event overwrites itself. Lines written before events had an id get a stable one
derived from the line.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import httpx

GUARD = Path(__file__).resolve().parents[1]
EVENTS = GUARD / "data" / "events"
NDJSON = {"content-type": "application/x-ndjson"}
BATCH = 500


def lines(since: str | None):
    for path in sorted(EVENTS.glob("*.jsonl")):
        if since and path.stem < since:
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except ValueError:
                continue
            event.setdefault("event.id", hashlib.sha1(raw.encode()).hexdigest()[:20])
            yield json.dumps(event, separators=(",", ":"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--since", help="first day to replay, YYYY-MM-DD")
    parser.add_argument("--logstash", default="127.0.0.1:5000")
    args = parser.parse_args(argv)
    url = f"http://{args.logstash}/"
    sent, batch = 0, []
    try:
        with httpx.Client(timeout=30) as client:
            for line in lines(args.since):
                batch.append(line)
                if len(batch) >= BATCH:
                    client.post(
                        url, content="\n".join(batch) + "\n", headers=NDJSON
                    ).raise_for_status()
                    sent, batch = sent + len(batch), []
            if batch:
                client.post(url, content="\n".join(batch) + "\n", headers=NDJSON).raise_for_status()
                sent += len(batch)
    except httpx.HTTPError as error:
        print(f"backfill: Logstash at {url} failed ({error}); {sent} sent", file=sys.stderr)
        return 1
    print(f"backfill: replayed {sent} events into {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
