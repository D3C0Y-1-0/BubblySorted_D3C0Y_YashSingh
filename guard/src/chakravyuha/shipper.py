"""Ships events to Logstash from a background thread, as newline-delimited JSON over HTTP.

A slow or stopped Logstash never delays a request: `put` only appends to a bounded queue. The
queue holds 10,000 events and drops the oldest when full; drops are counted and shown on the
dashboard. Each batch is acknowledged by Logstash's `http` input (200), and put back in the
queue otherwise. Plain TCP could not tell: Docker Desktop's port proxy accepts connections and
discards the data while Logstash is down. The daily JSONL files keep everything, and
`guard/tools/backfill.py` replays them.
"""

import json
import threading
import time
from collections import deque
from typing import Any

import httpx

QUEUE_SIZE = 10_000
BATCH = 500
NDJSON = {"content-type": "application/x-ndjson"}


def logstash_url(address: str) -> str:
    return address if address.startswith("http") else f"http://{address}/"


class Shipper:
    def __init__(self, address: str, *, queue_size: int = QUEUE_SIZE, timeout: float = 2.0):
        self.url = logstash_url(address)
        self.queue: deque[str] = deque(maxlen=queue_size)
        self.timeout = timeout
        self.dropped = 0
        self.sent = 0
        self.connected = False  # the last batch was acknowledged
        self.in_flight = 0  # events in the batch being posted right now
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="chakravyuha-shipper", daemon=True)

    @property
    def healthy(self) -> bool:
        """Logstash is taking events, or there is nothing to send."""
        return self.connected or not (self.queue or self.in_flight)

    def start(self) -> "Shipper":
        self._thread.start()
        return self

    def put(self, event: dict[str, Any]) -> None:
        """Called inline for every event: must stay cheap and never block."""
        if len(self.queue) == self.queue.maxlen:
            self.dropped += 1  # the deque drops the oldest
        self.queue.append(json.dumps(event, separators=(",", ":"), default=str))
        self._wake.set()

    def close(self, flush_s: float = 1.0) -> None:
        deadline = time.monotonic() + flush_s
        while self.queue and self.connected and time.monotonic() < deadline:
            time.sleep(0.05)
        self._stop.set()
        self._wake.set()
        if self._thread.is_alive():
            self._thread.join(timeout=self.timeout + 1)

    def _requeue(self, batch: list[str]) -> None:
        """Put a failed batch back, oldest first, unless that would push out newer events."""
        for line in reversed(batch):
            if len(self.queue) < (self.queue.maxlen or QUEUE_SIZE):
                self.queue.appendleft(line)
            else:
                self.dropped += 1

    def _run(self) -> None:
        backoff = 0.5
        with httpx.Client(timeout=self.timeout) as client:
            while not self._stop.is_set():
                if not self.queue:
                    self._wake.wait(1.0)
                    self._wake.clear()
                    continue
                batch = []
                while self.queue and len(batch) < BATCH:
                    batch.append(self.queue.popleft())
                self.in_flight = len(batch)
                try:
                    response = client.post(
                        self.url, content="\n".join(batch) + "\n", headers=NDJSON
                    )
                    ok = response.status_code == 200
                except httpx.HTTPError:
                    ok = False
                self.connected, self.in_flight = ok, 0
                if ok:
                    self.sent += len(batch)
                    backoff = 0.5
                    continue
                self._requeue(batch)
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 10)
