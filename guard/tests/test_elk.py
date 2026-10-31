"""Phase C9: the ELK pipeline. Logstash and Elasticsearch are stood in for, never required."""

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from chakravyuha.config import Elk
from chakravyuha.elastic import EventSource
from chakravyuha.events import EventBus, make_event
from chakravyuha.shipper import Shipper

pytestmark = pytest.mark.anyio


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]  # nothing listens once the socket closes


def event(i: int = 0) -> dict:
    return make_event("allowed", ip=f"127.0.0.{i % 250 + 2}", ring="centre")


def test_a_stopped_logstash_never_blocks_and_the_drop_counter_rises():
    shipper = Shipper(f"127.0.0.1:{closed_port()}", queue_size=50).start()
    started = time.perf_counter()
    for i in range(500):
        shipper.put(event(i))
    assert time.perf_counter() - started < 0.5  # 500 events, no waiting on the network
    assert shipper.dropped >= 450 and len(shipper.queue) == 50
    shipper.close(flush_s=0)


class FakeLogstash:
    """Logstash's http input: answers 200 (or `status`) and keeps what it got."""

    def __init__(self, status: int = 200) -> None:
        self.status, self.lines = status, []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["content-length"]))
                if owner.status == 200:
                    owner.lines += body.decode().splitlines()
                self.send_response(owner.status)
                self.send_header("content-length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.address = f"127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def wait_for(check, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not check():
        time.sleep(0.05)
    return check()


def test_events_reach_logstash_as_acknowledged_json_lines():
    logstash = FakeLogstash()
    shipper = Shipper(logstash.address).start()
    for i in range(3):
        shipper.put(event(i))
    assert wait_for(lambda: shipper.sent >= 3 and len(logstash.lines) == 3)
    assert all("event.id" in json.loads(line) for line in logstash.lines)
    assert shipper.connected and shipper.sent == 3
    shipper.close(flush_s=0)
    logstash.close()


def test_an_unacknowledged_batch_is_kept_and_sent_later():
    logstash = FakeLogstash(status=503)  # up, but not taking events (or a proxy answering)
    shipper = Shipper(logstash.address).start()
    shipper.put(event(1))
    assert wait_for(lambda: not shipper.connected and shipper.sent == 0, timeout=2)
    assert len(shipper.queue) == 1  # kept, not lost
    logstash.status = 200
    assert wait_for(lambda: len(logstash.lines) == 1, timeout=5)
    shipper.close(flush_s=0)
    logstash.close()


async def test_agents_fall_back_to_the_buffer_when_elasticsearch_is_down():
    bus = EventBus(None, stdout=False)
    bus.emit(make_event("login_failed", ip="127.0.0.9", ring=5))
    bus.emit(make_event("allowed", ip="127.0.0.9", ring="centre"))
    down = EventSource(bus, Elk(elastic_url=f"http://127.0.0.1:{closed_port()}"))
    events, where = await down.window(60, ["login_failed"])
    assert where == "buffer" and down.status == "offline"
    assert [e["event.action"] for e in events] == ["login_failed"]
    await down.aclose()


async def test_agents_read_elasticsearch_when_it_is_up():
    hit = make_event("login_failed", ip="127.0.0.7", ring=5)

    def answer(request: httpx.Request) -> httpx.Response:
        query = json.loads(request.content)["query"]["bool"]["filter"]
        assert {"terms": {"event.action": ["login_failed"]}} in query
        return httpx.Response(200, json={"hits": {"hits": [{"_source": hit}]}})

    client = httpx.AsyncClient(transport=httpx.MockTransport(answer))
    up = EventSource(EventBus(None, stdout=False), Elk(), client=client)
    events, where = await up.window(60, ["login_failed"])
    assert where == "elastic" and up.status == "online" and events == [hit]
    await up.aclose()
