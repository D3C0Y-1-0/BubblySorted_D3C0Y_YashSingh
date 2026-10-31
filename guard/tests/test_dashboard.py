"""Phase C3: the dashboard's snapshot and live stream."""

import asyncio
import json

import httpx
import pytest

from chakravyuha.dashboard import create_dashboard, snapshot, stream

pytestmark = pytest.mark.anyio
BROWSER = {"user-agent": "Mozilla/5.0"}


async def flood(client, n=40):
    for _ in range(n):
        await client.get("/transaction/", headers=BROWSER)


async def test_flood_shows_as_a_client_stopped_on_ring_2(make_guard):
    guard, *_, client = make_guard()
    async with client("10.0.0.6") as attacker, client("10.0.0.7") as user:
        await flood(attacker)
        await user.get("/transaction/", headers=BROWSER)
    data = snapshot(guard)
    by_ip = {c["ip"]: c for c in data["clients"]}
    assert by_ip["10.0.0.6"]["banned"] and by_ip["10.0.0.6"]["stops"] > 0
    assert by_ip["10.0.0.7"]["ring"] == "centre" and by_ip["10.0.0.7"]["action"] == "allowed"
    assert data["ring_stops"]["2"] >= 1 and data["bans"] == 1
    assert data["totals"]["requests"] == 41


async def test_stream_pushes_events_as_they_happen(make_guard):
    guard, *_, client = make_guard()
    messages = []

    async def read():
        async for message in stream(guard, tick=60):
            messages.append(message)
            if '"ring":2' in message:
                return

    reader = asyncio.create_task(read())
    await asyncio.sleep(0)  # let the stream subscribe and send its first snapshot
    async with client("10.0.0.6") as attacker:
        await flood(attacker, 30)
    await asyncio.wait_for(reader, 1)
    assert messages[0].startswith("event: snapshot")
    batches = [json.loads(m.split("data: ", 1)[1]) for m in messages[1:]]
    assert all(m.startswith("event: events") for m in messages[1:])
    assert any(e["event.action"] == "blocked" and e["ring"] == 2 for e in batches[-1])
    await asyncio.sleep(0)
    assert not guard.bus._subscribers  # unsubscribed on close


async def test_dashboard_serves_page_and_snapshot(make_guard):
    guard, *_ = make_guard()
    app = create_dashboard(guard)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://dash") as c:
        page = await c.get("/")
        assert page.status_code == 200 and "Chakravyuha" in page.text
        assert (await c.get("/static/app.js")).status_code == 200
        assert (await c.get("/api/snapshot")).json()["level"] == "calm"


async def test_brute_force_trip_is_not_counted_as_an_extra_request(make_guard):
    guard, *_, client = make_guard()
    guard.config.services["transaction"].rate = 1000
    async with client() as c:
        for i in range(8):
            body = {"username": "demo", "password": f"p{i}"}
            await c.post("/transaction/login", json=body, headers=BROWSER)
    data = snapshot(guard)
    assert data["totals"]["requests"] == 8 and data["passwords"] == 8 and data["traps"] == 1


async def test_hedwig_panel_reads_the_bank_folder_and_snippets_stay_inside_it(make_guard, tmp_path):
    bank = tmp_path / "bank"
    (bank / ".hedwig").mkdir(parents=True)
    (bank / "transaction").mkdir()
    (bank / "transaction" / "App.java").write_text("a\nb\nc\nd\n")
    finding = {
        "id": "CVE-1", "severity": "high", "risk": 0.3, "service": "transaction",
        "package": "x", "version": "1", "decision": {"action": "fix"}, "kind": "vulnerability",
        "call_sites": [{"file": "App.java", "line": 2, "function": "f", "symbol": "x.y"}],
    }  # fmt: skip
    scan = {"generated_at": "now", "findings": [finding]}
    (bank / ".hedwig" / "last-scan.json").write_text(json.dumps(scan))
    guard, *_ = make_guard(bank_root=str(bank))
    app = create_dashboard(guard)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://d") as c:
        data = (await c.get("/api/hedwig")).json()
        inside = (
            await c.get(
                "/api/snippet", params={"service": "transaction", "file": "App.java", "line": 2}
            )
        ).json()
        outside = (
            await c.get(
                "/api/snippet",
                params={"service": "transaction", "file": "../../../etc/passwd", "line": 1},
            )
        ).json()
        refused = await c.post("/api/run/scan")  # no token
    assert data["findings"][0]["id"] == "CVE-1" and data["findings"][0]["decision"] == "fix"
    assert [line["n"] for line in inside["lines"] if line["hit"]] == [2]
    assert outside["lines"] == [] and refused.status_code == 401
