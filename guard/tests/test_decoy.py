"""Phase C6: the trap and the decoy bank."""

import httpx
import pytest
from conftest import TOKEN

from chakravyuha.dashboard import create_dashboard

pytestmark = pytest.mark.anyio
BROWSER = {"user-agent": "Mozilla/5.0"}


async def trip(c, n=8):
    for i in range(n):
        await c.post("/transaction/login", json={"username": "demo", "password": f"p{i}"})


def fast(guard):
    guard.config.services["transaction"].rate = 1000
    return guard


async def test_after_a_trip_the_attacker_only_ever_sees_the_decoy(make_guard):
    guard, upstream, *_, client = make_guard(allowlist=["10.0.0.20"])
    fast(guard)
    async with client("10.0.0.20") as browser:
        real = await browser.get("/transaction/balance", headers=BROWSER)
        real_login = await browser.post(
            "/transaction/login", json={"username": "demo", "password": "demo-pass"}
        )
    async with client("10.0.0.5") as attacker:
        await trip(attacker)
        seen = len(upstream.seen)
        decoy = await attacker.get("/transaction/balance", headers=BROWSER)
        await attacker.get("/transaction/balance?x=${jndi:ldap://a}", headers=BROWSER)
        await attacker.post("/transaction/transfer", json={"to": "x", "amount": 5})
        assert len(upstream.seen) == seen  # the real service saw none of them

        maze = guard.decoy.maze("10.0.0.5")
        codes = []
        for i in range(maze.success_at):
            r = await attacker.post(
                "/transaction/login", json={"username": "demo", "password": f"q{i}"}
            )
            codes.append(r.status_code)
        assert codes[:-1] == [401] * (maze.success_at - 1) and codes[-1] == 200
        assert 3 <= maze.success_at <= 10
        decoy_login = r
        assert len(upstream.seen) == seen

    async with client("10.0.0.20") as browser:  # the demo browser is unaffected
        assert (await browser.get("/transaction/balance", headers=BROWSER)).json() == real.json()

    assert decoy.json()["balance"] != real.json()["balance"]
    assert decoy.json().keys() == real.json().keys()
    names = lambda r: sorted({k for k in r.headers if k != "content-length"})  # noqa: E731
    assert names(decoy) == names(real) and decoy.headers["x-bank"] == "demo"
    assert decoy_login.cookies.keys() == real_login.cookies.keys() == {"bank_session"}
    events = [e for e in guard.bus.recent() if e.get("hedwig.decoy")]
    assert events and all(e["ring"] == 7 and e["event.action"] == "trapped" for e in events)


async def test_the_maze_sits_behind_the_same_challenge(make_guard):
    guard, upstream, *_, client = make_guard()
    guard.state.trap("10.0.0.5")
    async with client("10.0.0.5", session=False) as attacker:
        response = await attacker.get("/transaction/balance", headers={"accept": "text/html"})
    assert response.status_code == 403 and "x-hedwig-challenge" in response.headers
    assert upstream.seen == []


async def test_trap_expires_and_the_release_button_works(make_guard):
    guard, upstream, clock, _, client = make_guard()
    guard.state.trap("10.0.0.5", minutes=30)
    clock.t += 30 * 60 + 1
    async with client("10.0.0.5") as freed:
        real = await freed.get("/transaction/balance", headers=BROWSER)
    assert real.json()["balance"] == 1234.56  # the trap expired: the real bank again
    guard.state.trap("10.0.0.6", minutes=30)

    dash = httpx.ASGITransport(app=create_dashboard(guard))
    async with httpx.AsyncClient(transport=dash, base_url="http://dash") as d:
        body = {"action": "release", "ip": "10.0.0.6"}
        assert (await d.post("/api/control", json=body)).status_code == 401
        auth = {"authorization": f"Bearer {TOKEN}"}
        assert (await d.post("/api/control", json=body, headers=auth)).json()["ok"]
        level = await d.post(
            "/api/control", json={"action": "level", "level": "siege"}, headers=auth
        )
        assert level.json()["ok"] and guard.state.level == "siege"
    assert not guard.state.trapped("10.0.0.6")
    assert any(e["event.action"] == "released" for e in guard.bus.recent())
    assert guard.feed[-1]["text"].startswith("level calm → siege")
