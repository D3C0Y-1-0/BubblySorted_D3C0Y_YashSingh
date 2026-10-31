"""Phase C2: rings 1, 2 and 5 and the suspicion score."""

import json

import pytest

from chakravyuha import state as signals

pytestmark = pytest.mark.anyio
BROWSER = {"user-agent": "Mozilla/5.0"}


async def test_flood_gets_429_then_ban_while_others_pass(make_guard):
    guard, upstream, clock, _, client = make_guard()
    async with client("10.0.0.6") as attacker, client("10.0.0.7") as other:
        codes = [(await attacker.get("/transaction/", headers=BROWSER)).status_code
                 for _ in range(40)]  # fmt: skip
        assert codes[:10] == [200] * 10  # bucket of rate 5 x burst 2
        assert 429 in codes
        assert (await attacker.get("/transaction/", headers=BROWSER)).status_code == 403
        assert (await other.get("/transaction/", headers=BROWSER)).status_code == 200
    assert guard.state.banned("10.0.0.6")
    assert any(e["event.action"] == "banned" for e in guard.bus.recent())
    clock.t += 5 * 60 + 1
    assert not guard.state.banned("10.0.0.6")


async def test_allowlisted_client_is_never_banned(make_guard):
    guard, *_, client = make_guard(allowlist=["10.0.0.20"])
    async with client("10.0.0.20") as tablet:
        for _ in range(40):
            await tablet.get("/transaction/", headers=BROWSER)
    assert not guard.state.banned("10.0.0.20")


async def test_monitor_mode_logs_but_lets_through(make_guard):
    guard, upstream, *_, client = make_guard(mode="monitor")
    async with client() as c:
        codes = {(await c.get("/transaction/", headers=BROWSER)).status_code for _ in range(40)}
    assert codes == {200} and len(upstream.seen) == 40
    assert any(e.get("hedwig.monitor") for e in guard.bus.recent())
    assert not guard.state.bans


def test_suspicion_adds_up_and_decays(make_guard):
    guard, _, clock, *_ = make_guard()
    state = guard.state
    client = state.client("10.0.0.9")
    state.add(client, signals.SCRIPT_UA)
    state.add(client, signals.SCRIPT_UA)  # one-shot within its cooldown
    state.add(client, signals.UNKNOWN_ROUTE)
    assert state.suspicion(client) == pytest.approx(3)
    clock.t += 600
    assert state.suspicion(client) == pytest.approx(1.5)


async def test_suspicious_client_is_tarpitted_and_the_cap_holds(make_guard):
    guard, _, _, sleeps, client = make_guard()
    guard.state.add(guard.state.client("10.0.0.3"), signals.PROBE_ROUTE)
    async with client("10.0.0.3") as c:
        response = await c.get("/transaction/", headers=BROWSER)
    assert response.status_code == 200
    assert sleeps.calls and 0.5 <= sleeps.calls[0] <= 3
    assert guard.bus.recent()[-1]["event.action"] == "tarpitted"

    guard.state.tarpitted = guard.config.flood.tarpit_cap
    async with client("10.0.0.3") as c:
        assert (await c.get("/transaction/", headers=BROWSER)).status_code == 429


async def test_brute_force_backs_off_trips_and_never_logs_passwords(make_guard):
    guard, upstream, _, sleeps, client = make_guard()
    guard.config.services["transaction"].rate = 1000
    async with client("10.0.0.5") as c:
        ok = await c.post(
            "/transaction/login", json={"username": "demo", "password": "demo-pass"},
            headers=BROWSER,
        )  # fmt: skip
        assert ok.status_code == 200
        for attempt in range(8):
            body = {"username": "demo", "password": f"guess-{attempt}"}
            response = await c.post("/transaction/login", json=body, headers=BROWSER)
            assert response.status_code == 401
        decoy = await c.get("/transaction/balance", headers=BROWSER)
        assert decoy.status_code == 200 and decoy.json()["currency"] == "EUR"  # the maze
    assert sleeps.calls[:3] == [0.25, 0.5, 0.75]  # each failure waits longer
    assert guard.state.trapped("10.0.0.5")
    events = guard.bus.recent()
    failed = [e for e in events if e["event.action"] == "login_failed"]
    assert len(failed) == 8 and failed[0]["user.name"] == "demo"
    assert len({e["hedwig.password_fp"] for e in failed}) == 8
    assert any(e["event.action"] == "trapped" and e["rule"] == "brute-force" for e in events)
    dumped = json.dumps(events)
    assert "guess-" not in dumped and "demo-pass" not in dumped
    assert len(upstream.seen) == 9  # the trapped request never reached the service


async def test_login_success_resets_the_count(make_guard):
    guard, *_, client = make_guard()
    guard.config.services["transaction"].rate = 1000
    bad, good = {"username": "demo", "password": "x"}, {"username": "demo", "password": "demo-pass"}
    async with client() as c:
        for _ in range(4):
            await c.post("/transaction/login", json=bad, headers=BROWSER)
        await c.post("/transaction/login", json=good, headers=BROWSER)
        await c.post("/transaction/login", json=bad, headers=BROWSER)
    assert guard.state.login_failures(guard.state.client("10.0.0.1")) == 1
    assert not guard.state.trapped("10.0.0.1")
