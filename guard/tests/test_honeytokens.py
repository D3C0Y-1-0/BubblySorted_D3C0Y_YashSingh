"""Phase C7: honeytokens."""

import base64
import re

import pytest

pytestmark = pytest.mark.anyio
BROWSER = {"user-agent": "Mozilla/5.0"}


async def planted_key(guard, client, ip="10.0.0.5") -> str:
    guard.state.trap(ip)
    async with client(ip) as attacker:
        history = (await attacker.get("/transaction/transactions", headers=BROWSER)).json()
    memo = next(t["memo"] for t in history["transactions"] if "API key" in t["memo"])
    return re.search(r"hk_live_[0-9a-f]{32}", memo).group(0)


async def test_planted_api_key_raises_the_alarm_and_bans_linked_ips(make_guard):
    guard, upstream, *_, client = make_guard()
    alarms = []
    guard.alarm_listeners.append(alarms.append)
    key = await planted_key(guard, client)
    async with client("10.0.0.9") as accomplice:
        used = await accomplice.get("/transaction/balance", headers={**BROWSER, "x-api-key": key})
    assert used.status_code == 403 and upstream.seen == []
    assert guard.state.banned("10.0.0.5") and guard.state.banned("10.0.0.9")
    assert len(alarms) == 1 and alarms[0]["issued_to"] == "10.0.0.5"
    event = guard.bus.recent()[-1]
    assert event["event.category"] == "honeytoken" and event["hedwig.honeytoken.kind"] == "api_key"


@pytest.mark.parametrize("where", ["query", "basic", "body", "no-session", "banned"])
async def test_honeytoken_is_detected_on_every_ring(make_guard, where):
    guard, upstream, *_, client = make_guard()
    key = await planted_key(guard, client)
    if where == "banned":
        guard.state.ban("10.0.0.9", 5)
    async with client("10.0.0.9", session=where != "no-session") as c:
        if where == "query":
            await c.get(f"/transaction/balance?k={key}")
        elif where == "basic":
            auth = base64.b64encode(f"admin:{key}".encode()).decode()
            await c.get("/transaction/balance", headers={"authorization": f"Basic {auth}"})
        elif where == "body":
            await c.post("/transaction/transfer", json={"note": key, "amount": 1})
        else:
            await c.get("/nowhere", headers={"authorization": f"Bearer {key}"})
    assert any(e.get("event.category") == "honeytoken" for e in guard.bus.recent())
    assert guard.alarms and upstream.seen == []


async def test_a_decoy_session_only_alarms_from_another_ip(make_guard):
    guard, *_, client = make_guard()
    guard.state.trap("10.0.0.5")
    session = guard.honeytokens.fill("session", "10.0.0.5")
    async with client("10.0.0.5") as own:
        own.cookies.set("bank_session", session)
        assert (await own.get("/transaction/balance", headers=BROWSER)).status_code == 200
    assert not guard.alarms
    async with client("10.0.0.7") as other:
        other.cookies.set("bank_session", session)
        assert (await other.get("/transaction/balance", headers=BROWSER)).status_code == 403
    assert guard.alarms[-1]["kind"] == "session" and guard.state.banned("10.0.0.7")


def test_rotation_issues_new_tokens_and_old_ones_stay_detectable(make_guard):
    guard, *_ = make_guard()
    old = guard.honeytokens.fill("api_key", "10.0.0.5")
    guard.rotate_tokens("Commander")
    new = guard.honeytokens.fill("api_key", "10.0.0.5")
    assert new != old
    assert {t.value for t in guard.honeytokens.scan(f"x {old} y {new}")} == {old, new}
    assert guard.feed[-1]["agent"] == "Commander"
