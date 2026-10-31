"""Phase C4: ring 3, the proof-of-work challenge and IP-bound sessions."""

import pytest

from chakravyuha import state as signals
from chakravyuha.challenge import COOKIE, leading_zero_bits_ok, solve

pytestmark = pytest.mark.anyio
BROWSER = {"user-agent": "Mozilla/5.0", "accept": "text/html,application/xhtml+xml"}
SCRIPT = {"user-agent": "python-httpx"}


async def get_session(c, headers=SCRIPT) -> str:
    """Do what the challenge page's script does: fetch a puzzle, solve it, post the answer."""
    challenged = await c.get("/transaction/", headers=headers)
    assert challenged.status_code == 403
    token = challenged.headers["x-hedwig-challenge"]
    bits = int(challenged.headers["x-hedwig-difficulty"])
    solved = await c.post(
        "/__hedwig/challenge", json={"token": token, "nonce": solve(token, bits)}, headers=headers
    )
    assert solved.status_code == 200
    return solved.cookies[COOKIE]


async def test_script_without_a_solution_gets_403_and_suspicion(make_guard):
    guard, upstream, *_, client = make_guard()
    async with client("10.0.0.2", session=False) as c:
        first = await c.get("/transaction/balance", headers=SCRIPT)
        assert first.status_code == 403 and first.json()["error"] == "challenge required"
        for _ in range(3):  # keeps coming back without solving
            await c.get("/transaction/balance", headers=SCRIPT)
        login = await c.post("/transaction/login", json={"username": "demo", "password": "x"})
        assert login.status_code == 403
    assert upstream.seen == []
    events = guard.bus.recent()
    assert all(e["event.action"] == "challenged" and e["ring"] == 3 for e in events)
    reasons = guard.state.client("10.0.0.2").reasons
    assert reasons["challenge-failed"] >= 2 and reasons["script-ua"] == 1


async def test_browser_gets_the_page_and_a_solution_earns_a_session(make_guard):
    guard, upstream, *_, client = make_guard()
    async with client(session=False) as c:
        page = await c.get("/transaction/", headers=BROWSER)
        assert page.status_code == 403 and "text/html" in page.headers["content-type"]
        assert page.headers["x-hedwig-challenge"] in page.text and "__TOKEN__" not in page.text

        await get_session(c, BROWSER)
        c.cookies.set("theme", "dark")
        response = await c.get("/transaction/", headers=BROWSER)
        assert response.status_code == 200
    assert upstream.seen[0]["headers"]["cookie"] == "theme=dark"  # the Guard's cookie stays home
    actions = [e["event.action"] for e in guard.bus.recent()]
    assert actions == ["challenged", "challenged", "challenge_solved", "allowed"]
    assert guard.state.suspicion(guard.state.client("10.0.0.1")) == 0  # a browser is not suspect


async def test_cookie_copied_to_another_ip_is_rejected(make_guard):
    guard, upstream, *_, client = make_guard()
    async with client("10.0.0.1", session=False) as owner:
        cookie = await get_session(owner)
    async with client("10.0.0.66", session=False) as thief:
        thief.cookies.set(COOKIE, cookie)
        stolen = await thief.get("/transaction/", headers=SCRIPT)
    assert stolen.status_code == 403 and upstream.seen == []
    assert guard.bus.recent()[-1]["rule"] == "session-invalid"
    assert guard.state.client("10.0.0.66").reasons["challenge-failed"] == 2


async def test_wrong_reused_and_forged_solutions_are_refused(make_guard):
    guard, *_, client = make_guard()
    async with client(session=False) as c:
        token = (await c.get("/transaction/", headers=SCRIPT)).headers["x-hedwig-challenge"]
        wrong = next(str(n) for n in range(100) if not leading_zero_bits_ok(token, str(n), 4))
        refused = await c.post("/__hedwig/challenge", json={"token": token, "nonce": wrong})
        assert refused.status_code == 403 and COOKIE not in refused.cookies

        good = {"token": token, "nonce": solve(token, 4)}
        assert (await c.post("/__hedwig/challenge", json=good)).status_code == 200
        reused = await c.post("/__hedwig/challenge", json=good)
        assert reused.json()["error"] == "reused"

        issued, bits, salt, mac = token.split(".")
        easy = f"{issued}.1.{salt}.{mac}"  # lower the difficulty without the key
        forged = await c.post("/__hedwig/challenge", json={"token": easy, "nonce": solve(easy, 1)})
        assert forged.json()["error"] == "invalid"


async def test_difficulty_rises_with_suspicion_and_level_and_sessions_expire(make_guard):
    guard, *_, client = make_guard(allowlist=["10.0.0.20"])
    state = guard.state

    async def bits(ip):
        async with client(ip, session=False) as c:
            response = await c.get("/transaction/", headers={"user-agent": "Mozilla"})
        return int(response.headers["x-hedwig-difficulty"])

    assert await bits("10.0.0.1") == 4
    state.add(state.client("10.0.0.3"), signals.CAMPAIGN_MEMBER)  # 5 points: hard challenge
    assert await bits("10.0.0.3") == 8
    assert guard.challenger.session_seconds(5, guard.config) == 600  # a third of 30 minutes
    state.level = "siege"
    assert await bits("10.0.0.1") == 8
    assert await bits("10.0.0.20") == 4  # the formation does not tighten for the tablet

    now = guard.challenger.clock()
    cookie = guard.challenger.make_session("10.0.0.1", 60)
    guard.challenger.clock = lambda: now + 61
    assert guard.challenger.check_session("10.0.0.1", cookie).reason == "expired"


async def test_machine_api_sends_its_key_instead(make_guard, monkeypatch):
    monkeypatch.setenv("CHAKRA_TEST_API_KEY", "s3cret")
    service = {"upstream": "http://api", "challenge": False, "api_key_env": "CHAKRA_TEST_API_KEY"}
    guard, upstream, *_, client = make_guard(services={"api": service})
    async with client(session=False) as c:
        assert (await c.get("/api/rates", headers=SCRIPT)).status_code == 401
        keyed = await c.get("/api/rates", headers={**SCRIPT, "x-api-key": "s3cret"})
        assert keyed.status_code == 200
    assert len(upstream.seen) == 1
