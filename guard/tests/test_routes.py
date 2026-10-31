"""Phase C5: ring 4, only known routes exist."""

import pytest

pytestmark = pytest.mark.anyio
BROWSER = {"user-agent": "Mozilla/5.0"}
ROUTES = ["GET /", "GET /balance", "POST /login", "GET /accounts/{id}"]


def guard_with_routes(make_guard):
    service = {"upstream": "http://transaction", "challenge": False, "routes": ROUTES}
    return make_guard(services={"transaction": service})


async def test_unlisted_route_never_reaches_the_upstream(make_guard):
    guard, upstream, *_, client = guard_with_routes(make_guard)
    async with client() as c:
        assert (await c.get("/transaction/balance", headers=BROWSER)).status_code == 200
        assert (await c.head("/transaction/balance", headers=BROWSER)).status_code == 200
        assert (await c.get("/transaction/accounts/42", headers=BROWSER)).status_code == 200
        assert (await c.get("/transaction/accounts/42/x", headers=BROWSER)).status_code == 404
        assert (await c.post("/transaction/balance", headers=BROWSER)).status_code == 404
        assert (await c.get("/transaction/internal", headers=BROWSER)).status_code == 404
    assert [s["path"] for s in upstream.seen] == ["/balance", "/balance", "/accounts/42"]
    assert guard.state.client("10.0.0.1").reasons["unknown-route"] == 6


@pytest.mark.parametrize("session", [True, False])
async def test_probing_env_admin_and_git_traps_the_client(make_guard, session):
    service = {"upstream": "http://transaction", "routes": ROUTES}  # challenge on
    guard, upstream, *_, client = make_guard(services={"transaction": service})
    async with client("10.0.0.8", session=session) as scanner:  # python-httpx user agent
        for path in ("/.env", "/transaction/admin", "/.git/config"):
            response = await scanner.get(path)
            assert response.status_code == (404 if session else 403)
    assert guard.state.trapped("10.0.0.8") and upstream.seen == []
    trapped = [e for e in guard.bus.recent() if e["event.action"] == "trapped"]
    assert len(trapped) == 1 and trapped[0]["ring"] == 7


async def test_allowlisted_client_probing_is_never_trapped(make_guard):
    guard, *_, client = make_guard(allowlist=["10.0.0.20"])
    async with client("10.0.0.20") as browser:
        for path in ("/.env", "/admin", "/.git/HEAD", "/backup.zip"):
            await browser.get(path)
    assert not guard.state.trapped("10.0.0.20")
