"""Phase C1: the proxy core."""

import os

import pytest
from conftest import TOKEN

pytestmark = pytest.mark.anyio


async def test_requests_reach_upstream_unchanged(make_guard):
    guard, upstream, *_, client = make_guard()
    big = os.urandom(5 * 1024 * 1024)
    async with client() as c:
        get = await c.get("/transaction/balance?account=42", headers={"user-agent": "Mozilla"})
        post = await c.post("/transaction/transfer", content=big, headers={"user-agent": "Mozilla"})
    assert get.status_code == 200
    assert post.status_code == 200 and post.content == big
    first, second = upstream.seen
    assert (first["method"], first["path"], first["query"]) == ("GET", "/balance", "account=42")
    assert first["headers"]["x-forwarded-for"] == "10.0.0.1"
    assert second["body"] == big
    assert get.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors" in get.headers["content-security-policy"]
    assert guard.bus.recent()[-1]["event.action"] == "allowed"


async def test_oversized_body_is_refused(make_guard):
    _, upstream, *_, client = make_guard(max_body_bytes=1024)
    async with client() as c:
        response = await c.post("/transaction/transfer", content=b"x" * 2048)
    assert response.status_code == 413
    assert upstream.seen == []


async def test_unknown_prefix_is_not_found(make_guard):
    _, upstream, *_, client = make_guard()
    async with client() as c:
        response = await c.get("/nowhere/at/all")
    assert response.status_code == 404
    assert upstream.seen == []


async def test_events_endpoint_needs_the_token(make_guard):
    *_, client = make_guard()
    async with client() as c:
        await c.get("/transaction/")
        assert (await c.get("/__hedwig/events")).status_code == 401
        wrong = await c.get("/__hedwig/events", headers={"authorization": "Bearer nope"})
        assert wrong.status_code == 401
        right = await c.get("/__hedwig/events", headers={"authorization": f"Bearer {TOKEN}"})
        assert right.status_code == 200 and right.json()[-1]["source.ip"] == "10.0.0.1"
        assert (await c.get("/__hedwig/health")).json() == {"status": "ok"}


async def test_fail_open_on_a_crashing_ring(make_guard, monkeypatch):
    from chakravyuha import rings

    def boom(*args):
        raise RuntimeError("rule crashed")

    monkeypatch.setattr(rings, "flood", boom)
    guard, upstream, *_, client = make_guard()
    async with client() as c:
        response = await c.get("/transaction/")
    assert response.status_code == 200 and len(upstream.seen) == 1
    actions = [event["event.action"] for event in guard.bus.recent()]
    assert actions == ["guard-error", "allowed"]
