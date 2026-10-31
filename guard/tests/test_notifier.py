"""Phase C11: the PM digest and the immediate honeytoken email."""

import threading

import pytest

from chakravyuha.notifier import PMNotifier, SmtpConfig

pytestmark = pytest.mark.anyio
CFG = SmtpConfig(host="smtp.test", to="pm@test", sender="guard@test")


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class Outbox:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail
        self.done = threading.Event()

    def __call__(self, cfg, subject, body):
        if self.fail:
            self.done.set()
            raise OSError("smtp refused")
        self.sent.append((subject, body))
        self.done.set()


def blocked(action="blocked"):
    return {"event.action": action}


def notifier(outbox, clock, **kw):
    return PMNotifier(
        CFG,
        send=outbox,
        clock=clock,
        summary=lambda: "Alert level: siege.",
        kibana_url="http://127.0.0.1:5601",
        **kw,
    )


def test_a_burst_of_500_blocks_sends_exactly_one_email():
    outbox, clock = Outbox(), Clock()
    pm = notifier(outbox, clock, digest_delay_s=30, cooldown_s=300)
    for _ in range(500):
        pm.on_event(blocked())
    assert pm.poll() is False  # timer has not elapsed yet
    clock.t = 31
    assert pm.poll() is True
    outbox.done.wait(2)
    assert len(outbox.sent) == 1 and pm.sent == 1
    subject, body = outbox.sent[0]
    assert "500" in subject and "500 blocked" in body and "siege" in body and "5601" in body
    # more blocks during the cool-down do not send a second email
    for _ in range(500):
        pm.on_event(blocked())
    clock.t = 70
    assert pm.poll() is False
    clock.t = 331  # cool-down (300 s) passed
    assert pm.poll() is True and len(outbox.sent) == 2


def test_only_reportable_actions_arm_the_timer():
    outbox, clock = Outbox(), Clock()
    pm = notifier(outbox, clock)
    pm.on_event({"event.action": "allowed"})
    pm.on_event({"event.action": "blocked", "hedwig.monitor": True})  # monitor: would-be
    clock.t = 100
    assert pm.poll() is False and pm.pending_since is None


def test_honeytoken_use_emails_at_once_outside_the_timer():
    outbox, clock = Outbox(), Clock()
    pm = notifier(outbox, clock)
    pm.on_alarm(
        {
            "kind": "api_key",
            "ip": "10.0.0.9",
            "issued_to": "10.0.0.5",
            "path": "/x",
            "banned": ["10.0.0.5", "10.0.0.9"],
        }
    )
    outbox.done.wait(2)
    assert pm.alarms_sent == 1 and len(outbox.sent) == 1
    subject, body = outbox.sent[0]
    assert "Honeytoken" in subject and "10.0.0.9" in subject
    assert "api_key" in body and "certain compromise" in body


def test_an_email_failure_leaves_everything_working():
    outbox, clock = Outbox(fail=True), Clock()
    pm = notifier(outbox, clock, digest_delay_s=1)
    pm.on_event(blocked())
    clock.t = 2
    assert pm.poll() is True  # the send is dispatched and fails in its thread
    outbox.done.wait(2)
    assert outbox.sent == []  # nothing delivered, but no exception reached the caller
    pm.on_event(blocked("trapped"))  # the notifier keeps accepting events
    assert pm.pending == {"trapped": 1}


def test_without_smtp_configured_it_only_logs():
    logged = []
    pm = PMNotifier(SmtpConfig(), send=Outbox(), clock=Clock(), log=logged.append, digest_delay_s=0)
    assert not pm.active
    pm.on_event(blocked())
    pm.poll()
    assert any("would email PM" in line for line in logged)


def test_the_digest_names_each_attacker_with_trap_and_ban_times():
    outbox, clock = Outbox(), Clock()
    pm = notifier(outbox, clock)
    ip = "127.0.0.6"
    trapped = {
        "event.action": "trapped", "source.ip": ip, "service": "support",
        "url.path": "/attachments", "rule": "ransomware-command", "event.category": "malware",
        "@timestamp": "2026-11-01T10:00:02+00:00",
    }  # fmt: skip
    pm.on_event(trapped)
    for _ in range(3):
        pm.on_event({**trapped, "@timestamp": "2026-11-01T10:00:05+00:00", "hedwig.decoy": True})
    pm.on_event({
        "event.action": "banned", "source.ip": ip, "rule": "honeytoken-api_key",
        "event.category": "honeytoken", "@timestamp": "2026-11-01T10:00:09+00:00",
        "hedwig.ban_minutes": 60,
    })  # fmt: skip
    clock.t = 31
    assert pm.poll()
    assert outbox.done.wait(2)
    body = outbox.sent[0][1]
    assert ip in body and "support /attachments" in body
    assert "trapped in the decoy bank at 10:00:02" in body
    assert "banned at 10:00:09 until 11:00:09 UTC (honeytoken-api_key)" in body
    assert "the decoy answered 3" in body
