"""Reporting to the project manager over SMTP.

Digest: the first unreported event starts a timer (default 30 s); then one email goes out and a
cool-down starts (default 5 min), so a burst of 10,000 blocks sends one email. The Commander
writes the summary; without the agents a plain template is used.

Honeytoken use sends an email immediately, outside the timer.

A failed email never affects proxying: sending happens off the request path in a worker thread,
and every failure is caught and logged.
"""

import os
import smtplib
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

REPORTABLE = {"blocked", "banned", "trapped"}  # a decision worth telling the PM about


@dataclass
class SmtpConfig:
    host: str = ""
    port: int = 587
    user: str = ""
    password: str = ""
    to: str = ""
    sender: str = ""

    @classmethod
    def from_env(cls) -> "SmtpConfig":
        env = os.environ.get
        return cls(
            host=env("SMTP_HOST", ""),
            port=int(env("SMTP_PORT", "587") or "587"),
            user=env("SMTP_USER", ""),
            password=env("SMTP_PASS", ""),
            to=env("PM_EMAIL", ""),
            sender=env("SMTP_FROM", "") or env("SMTP_USER", ""),
        )

    @property
    def ready(self) -> bool:
        return bool(self.host and self.to and self.sender)


def send_smtp(cfg: SmtpConfig, subject: str, body: str) -> None:
    """Blocking SMTP send (Gmail on 587 with STARTTLS by default). Runs in a worker thread."""
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg.sender
    message["To"] = cfg.to
    message.set_content(body)
    context = ssl.create_default_context()
    with smtplib.SMTP(cfg.host, cfg.port, timeout=10) as server:
        server.ehlo()
        if server.has_extn("starttls"):
            server.starttls(context=context)
            server.ehlo()
        if cfg.user and cfg.password:
            server.login(cfg.user, cfg.password)
        server.send_message(message)


class PMNotifier:
    def __init__(
        self,
        config: SmtpConfig | None = None,
        *,
        digest_delay_s: float = 30,
        cooldown_s: float = 300,
        send: Callable[[SmtpConfig, str, str], None] = send_smtp,
        summary: Callable[[], str] | None = None,
        kibana_url: str = "",
        clock: Callable[[], float] = time.monotonic,
        log: Callable[[str], None] = print,
    ) -> None:
        self.config = config or SmtpConfig.from_env()
        self.digest_delay_s = digest_delay_s
        self.cooldown_s = cooldown_s
        self._send = send
        self.summary = summary or (lambda: "")
        self.kibana_url = kibana_url
        self.clock = clock
        self.log = log
        self._lock = threading.Lock()
        self.pending_since: float | None = None
        self.pending: dict[str, int] = {}  # action -> count since the last digest
        self.cooldown_until = 0.0
        self.sent = 0  # digests sent
        self.alarms_sent = 0

    @property
    def active(self) -> bool:
        return self.config.ready

    # -- inputs (called inline from the event bus; stay cheap, never raise) ----------------
    def on_event(self, event: dict[str, Any]) -> None:
        action = event.get("event.action")
        if action not in REPORTABLE or event.get("hedwig.monitor"):
            return
        with self._lock:
            self.pending[action] = self.pending.get(action, 0) + 1
            if self.pending_since is None:
                self.pending_since = self.clock()

    def on_alarm(self, alarm: dict[str, Any]) -> None:
        """A honeytoken alarm: email at once, outside the digest timer."""
        subject = f"[Chakravyuha] Honeytoken used from {alarm.get('ip')}"
        body = (
            f"A honeytoken ({alarm.get('kind')}) was used from {alarm.get('ip')}.\n"
            f"It was planted for the trapped client {alarm.get('issued_to')}.\n"
            f"Path: {alarm.get('path')}\n"
            f"Banned: {', '.join(alarm.get('banned') or []) or 'none'}\n"
            f"This value only exists inside the decoy bank, so its use is a certain compromise.\n"
            + self._kibana_line()
        )
        self.alarms_sent += 1
        self._dispatch(subject, body)

    # -- the timer (called from the Guard's slow loop) -------------------------------------
    def poll(self) -> bool:
        """Send the digest if the timer has elapsed and the cool-down has passed. Returns sent."""
        with self._lock:
            now = self.clock()
            if self.pending_since is None or now - self.pending_since < self.digest_delay_s:
                return False
            if now < self.cooldown_until:
                return False
            counts, self.pending = self.pending, {}
            self.pending_since = None
            self.cooldown_until = now + self.cooldown_s
            self.sent += 1
        total = sum(counts.values())
        detail = ", ".join(f"{n} {action}" for action, n in sorted(counts.items()))
        summary = self.summary().strip()
        body = (
            f"The Guard handled {total} blocked or trapped requests ({detail}).\n\n"
            + (summary + "\n\n" if summary else "")
            + self._kibana_line()
        )
        self._dispatch(f"[Chakravyuha] {total} requests stopped", body)
        return True

    def _kibana_line(self) -> str:
        return f"Investigate in Kibana: {self.kibana_url}\n" if self.kibana_url else ""

    def _dispatch(self, subject: str, body: str) -> None:
        if not self.active:
            self.log(f"chakravyuha: (no SMTP configured) would email PM: {subject}")
            return
        threading.Thread(
            target=self._worker, args=(subject, body), name="chakravyuha-pm", daemon=True
        ).start()

    def _worker(self, subject: str, body: str) -> None:
        try:
            self._send(self.config, subject, body)
            self.log(f"chakravyuha: emailed the PM: {subject}")
        except Exception as error:  # a failed email must never affect proxying
            self.log(f"chakravyuha: PM email failed ({type(error).__name__}: {error})")
