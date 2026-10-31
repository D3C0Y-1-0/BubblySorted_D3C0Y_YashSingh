"""Ring 6: inspection, in and out.

Incoming: attack payloads (the patterns are copied from `src/hedwig/core/evidence.py`, not
imported, so a change there cannot break the Guard), open redirects, and dangerous uploads.
A payload or a bad upload traps the client; an open redirect is a plain 403.

Outgoing: HTML responses up to 512 KB are checked for an injected password form or an
obfuscated script, and 30x redirects to a foreign host are caught. A bad response is replaced
by 502 rather than passed on.

Ring 6 payload hits are also appended to the service's access log (see hedwig_link.py), so
`hedwig scan` and `hedwig status` show evidence level 3 for that service.
"""

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

# -- payload patterns (copied from src/hedwig/core/evidence.py) -------------------------------
PAYLOADS: tuple[tuple[str, re.Pattern], ...] = (
    ("jndi", re.compile(r"\$\{[^}\n]{0,30}jndi\s*:|\$\{\$\{", re.I)),
    ("jwt-alg-none", re.compile(r'"alg"\s*:\s*"none"|alg=none|eyJhbGciOiJub25l', re.I)),
    ("yaml-object", re.compile(r"!!python/object|!!ruby/object", re.I)),
    ("path-traversal", re.compile(r"(?:\.\./){2,}|%2e%2e(?:%2f|/)|\.\.%5c", re.I)),
    ("proto-pollution", re.compile(r"__proto__|constructor\[?\.?prototype", re.I)),
)
REDIRECT_PARAMS = ("next", "redirect", "redirect_uri", "url", "return", "returnurl", "dest", "to")

# -- upload signatures ------------------------------------------------------------------------
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"  # the standard antivirus test string prefix
MAGIC = (
    (b"MZ", "dos/pe"),
    (b"\x7fELF", "elf"),
    (b"\xca\xfe\xba\xbe", "mach-o"),
    (b"PK\x03\x04", "zip"),
)
WEBSHELL = re.compile(
    rb"<\?php.{0,400}?\b(eval|system|exec|shell_exec|passthru|assert|base64_decode|popen)\b"
    rb"|<%.{0,200}?\bRuntime\b|\beval\s*\(\s*(?:base64_decode|\$_(?:GET|POST|REQUEST))",
    re.I | re.S,
)
# Outbound HTML checks
PASSWORD_FORM = re.compile(rb"<input[^>]+type\s*=\s*['\"]?password", re.I)
OBFUSCATED = re.compile(
    rb"eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)|document\.write\s*\(\s*unescape",
    re.I,
)


@dataclass
class Finding:
    where: str  # request | upload | response
    rule: str
    category: str  # payload | phishing | malware
    trap: bool
    status: int = 403


def scan_payload(*parts: str) -> Finding | None:
    for text in parts:
        if not text:
            continue
        for name, pattern in PAYLOADS:
            if pattern.search(text):
                return Finding("request", name, "payload", trap=True)
    return None


def open_redirect(query: str, own_hosts: set[str], allowed: list[str]) -> Finding | None:
    params = parse_qs(query)
    allow = {h.lower() for h in allowed} | own_hosts
    for key, values in params.items():
        if key.lower() not in REDIRECT_PARAMS:
            continue
        for value in values:
            host = _external_host(value)
            if host and host not in allow:
                return Finding("request", "open-redirect", "phishing", trap=False)
    return None


def _external_host(value: str) -> str | None:
    """The host of an absolute or scheme-relative URL, else None for a same-site path."""
    value = value.strip()
    if value.startswith("//"):
        value = "http:" + value
    parsed = urlparse(value)
    external = parsed.scheme in ("http", "https") and parsed.hostname
    return parsed.hostname.lower() if external else None


def scan_upload(body: bytes, uploads, blocked_hashes: set[str]) -> Finding | None:
    """A body is inspected when the service does not allow uploads, or allows only some kinds
    and this one is dangerous. `uploads` is False, True or a list of allowed extensions."""
    if not body:
        return None
    head = body[:4096]
    if EICAR in body[:1024]:
        return Finding("upload", "eicar", "malware", trap=True)
    if WEBSHELL.search(body[:65536]):
        return Finding("upload", "webshell", "malware", trap=True)
    if blocked_hashes and hashlib.sha256(body).hexdigest() in blocked_hashes:
        return Finding("upload", "blocklisted-hash", "malware", trap=True)
    for magic, label in MAGIC:
        if head.startswith(magic):
            # a zip is only suspicious where uploads are off (office files are zips)
            if label == "zip" and uploads is not False:
                return None
            return Finding("upload", f"executable-{label}", "malware", trap=True)
    return None


def scan_response(body: bytes, content_type: str) -> Finding | None:
    if "html" not in content_type.lower():
        return None
    if PASSWORD_FORM.search(body):
        return Finding("response", "injected-password-form", "phishing", trap=False, status=502)
    if OBFUSCATED.search(body):
        return Finding("response", "obfuscated-script", "malware", trap=False, status=502)
    return None


def external_location(location: str, own_hosts: set[str], allowed: list[str]) -> bool:
    host = _external_host(location)
    return bool(host) and host not in ({h.lower() for h in allowed} | own_hosts)
