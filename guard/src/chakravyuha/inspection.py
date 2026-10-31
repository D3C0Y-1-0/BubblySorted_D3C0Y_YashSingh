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
import io
import re
import zipfile
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
# -- malware and ransomware, in request text --------------------------------------------------
# What a dropper or ransomware does after it lands: wipe the backups, disable recovery, fetch and
# run more code, open a shell. Matching these in a request body means someone is trying to plant
# or run it. All of these are detection strings; nothing here runs anything.
MALWARE_TEXT: tuple[tuple[str, re.Pattern], ...] = (
    (
        "ransomware-command",
        re.compile(
            r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete"
            r"|wbadmin\s+delete\s+(?:catalog|systemstatebackup)"
            r"|bcdedit(?:\.exe)?\s+/set\s+\{?default\}?\s+(?:recoveryenabled\s+no|bootstatuspolicy)"
            r"|cipher(?:\.exe)?\s+/w[:\s]|openssl\s+enc\s+-aes[^\n]{0,80}-in\b",
            re.I,
        ),
    ),
    (
        "ransom-note",
        re.compile(
            r"(?:your|all)\s+(?:important\s+)?(?:files|data|documents)\s+(?:have\s+been|are|were)"
            r"\s+(?:encrypted|locked)|pay\s+(?:the\s+)?ransom|decryption\s+key"
            r"|send\s+[\d.]+\s*(?:btc|bitcoin|xmr|monero)|how_to_(?:decrypt|recover)"
            r"|read_?me_to_decrypt|\.onion\b",
            re.I,
        ),
    ),
    (
        "dropper-command",
        re.compile(
            r"(?:curl|wget)\s+[^|\n]{0,200}\|\s*(?:ba|z)?sh\b"
            r"|powershell(?:\.exe)?[^\n]{0,120}\s-(?:enc|encodedcommand)\b"
            r"|(?:iex|invoke-expression)[^\n]{0,80}(?:downloadstring|webclient)"
            r"|certutil(?:\.exe)?\s+-urlcache|bitsadmin\s+/transfer",
            re.I,
        ),
    ),
    (
        "reverse-shell",
        re.compile(
            r"bash\s+-i\s*>&\s*/dev/tcp/|\bnc(?:at)?\b[^\n]{0,30}\s-e\s+/bin/(?:ba)?sh"
            r"|/dev/tcp/[\d.]+/\d+|socket\.socket\([^\n]{0,200}os\.dup2",
            re.I,
        ),
    ),
)
RANSOM_EXTENSIONS = re.compile(
    r"\.(?:locked|lockbit|encrypted|crypted|crypt|wncry|wnry|wcry|ryk|ryuk|conti|cerber|locky"
    r"|petya|zepto|odin|hive|babuk|djvu|akira|royal|blackcat)$",
    re.I,
)
EXECUTABLE_NAMES = re.compile(
    r"\.(?:exe|dll|scr|bat|cmd|com|ps1|vbs|vbe|jse?|wsf|hta|msi|jar|lnk|sh)$", re.I
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
        for name, pattern in MALWARE_TEXT:
            if pattern.search(text):
                return Finding("request", name, "malware", trap=True)
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


FILENAME = re.compile(rb"filename\*?\s*=\s*(?:UTF-8'')?\"?([^\";\r\n]+)", re.I)
JSON_FILENAME = re.compile(rb'"(?:file_?name|name)"\s*:\s*"([^"\\]{1,255})"', re.I)
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
OLE_MACRO = re.compile(rb"AutoOpen|Document_Open|Auto_Open|Workbook_Open|CreateObject\(", re.I)
MAX_ARCHIVE_BYTES = 8_000_000


def _parts(body: bytes) -> list[tuple[str, bytes]]:
    """(filename, content) for each part of a multipart body, or the whole body as one part."""
    if body.startswith(b"--"):
        boundary = body.split(b"\r\n", 1)[0]
        parts = []
        for chunk in body.split(boundary)[1:]:
            head, _, content = chunk.partition(b"\r\n\r\n")
            if not content:
                continue
            named = FILENAME.search(head)
            parts.append((named.group(1).decode("utf-8", "replace") if named else "",
                          content.rstrip(b"\r\n-")))  # fmt: skip
        if parts:
            return parts
    names = [m.group(1).decode("utf-8", "replace") for m in JSON_FILENAME.finditer(body[:65536])]
    return [(names[0] if names else "", body)]


def _extension(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _archive(content: bytes) -> Finding | None:
    """A zip that holds an executable or an Office macro. Only the file names are read."""
    if not content.startswith(b"PK\x03\x04") or len(content) > MAX_ARCHIVE_BYTES:
        return None
    try:
        names = zipfile.ZipFile(io.BytesIO(content)).namelist()
    except (zipfile.BadZipFile, OSError):
        return None
    if any(name.lower().endswith("vbaproject.bin") for name in names):
        return Finding("upload", "office-macro", "malware", trap=True)
    if any(EXECUTABLE_NAMES.search(name) for name in names):
        return Finding("upload", "archive-executable", "malware", trap=True)
    return None


def _check_part(filename: str, content: bytes, uploads) -> Finding | None:
    head = content[:4096]
    if EICAR in content[:1024]:
        return Finding("upload", "eicar", "malware", trap=True)
    if WEBSHELL.search(content[:65536]):
        return Finding("upload", "webshell", "malware", trap=True)
    if filename and RANSOM_EXTENSIONS.search(filename):
        return Finding("upload", "ransomware-extension", "malware", trap=True)
    if filename and EXECUTABLE_NAMES.search(filename):
        return Finding("upload", "executable-filename", "malware", trap=True)
    if head.startswith(OLE_MAGIC) and OLE_MACRO.search(content[:262144]):
        return Finding("upload", "office-macro", "malware", trap=True)
    archive = _archive(content)
    if archive:
        return archive
    for magic, label in MAGIC:
        if head.startswith(magic):
            # a zip is only suspicious where uploads are off (office files are zips)
            if label == "zip" and uploads is not False:
                break
            return Finding("upload", f"executable-{label}", "malware", trap=True)
    if (
        filename
        and isinstance(uploads, list)
        and _extension(filename) not in {e.lower().lstrip(".") for e in uploads}
    ):
        return Finding("upload", "disallowed-extension", "malware", trap=False, status=415)
    return None


def scan_upload(body: bytes, uploads, blocked_hashes: set[str]) -> Finding | None:
    """A body is inspected when the service does not allow uploads, or allows only some kinds
    and this one is dangerous. `uploads` is False, True or a list of allowed extensions.
    Multipart bodies are taken apart, so a file inside one is judged like a raw upload."""
    if not body:
        return None
    if blocked_hashes and hashlib.sha256(body).hexdigest() in blocked_hashes:
        return Finding("upload", "blocklisted-hash", "malware", trap=True)
    for filename, content in _parts(body):
        if blocked_hashes and hashlib.sha256(content).hexdigest() in blocked_hashes:
            return Finding("upload", "blocklisted-hash", "malware", trap=True)
        found = _check_part(filename, content, uploads)
        if found:
            return found
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
