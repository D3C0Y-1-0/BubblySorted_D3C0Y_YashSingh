"""What the dashboard shows about the bank and Hedwig: the architecture with live status, the
infrastructure, the scan findings, fix runs, incidents and SOC reports.

Everything is read from Hedwig's files in the bank folder (`.hedwig/`, `.hedwig.yml`) and from
live probes. The Guard never imports `hedwig`; when asked to run it, it starts the `hedwig`
command like a person would.
"""

import json
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import yaml

PROBE_TIMEOUT = 1.0
AUDIT_TAIL = 60
SNIPPET_CONTEXT = 3
MAX_FINDINGS = 400
INFRA = (
    ("postgres", "database", "tcp", 15432),
    ("redis", "cache", "redis", 16379),
    ("qdrant", "vector store", "http://127.0.0.1:16333/healthz", 16333),
    ("elasticsearch", "event store", "http://127.0.0.1:19200", 19200),
    ("logstash", "event pipeline", "http://127.0.0.1:19600", 19600),
    ("kibana", "search and dashboards", "http://127.0.0.1:15601/api/status", 15601),
)
STACK = {"java": "Java", "rust": "Rust", "php": "PHP", "node": "Node", "python": "Python"}


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _http(url: str) -> tuple[bool, str]:
    try:
        reply = httpx.get(url, timeout=PROBE_TIMEOUT)
    except httpx.HTTPError:
        return False, ""
    version = ""
    try:
        version = str(reply.json().get("version", {}).get("number", ""))
    except (ValueError, AttributeError):
        pass
    return reply.status_code < 500, version


def _tcp(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=PROBE_TIMEOUT):
            return True
    except OSError:
        return False


def _redis(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=PROBE_TIMEOUT) as sock:
            sock.sendall(b"PING\r\n")
            return sock.recv(16).startswith(b"+PONG")
    except OSError:
        return False


def _probe(item: tuple) -> dict[str, Any]:
    name, role, how, port = item
    version = ""
    if how == "tcp":
        up = _tcp(port)
    elif how == "redis":
        up = _redis(port)
    else:
        up, version = _http(how)
    return {
        "name": name,
        "role": role,
        "port": port,
        "status": "active" if up else "down",
        "version": version,
    }


def infra() -> list[dict[str, Any]]:
    with ThreadPoolExecutor(max_workers=len(INFRA)) as pool:
        return list(pool.map(_probe, INFRA))


def architecture(services: dict[str, Any], bank: Path | None) -> list[dict[str, Any]]:
    """One entry per bank service: tech stack, tier and whether it answers its health path."""
    project = (yaml.safe_load((bank / ".hedwig.yml").read_text()) or {}) if bank else {}
    declared = (project.get("services") or {}) if isinstance(project, dict) else {}

    def one(item: tuple[str, Any]) -> dict[str, Any]:
        name, svc = item
        info = declared.get(name) or {}
        language = info.get("language") or "static"
        up, _ = _http(svc.upstream.rstrip("/") + svc.health_path)
        return {
            "name": name,
            "stack": STACK.get(language, language.title()),
            "tier": info.get("tier", "-"),
            "port": svc.upstream.rsplit(":", 1)[-1].rstrip("/"),
            "status": "active" if up else "down",
        }

    with ThreadPoolExecutor(max_workers=max(1, len(services))) as pool:
        return list(pool.map(one, services.items()))


def _findings(scan: dict) -> list[dict[str, Any]]:
    keep = (
        "id", "severity", "risk", "service", "package", "version", "reachability", "summary",
        "reasoning", "package_fix", "evidence_level", "kev", "tier", "kind",
    )  # fmt: skip
    found = []
    for f in scan.get("findings", [])[:MAX_FINDINGS]:
        item = {k: f.get(k) for k in keep}
        item["decision"] = (f.get("decision") or {}).get("action", "")
        item["call_sites"] = f.get("call_sites", [])[:8]
        found.append(item)
    return found


def hedwig_data(bank: Path | None) -> dict[str, Any]:
    if bank is None or not (bank / ".hedwig").is_dir():
        return {"scanned_at": "", "findings": [], "runs": [], "incidents": [], "audit": [],
                "note": "Run `hedwig scan` in guard/bank to fill this in."}  # fmt: skip
    state = bank / ".hedwig"
    scan = _json(state / "last-scan.json") or {}
    runs = [r for p in sorted((state / "runs").glob("*/run.json"))[-30:] if (r := _json(p))]
    incidents = [i for p in sorted((state / "incidents").glob("*.json"))[-20:] if (i := _json(p))]
    audit: list[dict] = []
    log = state / "audit.jsonl"
    if log.is_file():
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines()[-AUDIT_TAIL:]:
            try:
                audit.append(json.loads(line))
            except ValueError:
                continue
    for run in runs:
        run.pop("steps", None)
    return {
        "scanned_at": scan.get("generated_at", ""),
        "findings": _findings(scan),
        "runs": list(reversed(runs)),
        "incidents": list(reversed(incidents)),
        "audit": audit,
        "note": "" if scan else "Run `hedwig scan` in guard/bank to fill this in.",
    }


def snippet(bank: Path | None, service: str, file: str, line: int) -> dict[str, Any]:
    """A few source lines around a call site. The path must stay inside the service folder."""
    if bank is None:
        return {"lines": []}
    folder = (bank / service).resolve()
    path = (folder / file).resolve()
    if folder not in path.parents or not path.is_file():
        return {"lines": []}
    try:
        text = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return {"lines": []}
    low, high = max(1, line - SNIPPET_CONTEXT), min(len(text), line + SNIPPET_CONTEXT)
    return {
        "lines": [{"n": n, "text": text[n - 1], "hit": n == line} for n in range(low, high + 1)]
    }


def soc_reports(bank: Path | None) -> list[dict[str, Any]]:
    if bank is None:
        return []
    files = sorted((bank / ".hedwig" / "reports").glob("SOC-*.pdf"), reverse=True)[:10]
    return [{"name": p.name, "at": p.stat().st_mtime} for p in files]


def soc_file(bank: Path | None, name: str) -> Path | None:
    if bank is None or "/" in name or not name.startswith("SOC-") or not name.endswith(".pdf"):
        return None
    path = bank / ".hedwig" / "reports" / name
    return path if path.is_file() else None


def run_hedwig(bank: Path | None, args: list[str], repo: Path) -> tuple[bool, str]:
    """Start the hedwig command in the bank folder (the user's own tool, like a terminal)."""
    if bank is None:
        return False, "no bank folder configured"
    command = ["uv", "run", "--project", str(repo), "hedwig"]
    if shutil.which("hedwig"):  # the installed one, when it knows the command
        probe = subprocess.run(["hedwig", args[0], "--help"], capture_output=True)
        if probe.returncode == 0:
            command = ["hedwig"]
    try:
        done = subprocess.run(
            [*command, *args], cwd=bank, capture_output=True, text=True, timeout=300
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        return False, f"{type(err).__name__}: {err}"
    return done.returncode == 0, (done.stdout + done.stderr).strip()[-600:]
