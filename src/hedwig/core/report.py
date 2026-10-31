"""PM report: Jinja2 -> LaTeX -> tectonic -> PDF, optionally emailed over SMTP."""

import re
import shutil
import smtplib
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path

from jinja2 import Environment

from hedwig import settings
from hedwig.core import engine, runs
from hedwig.core.advisories import AdvisorySource
from hedwig.core.models import Finding, Run, ScanResult

TEMPLATE = Path(__file__).resolve().parent.parent / "data" / "report.tex.j2"
REPORTS = Path(".hedwig") / "reports"
TOP = 8
DEFAULT_SMTP = ("smtp.gmail.com", 587)  # used until smtp_host / smtp_port exist in settings
EVIDENCE = {
    0: "vulnerable version present",
    1: "the vulnerable code is called",
    2: "exploited in the wild (CISA KEV)",
    3: "attack attempts seen in the service logs",
    4: "signs of compromise in the service logs",
}
ACTION_TEXT = {
    "merged": "fix merged",
    "review_pr": "fix ready, waiting for human review",
    "failed_pr": "fix failed verification, PR left for a human",
    "takedown": "service taken down",
    "notify": "project manager notified",
    "none": "no action",
    "": "in progress",
}
_TEX_SPECIAL = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}


class ReportError(Exception):
    pass


def escape_tex(value) -> str:
    return "".join(_TEX_SPECIAL.get(ch, ch) for ch in str(value))


@dataclass
class ReportData:
    name: str
    root: str
    findings: list[Finding]
    runs: list[Run]
    summaries: dict[str, str]


def build(root: Path, target: str, result: ScanResult | None = None) -> ReportData:
    """Everything the report covers. `target` is a service name or a fix run id."""
    run = runs.load(root, target)
    if result is None:
        result = engine.load_last(root) or engine.scan(root, AdvisorySource(), save=False)
    if run:
        findings = [
            f for f in result.findings if f.service == run.service and f.package == run.package
        ]
        chosen, name = [run], f"{run.service}: {run.package} fix {run.run_id}"
    else:
        if target not in {s.name for s in result.services}:
            names = ", ".join(s.name for s in result.services) or "none"
            raise ReportError(
                f"'{target}' is neither a fix run id nor a service. Services: {names}"
            )
        findings = [f for f in result.findings if f.service == target]
        chosen, name = [r for r in runs.load_all(root) if r.service == target], f"Service {target}"
    summaries = {}
    for r in chosen:
        path = runs.run_dir(root, r.run_id) / "summary.txt"
        if path.is_file():
            summaries[r.run_id] = path.read_text(encoding="utf-8").strip()
    return ReportData(name, result.root, findings, chosen, summaries)


def duration(run: Run) -> str:
    if not run.finished_at:
        return "still running"
    seconds = (
        datetime.fromisoformat(run.finished_at) - datetime.fromisoformat(run.started_at)
    ).total_seconds()
    return (
        f"{int(seconds // 60)} min {int(seconds % 60)} s" if seconds >= 60 else f"{seconds:.0f} s"
    )


def _next_steps(data: ReportData) -> list[str]:
    steps = []
    for f in data.findings[:3]:
        if f.package_fix:
            steps.append(f"Bump {f.package} from {f.version} to {f.package_fix} in {f.service}.")
        else:
            steps.append(f"{f.package} has no fixed version: isolate {f.service} or remove it.")
    for r in data.runs:
        if r.action == "review_pr":
            steps.append(f"Review and merge branch {r.branch} ({r.service}).")
        if r.action == "failed_pr":
            steps.append(f"A person must fix {r.package} in {r.service}: {r.failed_step} failed.")
        if r.action == "takedown":
            steps.append(f"{r.service} is down. Patch it, verify it, then bring it back up.")
    return steps or ["Nothing needs attention right now."]


def render_tex(data: ReportData) -> str:
    env = Environment(
        block_start_string="((*",
        block_end_string="*))",
        variable_start_string="(((",
        variable_end_string=")))",
        comment_start_string="((#",
        comment_end_string="#))",
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["tex"] = escape_tex
    findings = data.findings
    counts = {
        s: sum(1 for f in findings if f.severity == s)
        for s in ("critical", "high", "medium", "low")
    }
    view = [
        _View(
            f,
            risk_text=f"{f.risk:.2f}",
            kev_text="yes" if f.kev else "no",
            evidence_text=EVIDENCE[f.evidence_level],
        )
        for f in findings
    ]
    run_views = [
        _View(
            r,
            to_version_text=r.to_version or "no fix",
            action_text=ACTION_TEXT.get(r.action, r.action),
            duration=duration(r),
            summary=data.summaries.get(r.run_id, ""),
        )
        for r in data.runs
    ]
    kev_count = sum(1 for f in findings if f.kev)
    worst = max(findings, key=lambda f: f.risk, default=None)
    summary = (
        f"Hedwig found {len(findings)} known vulnerabilities. "
        + (
            f"The highest risk is {worst.id} in {worst.package}@{worst.version} ({worst.service}). "
            if worst
            else ""
        )
        + (f"{kev_count} of them are being exploited in the wild. " if kev_count else "")
        + (
            f"{len(data.runs)} fix run(s) are covered below."
            if data.runs
            else "No fix has been run yet."
        )
    )
    template = env.from_string(TEMPLATE.read_text(encoding="utf-8"))
    return template.render(
        name=data.name,
        root=data.root,
        generated=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        summary=summary,
        findings=view,
        top=view[:TOP],
        counts=counts,
        kev_count=kev_count,
        runs=run_views,
        next_steps=_next_steps(data),
    )


class _View:
    """A model with a few extra display fields, for the template."""

    def __init__(self, model, **extra) -> None:
        self._model, self._extra = model, extra

    def __getattr__(self, name):
        if name in self._extra:
            return self._extra[name]
        return getattr(self._model, name)


def compile_pdf(root: Path, data: ReportData) -> Path:
    """Write the .tex and compile it. The .tex stays even if tectonic is missing."""
    folder = root / REPORTS
    folder.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", data.name).strip("-") or "report"
    stem += "-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    tex = folder / f"{stem}.tex"
    tex.write_text(render_tex(data), encoding="utf-8")
    if not shutil.which("tectonic"):
        raise ReportError(f"tectonic is not installed (see `hedwig doctor`); LaTeX saved at {tex}")
    done = subprocess.run(
        ["tectonic", "-X", "compile", "--outdir", str(folder), str(tex)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    pdf = tex.with_suffix(".pdf")
    if done.returncode != 0 or not pdf.is_file():
        raise ReportError(f"tectonic failed: {(done.stderr or done.stdout).strip()[-400:]}")
    return pdf


def smtp_server() -> tuple[str, int]:
    values = settings.load()
    return values.get("smtp_host") or DEFAULT_SMTP[0], int(
        values.get("smtp_port") or DEFAULT_SMTP[1]
    )


def email_pdf(pdf: Path, subject: str, body: str) -> str:
    """Send the PDF to the project manager. Returns the address it went to."""
    values = settings.load()
    user, password, to = values["smtp_user"], values["smtp_pass"], values["pm_email"]
    if not (user and password):
        raise ReportError("smtp_user / smtp_pass are not set, run: hedwig config")
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = user, to, subject
    message.set_content(body)
    message.add_attachment(
        pdf.read_bytes(), maintype="application", subtype="pdf", filename=pdf.name
    )
    host, port = smtp_server()
    try:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as err:
        raise ReportError(f"could not send the email: {err}") from err
    return to


def send_service_report(root: Path, service: str) -> str:
    """Build, compile and (if SMTP is set up) email a service report. Returns a status line."""
    data = build(root, service)
    pdf = compile_pdf(root, data)
    values = settings.load()
    if not (values["smtp_user"] and values["smtp_pass"]):
        return f"report saved at {pdf} (set smtp_user/smtp_pass to email it)"
    summary = next(iter(data.summaries.values()), f"Hedwig report for {service}.")
    to = email_pdf(pdf, f"Hedwig report: {service}", summary)
    return f"report emailed to {to}"
