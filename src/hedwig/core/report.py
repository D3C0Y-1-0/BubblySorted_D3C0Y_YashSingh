"""PM report: Jinja2 -> LaTeX -> tectonic -> PDF, optionally emailed over SMTP."""

import re
import smtplib
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path

from jinja2 import Environment
from rich.console import Console

from hedwig import settings
from hedwig.core import engine, incidents, runs, tools
from hedwig.core.advisories import AdvisorySource
from hedwig.core.models import Finding, Incident, Run, ScanResult

console = Console()
TEMPLATE = Path(__file__).resolve().parent.parent / "data" / "report.tex.j2"
REPORTS = Path(".hedwig") / "reports"
TOP = 8
COMPILE_TIMEOUT = 600  # the first run fetches TeX support files
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
    "rolled_back": "fix merged, did not come up, rolled back",
    "deploy_failed": "fix merged, service did not come up",
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
    incidents: list[Incident] = field(default_factory=list)


def build(root: Path, target: str, result: ScanResult | None = None) -> ReportData:
    """Everything the report covers. `target` is a service name or a fix run id."""
    incident = incidents.load(root, target)
    if incident:
        chosen = [r for rid in incident.run_ids if (r := runs.load(root, rid))]
        summaries = {}
        for r in chosen:
            path = runs.run_dir(root, r.run_id) / "summary.txt"
            if path.is_file():
                summaries[r.run_id] = path.read_text(encoding="utf-8").strip()
        name = f"Incident {incident.service}: PR #{incident.pr_number}"
        return ReportData(name, str(root), incident.findings, chosen, summaries, [incident])
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
    related = [i for i in incidents.load_all(root) if run is None and i.service == target]
    return ReportData(name, result.root, findings, chosen, summaries, related)


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
    seen: set[tuple[str, str]] = set()
    for f in data.findings:
        if (f.service, f.package) in seen or len(seen) == 3:
            continue
        seen.add((f.service, f.package))
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
    incident_views = [
        _View(
            i,
            downtime_text=seconds_text(i.downtime_seconds),
            rows=[_View(e, when=_stamp(e.at)) for e in i.timeline],
        )
        for i in data.incidents
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
    if data.incidents:
        summary = _incident_summary(data.incidents[0]) if len(data.incidents) == 1 else summary
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
        incidents=incident_views,
        next_steps=_next_steps(data),
    )


def _stamp(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def seconds_text(value: float | None) -> str:
    if value is None:
        return "not applicable"
    return f"{int(value // 60)} min {int(value % 60)} s" if value >= 60 else f"{value:.0f} s"


def _incident_summary(i: Incident) -> str:
    where = {
        "contained": "The service is back up with the vulnerable packages fixed.",
        "down": "The service is STILL DOWN: the fix could not be verified or deployed.",
        "failed": "Hedwig could not respond (see the timeline); a person must act.",
    }.get(i.state, "The response is still running.")
    return (
        f"Pull request #{i.pr_number} ({i.pr_title}) was merged and introduced "
        f"{len(i.findings)} known vulnerabilities into {i.service}. Hedwig noticed on its own. "
        f"{where} Downtime: {seconds_text(i.downtime_seconds)}."
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
    """Write the .tex and compile it. The .tex stays even if the PDF cannot be built."""
    folder = root / REPORTS
    folder.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", data.name).strip("-") or "report"
    stem += "-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    tex = folder / f"{stem}.tex"
    tex.write_text(render_tex(data), encoding="utf-8")
    try:
        tectonic = tools.ensure_tectonic(say=lambda text: console.print(text))
    except tools.ToolError as err:
        raise ReportError(f"{err} (LaTeX saved at {tex})") from err
    try:
        done = subprocess.run(
            [str(tectonic), "-X", "compile", "--outdir", str(folder), str(tex)],
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )
    except subprocess.TimeoutExpired as err:
        raise ReportError(
            f"tectonic timed out (is the network up? it fetches TeX files on first use). "
            f"LaTeX saved at {tex}"
        ) from err
    pdf = tex.with_suffix(".pdf")
    if done.returncode != 0 or not pdf.is_file():
        raise ReportError(
            f"tectonic failed: {(done.stderr or done.stdout).strip()[-600:]}\nLaTeX saved at {tex}"
        )
    return pdf


def smtp_server() -> tuple[str, int]:
    values = settings.load()
    return values.get("smtp_host") or DEFAULT_SMTP[0], int(
        values.get("smtp_port") or DEFAULT_SMTP[1]
    )


def email_pdf(pdf: Path, subject: str, body: str) -> str:
    """Send the PDF to the project manager. Returns the address it went to."""
    values = settings.load()
    missing = [key for key in ("smtp_user", "smtp_pass") if not values[key]]
    if missing:
        raise ReportError(f"{' and '.join(missing)} not set. Run: hedwig config")
    user, to = values["smtp_user"], values["pm_email"]
    password = values["smtp_pass"].replace(" ", "")  # Google shows app passwords in 4 groups
    if "@" not in to:
        raise ReportError(f"pm_email '{to}' is not an email address. Run: hedwig config")
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
    except smtplib.SMTPServerDisconnected as err:
        raise ReportError(
            f"{host} closed the connection while logging in. That usually means the password is "
            f"wrong: smtp_pass is {len(password)} characters, a Gmail app password is 16. "
            "Create one at myaccount.google.com/apppasswords, then run: hedwig config"
        ) from err
    except smtplib.SMTPAuthenticationError as err:
        raise ReportError(
            f"{host} rejected the login for {user}. For Gmail use an app password "
            "(Google account > Security > 2-step verification > App passwords)"
        ) from err
    except (OSError, smtplib.SMTPException) as err:
        raise ReportError(f"could not send the email through {host}:{port}: {err}") from err
    return to


@dataclass
class Sent:
    ok: bool
    message: str
    pdf: Path | None = None


def mail_body(data: ReportData) -> str:
    """Plain-text body: the newest summary, what was found and what Hedwig did."""
    lines = [f"Hedwig report: {data.name}", ""]
    if data.summaries and not data.incidents:
        lines += [next(iter(data.summaries.values())), ""]
    for incident in data.incidents:
        lines += [_incident_summary(incident), "", "Timeline (UTC):"]
        lines += [f"- {_stamp(e.at)}  {e.event}  {e.detail}".rstrip() for e in incident.timeline]
        lines.append("")
    lines.append(f"{len(data.findings)} finding(s):")
    for f in data.findings[:8]:
        lines.append(f"- {f.id} {f.package}@{f.version} ({f.severity}, risk {f.risk:.2f})")
    if data.runs:
        lines += ["", "Fix runs:"]
        for r in data.runs[:8]:
            lines.append(
                f"- {r.package} {r.from_version} to {r.to_version or 'no fix'}: {r.state}, "
                f"{ACTION_TEXT.get(r.action, r.action)} ({duration(r)})"
            )
    lines += ["", "The full report is attached as a PDF."]
    return "\n".join(lines)


def send_service_report(root: Path, service: str) -> Sent:
    """Build, compile and email a service report. Never raises; says why if it could not."""
    try:
        data = build(root, service)
        pdf = compile_pdf(root, data)
        to = email_pdf(pdf, f"Hedwig report: {service}", mail_body(data))
    except ReportError as err:
        return Sent(False, str(err))
    except Exception as err:  # reporting must never break a fix run
        return Sent(False, f"{type(err).__name__}: {err}")
    return Sent(True, f"report emailed to {to}", pdf)


def send_incident_report(root: Path, incident: Incident) -> Sent:
    """Build, compile and email the incident report. Never raises."""
    try:
        data = build(root, incident.incident_id)
        pdf = compile_pdf(root, data)
        state = "contained" if incident.state == "contained" else "service still down"
        subject = f"Hedwig incident: {incident.service} ({state}), PR #{incident.pr_number}"
        to = email_pdf(pdf, subject, mail_body(data))
    except ReportError as err:
        return Sent(False, str(err))
    except Exception as err:
        return Sent(False, f"{type(err).__name__}: {err}")
    return Sent(True, f"report emailed to {to}", pdf)
