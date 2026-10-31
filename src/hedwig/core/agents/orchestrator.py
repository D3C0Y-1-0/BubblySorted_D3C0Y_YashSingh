"""The fixing pipeline. Plain Python: agents propose, the code and the policy gate decide.

    plan -> (fixer -> checks -> tester -> tests + old-vs-new + re-scan -> verifier) x up to 3
    -> reporter -> act

Everything happens in git worktrees under .hedwig/work/, so the working copy is never touched.
"""

import re
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from hedwig.core import actions, audit, bump, deploy, engine, github, runner, runs
from hedwig.core.advisories import AdvisorySource
from hedwig.core.agents import fixer, guards, reporter, tester, verifier
from hedwig.core.agents.tester import known_requests
from hedwig.core.code_index import CodeIndex, _matches, module_names
from hedwig.core.llm import AgentError
from hedwig.core.models import Finding, Package, Run, Step

MAX_RETRIES = 2
MAX_ALLOWED_CODE_FILES = 8
StepCallback = Callable[[Run, Step], None]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")


class _Pipeline:
    def __init__(self, root: Path, run: Run, on_step: StepCallback | None) -> None:
        self.root, self.run, self.on_step = root, run, on_step

    def begin(self, name: str, detail: str = "") -> Step:
        step = Step(name=name, status="running", detail=detail)
        self.run.steps.append(step)
        self._publish(step)
        return step

    def end(self, step: Step, status: str, detail: str = "") -> None:
        step.status, step.at = status, _now()
        if detail:
            step.detail = detail
        audit.record(self.root, "step", run=self.run.run_id, step=step.name, status=status)
        self._publish(step)

    def _publish(self, step: Step) -> None:
        runs.save(self.root, self.run)
        if self.on_step:
            self.on_step(self.run, step)


def _lead(findings: list[Finding]) -> Finding:
    """The finding whose evidence decides the policy outcome."""
    return max(findings, key=lambda f: (f.evidence_level, f.risk))


def _allowed_files(
    spec: engine.ServiceSpec, findings: list[Finding]
) -> tuple[list[str], list[str]]:
    """The manifest, plus the source files that import or call the package. Returns (all, code)."""
    first = findings[0]
    package = Package(
        ecosystem=first.ecosystem,
        name=first.package,
        version=first.version,
        service=spec.name,
        manifest=first.manifest,
    )
    names = module_names(package)
    code = {site.file for f in findings for site in f.call_sites}
    for facts in CodeIndex(spec.folder).files():
        if any(_matches(item.module, names) for item in facts.imports):
            code.add(facts.path)
    code_files = sorted(code)[:MAX_ALLOWED_CODE_FILES]
    return [bump.manifest_for(first), *code_files], code_files


def _service_ids(source: AdvisorySource, folder: Path) -> set[str]:
    """Advisory ids a scan of this folder alone reports."""
    return {i for f in engine.scan(folder, source, save=False).findings for i in f.ids}


def _finish(root: Path, run: Run, state: str, action: str) -> Run:
    run.state, run.action, run.finished_at = state, action, _now()
    runs.save(root, run)
    audit.record(root, "run", run=run.run_id, state=state, action=action, service=run.service)
    return run


def run_fix(
    root: Path,
    findings: list[Finding],
    spec: engine.ServiceSpec,
    source: AdvisorySource,
    on_step: StepCallback | None = None,
    publish: bool = True,
) -> Run:
    """Fix one package of one service. `findings` are all the advisories on that package."""
    findings = sorted(findings, key=lambda f: -f.risk)
    top, lead = findings[0], _lead(findings)
    run = Run(
        run_id=runner.new_run_id(spec.name),
        service=spec.name,
        package=top.package,
        ecosystem=top.ecosystem,
        from_version=top.version,
        to_version=top.package_fix,
        advisories=sorted({i for f in findings for i in [f.id]}),
        decision=lead.decision,
    )
    pipe = _Pipeline(root, run, on_step)
    runs.save(root, run)
    decision = lead.decision

    # Policy comes first: some findings never enter the fixing pipeline.
    if decision.action == "takedown":
        step = pipe.begin("act", decision.reason)
        note = actions.takedown(root, spec.name, decision.reason)
        pipe.end(step, "ok", f"service taken down ({note})")
        return _finish(root, run, "skipped", "takedown")
    if decision.action == "notify":
        step = pipe.begin("act", decision.reason)
        pipe.end(step, "ok", "the project manager is notified in the report")
        return _finish(root, run, "skipped", "notify")

    step = pipe.begin("plan")
    target = top.package_fix
    if not target:
        pipe.end(
            step, "skipped", "no fixed version exists; isolate the service or drop the package"
        )
        return _finish(root, run, "skipped", "notify")
    if bump.declared(spec.folder, top) is None:
        pipe.end(
            step, "skipped", f"{top.package} is transitive; Hedwig only bumps direct dependencies"
        )
        return _finish(root, run, "skipped", "notify")
    repo = runner.toplevel(spec.folder)
    if repo is None:
        pipe.end(step, "failed", "the service is not inside a git repository")
        run.failed_step = "plan"
        return _finish(root, run, "failed", "none")

    if not runner.has_commits(repo):
        pipe.end(step, "failed", "the repository has no commits yet; commit your code first")
        run.failed_step = "plan"
        return _finish(root, run, "failed", "none")
    runner.hide_state_dir(repo, root)
    relative = spec.folder.resolve().relative_to(repo).as_posix() or "."
    allowed, code_files = _allowed_files(spec, findings)
    run.branch = runner.free_branch(repo, f"hedwig/fix/{spec.name}/{_slug(top.package)}-{target}")
    base_sha = runner.git(repo, "rev-parse", "HEAD").stdout.strip()
    new_wt = root / runs.WORK / run.run_id
    base_wt = root / runs.WORK / f"{run.run_id}-base"
    note = f"{top.package} {top.version} -> {target}, branch {run.branch}"
    if runner.is_dirty(repo, relative):
        note += " (uncommitted changes in the service are not included)"
    pipe.end(step, "ok", note)

    verified, failures, stat = False, [], ""
    try:
        runner.add_worktree(repo, new_wt, run.branch)
        runner.add_worktree(repo, base_wt, None)
        new_folder = new_wt / relative
        base_folder = base_wt / relative
        verified, failures = _attempts(
            pipe, root, spec, findings, source, target, allowed, code_files,
            repo, relative, new_wt, new_folder, base_folder,
        )  # fmt: skip
        diff = runner.diff_text(new_wt, relative)
        stat = runner.diff_stat(new_wt, relative)
        runs.write_artifact(root, run.run_id, "diff.patch", diff)
        changed = _changed_paths(new_wt, relative)
        if changed:
            runner.commit(new_wt, changed, f"[fix] {top.package} {top.version} -> {target}")
    except (RuntimeError, OSError) as err:
        step = pipe.begin("run")
        pipe.end(step, "failed", str(err))
        run.failed_step = run.failed_step or "run"
        failures = [str(err)]
    finally:
        runner.remove_worktree(repo, new_wt)
        runner.remove_worktree(repo, base_wt)
        shutil.rmtree(root / runs.WORK / run.run_id, ignore_errors=True)

    run.violations = failures
    run.state = "verified" if verified else "failed"
    run.verification = _classify(verified, failures)
    runs.write_artifact(
        root,
        run.run_id,
        "verdict.json",
        {
            "verified": verified,
            "failed_step": run.failed_step,
            "violations": run.violations,
            "attempts": run.attempts,
        },
    )
    runs.write_artifact(root, run.run_id, "plan.json", {"target": target, "allowed": allowed})

    step = pipe.begin("reporter")
    try:
        text = reporter.write(root, lead, run, stat, run.violations or ["all checks passed"])
    except AgentError as err:
        text = reporter.Text(
            pr_title=f"Bump {top.package} to {target}",
            pr_body=f"Hedwig bumped {top.package} from {top.version} to {target}.",
            report_summary=f"Hedwig bumped {top.package}. Verified: {verified}.",
        )
        pipe.end(step, "skipped", f"using a plain summary ({err})")
    else:
        pipe.end(step, "ok")
    runs.write_artifact(root, run.run_id, "summary.txt", text.report_summary)

    run = _act(pipe, root, repo, spec, run, lead, text, verified, publish, base_sha)
    _append_location(root, run, text.report_summary)
    return run


UNAVAILABLE = (
    "not installed", "no tests", "no test_cmd", "daemon is not running", "no dockerfile",
    "install failed", "could not create a virtualenv", "no test or build", "pip install",
)  # fmt: skip


def _classify(verified: bool, failures: list[str]) -> str:
    """passed, failed, or unavailable (the checks could not run, so nothing was disproved)."""
    if verified:
        return "passed"
    text = " ".join(failures).lower()
    return "unavailable" if any(marker in text for marker in UNAVAILABLE) else "failed"


def _publishable(repo: Path, run: Run, base_sha: str) -> bool:
    """A PR is worth opening when the bump is real: the branch has commits and the guards held.

    A failed test or comparison does not stop it (the PR says so). A bump that could not be
    applied, or edits that broke a rule, do.
    """
    if run.failed_step not in ("", "run", "verifier") or not run.branch:
        return False
    head = runner.git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{run.branch}")
    return head.returncode == 0 and head.stdout.strip() != base_sha


def _verification_lines(run: Run) -> str:
    last = {step.name: step for step in run.steps if step.name in ("checks", "run", "verifier")}
    lines = [f"- **{s.name}**: {s.status}. {s.detail}" for s in last.values()]
    return "\n".join(lines) or "- no check ran"


def _publish(pipe: _Pipeline, repo: Path, run: Run, title: str, body: str) -> None:
    """Push the fix branch and open the PR: normal when verified, draft when not."""
    step = pipe.begin("publish")
    reason = github.unavailable(repo)
    if reason:
        pipe.end(step, "skipped", f"{reason}; the fix stays on branch {run.branch}")
        return
    label = {
        "passed": "hedwig:needs-review",
        "unavailable": "hedwig:unverified",
        "failed": "hedwig:verification-failed",
    }[run.verification]
    note = {
        "passed": "All checks passed.",
        "unavailable": "**Verification could not run**, so this is a draft. The version change "
        "itself is real.",
        "failed": "**Verification ran and failed**, so this is a draft.",
    }[run.verification]
    full = (
        f"{body}\n\n## Hedwig verification\n{note}\n\n{_verification_lines(run)}\n\n"
        "_Opened by Hedwig._"
    )
    try:
        pr = github.create_pr(
            repo, run.branch, title, full, label, draft=run.verification != "passed"
        )
    except github.GitHubError as err:
        pipe.end(step, "failed", f"{err}; the fix stays on branch {run.branch}")
        return
    run.pr_url = pr.url
    pipe.end(step, "ok", pr.url)


def _deploy_after_merge(
    pipe: _Pipeline, root: Path, repo: Path, spec: engine.ServiceSpec, run: Run, before: str
) -> str:
    """Rebuild and restart the service from the merged code, rolling back if it does not come up.

    Returns the run's outcome: merged, rolled_back or deploy_failed. Nothing happens without a
    compose file.
    """
    if deploy.compose_file(root) is None:
        return "merged"
    step = pipe.begin("deploy", f"rebuild {run.service}")
    ok, detail = _rebuild_and_smoke(root, spec)
    if ok:
        actions.clear_down(root, run.service)
        pipe.end(step, "ok", detail)
        return "merged"
    if "rollback" not in spec.allow:
        pipe.end(step, "failed", f"{detail}; rollback is not allowed for this service")
        return "deploy_failed"
    reverted = runner.git(repo, *runner.BOT, "revert", "--no-edit", f"{before}..HEAD")
    if reverted.returncode != 0:
        pipe.end(step, "failed", f"{detail}; the revert failed: {reverted.stderr.strip()[-200:]}")
        return "deploy_failed"
    again, more = _rebuild_and_smoke(root, spec)
    if again:
        actions.clear_down(root, run.service)
    pipe.end(step, "failed", f"{detail}; rolled back to the previous version ({more})")
    audit.record(root, "action", action="rollback", service=run.service, ok=again)
    return "rolled_back"


def _rebuild_and_smoke(root: Path, spec: engine.ServiceSpec) -> tuple[bool, str]:
    try:
        deploy.rebuild(root, spec.name)
    except deploy.DeployError as err:
        return False, str(err)
    return deploy.smoke(root, spec.name, spec.health_path)


def _append_location(root: Path, run: Run, summary: str) -> None:
    """Say where the change is, in words from code. The Reporter cannot be trusted with that."""
    where = {
        "merged": f"The change is merged into your current branch (also on {run.branch}).",
        "rolled_back": "The fix was merged but the service did not come up, so the merge was "
        f"reverted (branch {run.branch}).",
        "deploy_failed": "The fix was merged but the service did not come up "
        f"(branch {run.branch}).",
        "takedown": f"The service was taken down. The change is only on branch {run.branch}.",
    }.get(
        run.action,
        f"The change is only on branch {run.branch}. It is not in your working files until you "
        f"merge it (git merge {run.branch}).",
    )
    if run.state == "failed":
        where = "It did NOT pass verification. " + where
    if run.pr_url:
        where += f" Pull request: {run.pr_url}"
    runs.write_artifact(root, run.run_id, "summary.txt", f"{summary} {where}".strip())


def _changed_paths(worktree: Path, relative: str) -> list[str]:
    out = runner.git(worktree, "status", "--porcelain", "-uall", "--", relative).stdout
    return [line[3:].strip().strip('"') for line in out.splitlines() if line.strip()]


def _attempts(
    pipe: _Pipeline,
    root: Path,
    spec: engine.ServiceSpec,
    findings: list[Finding],
    source: AdvisorySource,
    target: str,
    allowed: list[str],
    code_files: list[str],
    repo: Path,
    relative: str,
    new_wt: Path,
    new_folder: Path,
    base_folder: Path,
) -> tuple[bool, list[str]]:
    run, top = pipe.run, findings[0]
    failures: list[str] = []
    has_image = (spec.folder / "Dockerfile").is_file()
    env_problem = runner.docker_ready(spec.folder) if has_image else None
    baseline = _service_ids(source, spec.folder)
    cases: list[dict] = []
    for attempt in range(MAX_RETRIES + 1):
        run.attempts = attempt + 1
        if attempt:
            runner.reset_service(repo, new_wt, relative)
        step = pipe.begin("plan", f"attempt {attempt + 1}: bump {top.package} to {target}")
        error = bump.apply(new_folder, top, target) or bump.regenerate_lock(new_folder, top, target)
        if error:
            pipe.end(step, "failed", error)
            run.failed_step = "plan"
            return False, [error]
        pipe.end(step, "ok")

        if code_files and (top.call_sites or failures):
            step = pipe.begin("fixer", f"attempt {attempt + 1}")
            try:
                proposal = fixer.propose(root, new_folder, top, target, allowed, failures)
            except AgentError as err:
                pipe.end(step, "failed", str(err))
                failures, run.failed_step = [str(err)], "fixer"
                continue
            violations = guards.apply_edits(new_folder, proposal.edits, allowed)
            if violations:
                pipe.end(step, "failed", "; ".join(violations))
                failures, run.failed_step = violations, "fixer"
                continue
            if any(e.path == bump.manifest_for(top) for e in proposal.edits):
                error = bump.regenerate_lock(new_folder, top, target)
                if error:
                    pipe.end(step, "failed", error)
                    failures, run.failed_step = [error], "fixer"
                    continue
            pipe.end(step, "ok", f"{len(proposal.edits)} edit(s): {proposal.rationale}")

        violations = guards.check_result(base_folder, new_folder, top, target, allowed)
        if violations:
            step = pipe.begin("checks")
            pipe.end(step, "failed", "; ".join(violations))
            failures, run.failed_step = violations, "checks"
            continue

        cases = []
        if top.call_sites:
            step = pipe.begin("tester")
            try:
                cases = [c.model_dump() for c in tester.propose(root, new_folder, top)]
                pipe.end(step, "ok", f"{len(cases)} case(s)")
            except AgentError as err:
                pipe.end(step, "skipped", f"using recorded requests only ({err})")

        step = pipe.begin("run", "tests, old-vs-new comparison, re-scan")
        checks = [runner.run_tests(new_folder, top, spec.test_cmd)]
        if checks[0].ok and env_problem:
            checks.append(runner.Check("differential", False, env_problem))
        elif checks[0].ok and has_image:
            diff_check, kept = runner.differential(
                base_folder, new_folder, run.run_id, spec.port, spec.health_path,
                known_requests(spec.folder) + cases,
            )  # fmt: skip
            checks.append(diff_check)
            cases = kept
        elif checks[0].ok:
            checks.append(runner.Check("differential", True, "no Dockerfile", ran=False))
        checks.append(_rescan_check(source, new_folder, top, baseline))
        failed = [c for c in checks if not c.ok]
        if not failed and not any(c.ran for c in checks if c.name != "re-scan"):
            failed = [runner.Check("verification", False, "no tests, build or Dockerfile to run")]
            checks += failed
        pipe.end(step, "failed" if failed else "ok", "; ".join(c.line() for c in checks))
        runs.write_artifact(root, run.run_id, "cases.json", cases)
        if failed:
            run.failed_step = "run"
            failures = [c.line() for c in failed]
            if (
                (env_problem and checks[0].ok)
                or not code_files
                or _classify(False, failures) == "unavailable"
            ):
                return False, failures  # no code the Fixer may edit, so a retry changes nothing
            continue

        step = pipe.begin("verifier")
        diff = runner.diff_text(new_wt, relative, _reviewable(new_wt, relative))
        try:
            review = verifier.review(root, diff, [c.line() for c in checks])
        except AgentError as err:
            pipe.end(step, "failed", str(err))
            failures, run.failed_step = [str(err)], "verifier"
            continue
        runs.write_artifact(root, run.run_id, "review.json", review.model_dump())
        if review.approve and not review.violations:
            pipe.end(step, "ok", "approved")
            run.failed_step = ""
            return True, []
        pipe.end(step, "failed", "; ".join(review.violations) or "not approved")
        failures, run.failed_step = (
            review.violations or ["the Verifier did not approve"],
            "verifier",
        )
    return False, failures


def _reviewable(worktree: Path, relative: str) -> list[str]:
    """Changed files except lockfiles, whose diffs are noise to a reviewer."""
    return [
        p for p in _changed_paths(worktree, relative) if Path(p).name not in bump.LOCKFILES
    ] or [relative]


def _rescan_check(
    source: AdvisorySource, folder: Path, finding: Finding, baseline: set[str]
) -> runner.Check:
    result = engine.scan(folder, source, save=False)
    left = [f.id for f in result.findings if f.package == finding.package]
    new = sorted({i for f in result.findings for i in f.ids} - baseline)
    if left:
        return runner.Check("re-scan", False, f"{finding.package} still has {', '.join(left[:3])}")
    if new:
        return runner.Check("re-scan", False, f"new findings: {', '.join(new[:3])}")
    return runner.Check("re-scan", True, "target finding gone, nothing new")


def _act(
    pipe: _Pipeline,
    root: Path,
    repo: Path,
    spec: engine.ServiceSpec,
    run: Run,
    lead: Finding,
    text: reporter.Text,
    verified: bool,
    publish: bool = True,
    base_sha: str = "",
) -> Run:
    title = text.pr_title or f"Bump {run.package} to {run.to_version}"
    if publish and _publishable(repo, run, base_sha):
        _publish(pipe, repo, run, title, text.pr_body)
    step = pipe.begin("act")
    decision = lead.decision
    if verified and decision.on_verified == "merge":
        before = runner.git(repo, "rev-parse", "HEAD").stdout.strip()
        error = actions.merge(root, repo, run.branch, run.service)
        if error is None:
            pipe.end(step, "ok", f"merged {run.branch}")
            outcome = _deploy_after_merge(pipe, root, repo, spec, run, before)
            return _finish(root, run, "verified", outcome)
        actions.save_pr(root, run, title, text.pr_body, "hedwig:needs-review")
        pipe.end(step, "ok", f"could not fast-forward ({error}); left for review")
        return _finish(root, run, "verified", "review_pr")
    if verified:
        actions.save_pr(root, run, title, text.pr_body, "hedwig:needs-review")
        pipe.end(step, "ok", "fix verified; left for human review")
        return _finish(root, run, "verified", "review_pr")
    if decision.on_failed == "takedown":
        note = actions.takedown(root, run.service, f"fix failed at {run.failed_step}")
        actions.save_pr(root, run, title, text.pr_body, "draft")
        pipe.end(step, "ok", f"verification failed; service taken down ({note})")
        return _finish(root, run, "failed", "takedown")
    actions.save_pr(root, run, title, text.pr_body, "hedwig:verification-failed")
    pipe.end(step, "ok", "verification failed; PR left for a human")
    return _finish(root, run, "failed", "failed_pr")
