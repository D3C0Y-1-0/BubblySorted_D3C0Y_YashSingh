"""The policy gate. Deterministic: agents propose, this decides."""

from hedwig.core.models import Decision


def decide(evidence_level: int, allow: list[str]) -> Decision:
    """What to do with one finding on a service with these permissions.

    Every finding gets an action, whatever its severity. `fix` means run the fixing pipeline
    (Phase 3); on_verified and on_failed say what happens after it.
    """
    if evidence_level >= 4 and "takedown" in allow:
        return Decision(
            action="takedown",
            reason="signs of compromise (evidence 4) and takedown is allowed",
        )
    if "open_fix_pr" not in allow:
        return Decision(
            action="notify",
            reason="fixing is not allowed for this service, so the project manager is notified",
        )
    verified = "merge" if "auto_merge_if_verified" in allow else "review_pr"
    failed = "takedown" if "takedown" in allow else "failed_pr"
    return Decision(
        action="fix",
        reason="open a minimal fix, then verify it",
        on_verified=verified,
        on_failed=failed,
    )
