"""Read-only evidence eligibility. This never grants merge or deployment authority."""

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .config import Config
from .errors import AssistantError
from .ledger import CURRENT_RUN, Ledger
from .review import validate_review
from .scope import verify_packet
from .security import canonical, digest


def verify_gate(
    packet: dict, review: dict, checks: list[dict], config: Config, head: str, state: Path
) -> dict:
    config.validate()
    verify_packet(packet)
    if not isinstance(review, dict) or any(
        not isinstance(value, dict)
        or not isinstance(value.get("receipt"), dict)
        or not isinstance(value.get("snapshot"), dict)
        for value in checks
    ):
        raise AssistantError("readiness_evidence_invalid")
    blockers = set()
    if packet["schema_version"] < 2:
        blockers.add("packet_mode_evidence_missing")
    if packet["head"] != head or review.get("head") != head:
        blockers.add("revision_mismatch")
    if packet["omitted"] or review.get("omitted"):
        blockers.add("coverage_incomplete")
    if (
        packet["profile"] != config.profile
        or review.get("provider") != config.provider
        or review.get("model") != config.model
    ):
        blockers.add("review_policy_changed")
    if review.get("config_hash") != digest(canonical(asdict(config))):
        blockers.add("review_configuration_changed")
    if review.get("provider") in {None, "offline"}:
        blockers.add("model_review_absent")
    else:
        validate_review(review.get("review"), packet, extra_patterns=config.extra_sensitive_patterns)
        if any(f["severity"] in config.blocking_severities for f in review["review"]["findings"]):
            blockers.add("blocking_findings")
    if review.get("packet_hash") != packet["packet_hash"]:
        blockers.add("review_packet_mismatch")
    if not config.required_recipes:
        blockers.add("required_recipes_unconfigured")
    if not state.is_file():
        raise AssistantError("audit_evidence_missing")
    with Ledger(state) as ledger:
        ledger.verify()
        if ledger.open_reservations():
            blockers.add("unreconciled_spend")
        if any(run["run_id"] != CURRENT_RUN.get() for run in ledger.incomplete_runs()):
            blockers.add("unfinished_operation")
        # Iterate all records without confusing a bounded export page with full
        # history. No source, arguments or test logs are returned by this query.
        rows = ledger.db.execute("SELECT payload,hash FROM events ORDER BY seq").fetchall()
    import json

    events = [(json.loads(payload), value) for payload, value in rows]
    now = datetime.now(timezone.utc)

    def fresh(payload: dict) -> bool:
        try:
            instant = datetime.fromisoformat(payload["recorded_at"])
            return (
                instant.tzinfo is not None
                and 0 <= (now - instant).total_seconds() <= config.readiness_max_age_seconds
            )
        except (KeyError, TypeError, ValueError):
            return False

    report_hash = digest(canonical({key: value for key, value in review.items() if key != "receipt"}))
    if not any(
        p.get("event") == "review_completed"
        and p.get("report_hash") == report_hash
        and value == review.get("receipt")
        and p.get("packet_hash") == packet["packet_hash"]
        and fresh(p)
        for p, value in events
    ):
        blockers.add("review_receipt_missing_or_stale")
    seen = set()
    for document in checks:
        receipt, snapshot = document.get("receipt", {}), document.get("snapshot", {})
        name = receipt.get("recipe")
        if name not in config.required_recipes:
            continue
        if name in seen:
            blockers.add("duplicate_recipe_evidence")
        seen.add(name)
        if receipt.get("head") != head or snapshot.get("head") != head:
            blockers.add("check_revision_mismatch")
        if receipt.get("snapshot_hash") != digest(canonical(snapshot)):
            blockers.add("snapshot_integrity_failed")
        if receipt.get("argv_hash") != digest(canonical(config.recipes[name])):
            blockers.add("recipe_changed")
        if receipt.get("passed") is not True or receipt.get("cleanup_verified") is not True:
            blockers.add("check_failed_or_cleanup_unknown")
        if not config.allow_local_readiness and (
            not receipt.get("runner_image") or "container" not in receipt.get("isolation", "")
        ):
            blockers.add("isolated_check_required")
        if receipt.get("runner_image") and receipt["runner_image"] != config.runner_image:
            blockers.add("runner_image_changed")
        receipt_hash = digest(canonical(receipt))
        if not any(
            p.get("event") == "check_completed"
            and p.get("head") == head
            and p.get("receipt_hash") == receipt_hash
            and fresh(p)
            for p, _ in events
        ):
            blockers.add("check_receipt_missing_or_stale")
    if seen != set(config.required_recipes):
        blockers.add("required_recipe_evidence_missing")
    return {
        "status": "blocked" if blockers else "eligible-for-human-review",
        "head": head,
        "blocking_reasons": sorted(blockers),
        "required_recipes": list(config.required_recipes),
        "policy_hash": digest(canonical(asdict(config))),
        "merge_authority": False,
        "deployment_authority": False,
        "qualification": "Local source-bound evidence only. Verify current GitHub protections, approvals, target environment and release/rollback plan separately.",
    }
