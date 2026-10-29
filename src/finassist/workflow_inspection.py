"""Read-only, snapshot-bound workflow timelines with metadata-only projection."""

from __future__ import annotations

import json
from pathlib import Path
import re

from .errors import AssistantError
from .ledger import Ledger
from .security import canonical, digest
from .workflow_state import replay_workflows, run_identifier, run_phase

_TRANSITIONS = {
    "workflow_run_created", "workflow_run_cancelled", "workflow_step_started", "workflow_step_unknown",
    "workflow_step_result", "workflow_step_reconciled", "workflow_step_retry",
}
_METADATA = {
    "step_id", "attempt_id", "operation_id", "plan_hash", "head", "backend", "execution_hash",
    "snapshot_hash", "artifact_hash", "receipt_hash", "state", "cleanup_verified", "resolution",
}


def _page_contract(after: int, limit: int, through: int | None, anchor: str | None) -> None:
    if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 1000:
        raise AssistantError("workflow_timeline_page_invalid")
    if (through is None) != (anchor is None) or (through is not None and (
        type(through) is not int or through < 1 or after > through
        or not isinstance(anchor, str) or re.fullmatch(r"[0-9a-f]{64}", anchor) is None
    )):
        raise AssistantError("workflow_timeline_snapshot_invalid")


def _project(sequence: int, previous: str, event_hash: str, payload: dict) -> dict:
    row = {"sequence": sequence, "previous_hash": previous, "event_hash": event_hash,
           "event": payload["event"], "recorded_at": payload["recorded_at"]}
    # Workflow transition fields are validated by full replay. Arbitrary event
    # extensions and check output are never copied to the inspector/export.
    row.update({key: payload[key] for key in _METADATA if key in payload})
    return row


def _recorded_steps(state: dict) -> list[dict]:
    phase = run_phase(state)
    rows = []
    for name, step in state["steps"].items():
        missing = [dep for dep in step["depends_on"] if state["steps"][dep]["state"] != "succeeded"]
        reasons = []
        if step["state"] in {"running", "unknown"}:
            reasons.append("workflow_reconciliation_required")
        elif step["state"] == "failed":
            reasons.append("workflow_check_failed")
        elif step["state"] == "pending":
            if state["cancelled"]:
                reasons.append("workflow_run_cancelled")
            elif phase in {"running", "unknown", "failed"}:
                reasons.append("workflow_run_unresolved")
            if missing:
                reasons.append("workflow_dependencies_pending")
        rows.append({"step_id": name, "state": step["state"], "attempt_id": step["attempt_id"],
                     "depends_on": step["depends_on"], "unmet_dependencies": missing,
                     "dependencies_satisfied": not missing, "started_at": step["started_at"],
                     "snapshot_hash": step["snapshot_hash"],
                     "artifact_hash": step["artifact_hash"], "receipt_hash": step["receipt_hash"],
                     "recorded_blockers": reasons})
    return rows


def workflow_timeline(path: Path, identifier: str, *, after: int = 0, limit: int = 100,
                      through: int | None = None, anchor: str | None = None) -> dict:
    """Inspect one verified historical prefix; never dispatch or adopt artifacts."""
    run_identifier(identifier)
    _page_contract(after, limit, through, anchor)
    with Ledger(path, read_only=True) as ledger, ledger.transaction():
        ledger.verify()
        rows = [(seq, previous, json.loads(raw), value) for seq, previous, raw, value in ledger.db.execute(
            "SELECT seq,previous,payload,hash FROM events ORDER BY seq"
        )]
        # Invalid transitions/unknown workflow versions anywhere in the ledger
        # must not silently disappear behind pagination or a run filter.
        replay_workflows([(seq, payload) for seq, _prior, payload, _value in rows])
        if not rows:
            raise AssistantError("workflow_run_unknown")
        selected_tail = through if through is not None else rows[-1][0]
        if after > selected_tail:
            raise AssistantError("workflow_timeline_page_invalid")
        prefix = [row for row in rows if row[0] <= selected_tail]
        if not prefix or prefix[-1][0] != selected_tail or (anchor is not None and prefix[-1][3] != anchor):
            raise AssistantError("workflow_timeline_snapshot_changed")
        states = replay_workflows([(seq, payload) for seq, _prior, payload, _value in prefix])
        state = states.get(identifier)
        if state is None:
            raise AssistantError("workflow_run_unknown")
        selected = [
            _project(seq, previous, value, payload)
            for seq, previous, payload, value in prefix
            if seq > after and payload.get("event") in _TRANSITIONS and payload.get("workflow_run_id") == identifier
        ]
        page = selected[:limit]
        more = len(selected) > limit
        phase = run_phase(state)
        actions = {
            "pending": ["inspect_current_bindings_before_resume"],
            "running": ["inspect_active_owner_before_reconciliation"],
            "unknown": ["inspect_attempt_and_reconcile"],
            "failed": ["inspect_failed_check_before_retry_or_cancel"],
            "cancelled": [], "completed-checks": ["verify_artifacts_and_run_readiness_gate"],
        }[phase]
        result = {
            "schema_version": 1, "workflow_run_id": identifier, "plan_hash": state["plan_hash"],
            "execution_hash": state["execution_hash"], "head": state["head"], "backend": state["backend"],
            "recorded_status": phase, "chain_verified": True,
            "snapshot": {"through_sequence": selected_tail, "through_hash": prefix[-1][3]},
            "pagination": {"after": after, "limit": limit, "has_more": more,
                           "next_after": page[-1]["sequence"] if more else selected_tail},
            "events": page, "steps": _recorded_steps(state), "suggested_next_steps": actions,
            "artifacts_verified": False, "current_bindings_verified": False, "readiness_evaluated": False,
            "execution_authorized": False, "merge_authority": False, "deployment_authority": False,
            "qualification": "Historical workflow checkpoints only. Suggestions grant no permission. "
            "Running does not prove an owner is alive; inspect ownership and cleanup before reconciliation. "
            "Artifact contents, current bindings, spend and readiness require their separate checks. "
            "Filtered event hashes are links in the verified full ledger, not a standalone contiguous chain "
            "or an external attestation against same-user rewriting.",
        }
    result["report_hash"] = digest(canonical(result))
    return result
