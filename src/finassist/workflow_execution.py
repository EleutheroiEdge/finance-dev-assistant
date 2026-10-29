"""Bounded approved check execution, durable checkpoints and explicit recovery."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import tempfile
import uuid

from .config import Config
from .errors import AssistantError, OperationOutcomeUnknown
from .runner import run_recipe
from .security import canonical, digest, pinned_image, write_private
from .workflow import preflight_workflow, verify_workflow_plan
from .workflow_state import MAX_WORKFLOW_ARTIFACT_BYTES, WorkflowStore, operation_identifier, run_phase, workflow_lock
from .workspace import export_snapshot


def _authorize(plan: dict, config: Config, approved_plan: str | None, backend: str, approve_local: bool) -> None:
    config.validate()
    verify_workflow_plan(plan, config)
    if approved_plan != plan["plan_hash"]:
        raise AssistantError("workflow_plan_approval_required")
    if backend not in {"local", "docker", "podman"}:
        raise AssistantError("unsupported_runner")
    if backend == "local":
        if not approve_local:
            raise AssistantError("local_execution_not_approved")
    else:
        pinned_image(config.runner_image)


def _recipe(plan: dict, step_id: str) -> str:
    step = next(item for item in plan["template"]["steps"] if item["id"] == step_id)
    return next(item["recipe"] for item in plan["template"]["requirements"] if item["id"] == step["requirement"])


def _validate_result(document: dict, state: dict, plan: dict, step_id: str, config: Config) -> None:
    """Require the manifest recorded before dispatch, not a self-asserted snapshot."""
    receipt, snapshot, output = (document.get(key) for key in ("receipt", "snapshot", "output"))
    if (
        set(document) != {"receipt", "snapshot", "output"}
        or not isinstance(receipt, dict) or not isinstance(snapshot, dict) or not isinstance(output, str)
        or any(type(receipt.get(key)) is not bool for key in
               ("passed", "cleanup_verified", "timed_out", "output_limit_exceeded"))
        or type(receipt.get("exit_code")) is not int
    ):
        raise AssistantError("workflow_result_invalid")
    backend = state["backend"]
    expected_isolation = (
        "none: trusted local execution explicitly approved" if backend == "local"
        else "network-disabled read-only container; image must already be present"
    )
    passed = receipt["exit_code"] == 0 and not receipt["timed_out"] and not receipt["output_limit_exceeded"]
    expected = {
        "recipe": _recipe(plan, step_id), "head": state["head"], "config_hash": plan["config_hash"],
        "argv_hash": digest(canonical(config.recipes[_recipe(plan, step_id)])),
        "runner_image": None if backend == "local" else config.runner_image,
        "isolation": expected_isolation, "snapshot_hash": state["steps"][step_id]["snapshot_hash"],
        "output_hash": digest(output.encode()), "passed": passed and receipt["cleanup_verified"],
    }
    if (
        any(receipt.get(key) != value for key, value in expected.items())
        or snapshot.get("head") != state["head"] or digest(canonical(snapshot)) != expected["snapshot_hash"]
        or digest(canonical(asdict(config))) != plan["config_hash"]
        or len(canonical(document)) + 1 > MAX_WORKFLOW_ARTIFACT_BYTES
    ):
        raise AssistantError("workflow_result_invalid")


def inspect_run(store: WorkflowStore, identifier: str) -> dict:
    """Historical inspection verifies retained artifacts without executing anything."""
    state, _descriptor, _plan, _packet = store.load(identifier)
    steps, records, blockers = [], [], []
    for step_id, step in state["steps"].items():
        row = {
            "step_id": step_id, "state": step["state"], "attempt_id": step["attempt_id"],
            "depends_on": step["depends_on"], "artifact_hash": step["artifact_hash"],
            "started_at": step["started_at"],
        }
        if step["attempt_id"]:
            row["artifact_path"] = str(store.artifact_path(identifier, step["attempt_id"]))
        if step["artifact_hash"]:
            try:
                document, artifact_hash = store.artifact(identifier, step["attempt_id"])
                if artifact_hash != step["artifact_hash"] or digest(canonical(document.get("receipt"))) != step["receipt_hash"]:
                    raise AssistantError("workflow_artifact_missing_or_changed")
            except (AssistantError, OSError, ValueError, TypeError):
                blockers.append("workflow_artifact_missing_or_changed")
            else:
                if step["state"] == "succeeded":
                    records.append({"step_id": step_id, "path": row["artifact_path"], "artifact_hash": artifact_hash})
        elif step["state"] in {"running", "unknown"}:
            # A file written before the atomic checkpoint is a recovery candidate,
            # not completed evidence. Do not adopt it just because it exists.
            try:
                _document, candidate_hash = store.artifact(identifier, step["attempt_id"])
            except (AssistantError, OSError, ValueError, TypeError):
                pass
            else:
                row["recovery_artifact_hash"] = candidate_hash
        steps.append(row)
    phase = run_phase(state)
    if phase in {"running", "unknown"}:
        blockers.append("workflow_reconciliation_required")
    elif phase == "failed":
        blockers.append("workflow_check_failed")
    return {
        "schema_version": 1, "workflow_run_id": identifier, "plan_hash": state["plan_hash"],
        "execution_hash": state["execution_hash"], "head": state["head"], "backend": state["backend"],
        "status": "blocked" if "workflow_artifact_missing_or_changed" in blockers else phase,
        "recorded_status": phase, "sequence": state["sequence"], "steps": steps,
        "check_records": records, "blocking_reasons": sorted(set(blockers)),
        "merge_authority": False, "deployment_authority": False,
        "qualification": "Check execution only. Model review and the separate readiness gate still apply. "
        "Historical status does not verify current source, configuration or financial correctness.",
    }


def validate_run(plan: dict, packet: dict, repo: Path, config: Config,
                 *, approved_plan: str | None, backend: str = "docker", approve_local: bool = False) -> None:
    """Reject invalid inputs and approvals before initializing persistent state."""
    _authorize(plan, config, approved_plan, backend, approve_local)
    preflight = preflight_workflow(plan, packet, repo, config)
    if preflight["blocking_reasons"]:
        raise AssistantError("workflow_preflight_blocked")


def create_run(store: WorkflowStore, plan: dict, packet: dict, repo: Path, config: Config,
               *, approved_plan: str | None, backend: str = "docker", approve_local: bool = False) -> str:
    validate_run(plan, packet, repo, config, approved_plan=approved_plan, backend=backend, approve_local=approve_local)
    identifier = uuid.uuid4().hex
    descriptor = {
        "schema_version": 1, "workflow_run_id": identifier,
        **{key: plan[key] for key in ("plan_hash", "packet_hash", "config_hash", "head")},
        "backend": backend, "plan_document_hash": digest(canonical(plan)),
        "packet_document_hash": digest(canonical(packet)),
    }
    store.create(descriptor, plan, packet)
    return identifier


def _recover_interruption(store: WorkflowStore, identifier: str, state: dict) -> None:
    for step_id, step in state["steps"].items():
        if step["state"] == "running":
            store.record("workflow_step_unknown", identifier, step_id=step_id, attempt_id=step["attempt_id"])


def execute_run(store: WorkflowStore, identifier: str, repo: Path, config: Config,
                *, approved_plan: str | None, approve_local: bool = False, max_steps: int = 64) -> dict:
    if type(max_steps) is not int or not 1 <= max_steps <= 64:
        raise AssistantError("workflow_step_limit_invalid")
    with workflow_lock(store.root, identifier):
        state, _descriptor, plan, packet = store.load(identifier)
        config.validate()
        if approved_plan != plan["plan_hash"]:
            raise AssistantError("workflow_plan_approval_required")
        if digest(canonical(asdict(config))) != plan["config_hash"]:
            report = inspect_run(store, identifier)
            report.update(status="blocked", blocking_reasons=sorted(
                {*report["blocking_reasons"], "workflow_configuration_changed"}))
            return report
        _authorize(plan, config, approved_plan, state["backend"], approve_local)
        _recover_interruption(store, identifier, state)
        for _index in range(max_steps):
            report = inspect_run(store, identifier)
            if report["blocking_reasons"] or report["recorded_status"] in {"cancelled", "completed-checks"}:
                # Revalidate identities even when no new dispatch would occur.
                preflight = preflight_workflow(plan, packet, repo, config)
                if preflight["blocking_reasons"]:
                    report.update(status="blocked", blocking_reasons=sorted(
                        set(report["blocking_reasons"]) | set(preflight["blocking_reasons"])))
                return report
            preflight = preflight_workflow(plan, packet, repo, config)
            if preflight["blocking_reasons"]:
                report.update(status="blocked", blocking_reasons=preflight["blocking_reasons"])
                return report
            state = store.states()[identifier]
            step_id = next(name for name, step in state["steps"].items()
                           if step["state"] == "pending"
                           and all(state["steps"][dep]["state"] == "succeeded" for dep in step["depends_on"]))
            attempt_id = uuid.uuid4().hex
            # Snapshot preparation is safe to repeat. Durable intent precedes the
            # runner call; everything after that boundary may require reconciliation.
            with tempfile.TemporaryDirectory(prefix="finassist-workflow-") as temporary:
                snapshot = Path(temporary) / "source"
                manifest = export_snapshot(repo, plan["head"], snapshot, config)
                store.record(
                    "workflow_step_started", identifier, step_id=step_id, attempt_id=attempt_id,
                    operation_id=operation_identifier(identifier, step_id), snapshot_hash=digest(canonical(manifest)),
                )
                try:
                    result = run_recipe(config, _recipe(plan, step_id), snapshot,
                                        backend=state["backend"], approve_local=approve_local)
                    result["snapshot"] = manifest
                    result["receipt"].update(head=plan["head"], snapshot_hash=digest(canonical(manifest)),
                                             config_hash=plan["config_hash"])
                    _validate_result(result, store.states()[identifier], plan, step_id, config)
                    write_private(store.artifact_path(identifier, attempt_id), canonical(result) + b"\n")
                    store.commit_result(identifier, step_id, attempt_id, result)
                except BaseException as exc:
                    # Never replay after the dispatch intent, including validation,
                    # artifact or audit failures. Preserve whatever evidence exists.
                    try:
                        current = store.states()[identifier]["steps"][step_id]
                        if current["state"] == "running":
                            store.record("workflow_step_unknown", identifier, step_id=step_id, attempt_id=attempt_id)
                    except BaseException as audit_exc:
                        # The persisted start still prevents a second dispatch.
                        raise OperationOutcomeUnknown("workflow_outcome_audit_unavailable") from audit_exc
                    raise OperationOutcomeUnknown("workflow_step_outcome_unknown") from exc
        report = inspect_run(store, identifier)
        if report["status"] == "pending":
            report["status"] = "paused"
        return report


def reconcile_run(store: WorkflowStore, identifier: str, step_id: str, attempt_id: str,
                  config: Config, *, approved_artifact: str | None = None, confirm_cleanup: bool = False) -> dict:
    if (approved_artifact is not None) == confirm_cleanup:
        raise AssistantError("workflow_reconciliation_choice_required")
    with workflow_lock(store.root, identifier):
        state, _descriptor, plan, _packet = store.load(identifier)
        _recover_interruption(store, identifier, state)
        state = store.states()[identifier]
        step = state["steps"].get(step_id)
        if step is None or step["state"] != "unknown" or step["attempt_id"] != attempt_id:
            raise AssistantError("workflow_reconciliation_not_required")
        if confirm_cleanup:
            # Operator confirmation permits a failed terminal result, never a pass.
            store.record("workflow_step_reconciled", identifier, step_id=step_id, attempt_id=attempt_id,
                         state="failed", artifact_hash=None, receipt_hash=None, cleanup_verified=True,
                         resolution="cleanup")
        else:
            config.validate()
            verify_workflow_plan(plan, config)
            document, artifact_hash = store.artifact(identifier, attempt_id)
            if artifact_hash != approved_artifact:
                raise AssistantError("workflow_artifact_approval_required")
            _validate_result(document, state, plan, step_id, config)
            if not document["receipt"]["cleanup_verified"]:
                raise AssistantError("workflow_cleanup_unresolved")
            store.commit_result(identifier, step_id, attempt_id, document, reconciliation=True)
        return inspect_run(store, identifier)


def retry_step(store: WorkflowStore, identifier: str, step_id: str, attempt_id: str,
               *, approved_plan: str | None) -> dict:
    with workflow_lock(store.root, identifier):
        state, _descriptor, _plan, _packet = store.load(identifier)
        if approved_plan != state["plan_hash"]:
            raise AssistantError("workflow_plan_approval_required")
        step = state["steps"].get(step_id)
        if state["cancelled"] or step is None or step["state"] != "failed" or step["attempt_id"] != attempt_id:
            raise AssistantError("workflow_retry_not_allowed")
        store.record("workflow_step_retry", identifier, step_id=step_id, attempt_id=attempt_id)
        return inspect_run(store, identifier)


def cancel_run(store: WorkflowStore, identifier: str, *, approved_plan: str | None) -> dict:
    with workflow_lock(store.root, identifier):
        state, _descriptor, _plan, _packet = store.load(identifier)
        if approved_plan != state["plan_hash"]:
            raise AssistantError("workflow_plan_approval_required")
        if run_phase(state) not in {"pending", "failed"}:
            raise AssistantError("workflow_cancel_not_allowed")
        store.record("workflow_run_cancelled", identifier)
        return inspect_run(store, identifier)
