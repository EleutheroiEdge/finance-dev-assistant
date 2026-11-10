"""audit close-run and workflow abandon clear stuck state without deleting evidence or claiming success (#69)."""

from datetime import datetime, timedelta
from decimal import Decimal
import json

import pytest

from finassist import readiness
from finassist.auditing import command_audit
from finassist.cli import main
from finassist.config import Config, save_config
from finassist.errors import AssistantError
from finassist.ledger import CURRENT_RUN, Ledger
from finassist.readiness import verify_gate
from finassist.security import canonical, digest
from finassist.workflow_execution import abandon_run, cancel_run, inspect_run, retry_step
from finassist.workflow_inspection import workflow_timeline
from finassist.workflow_state import WorkflowStore, abandoned_workflows, operation_identifier, unfinished_workflows
from test_workflow_execution import new_run, run

# gate_bundle, workflow_case, execution_case and dispatches come from these modules.
pytest_plugins = ("test_readiness", "test_workflow", "test_workflow_execution")
STUCK = "b" * 32
WARNING = {"code": "reconciled_operation", "closed_runs": 1, "abandoned_workflows": 0}


def start(state, identifier=STUCK, name="apply"):
    """A command that started and never recorded its end, as after a kill."""
    token = CURRENT_RUN.set(identifier)
    try:
        with Ledger(state) as ledger:
            ledger.append({"event": "command_started", "command": name})
    finally:
        CURRENT_RUN.reset(token)


def close_elsewhere(state, identifier, name):
    """Close a run from outside it, as another process would."""
    token = CURRENT_RUN.set(None)
    try:
        with Ledger(state) as ledger:
            return ledger.close_run(identifier, name)
    finally:
        CURRENT_RUN.reset(token)


# --- audit close-run ---------------------------------------------------------------------------------


def test_closing_an_unfinished_run_clears_the_blocker_and_stays_visible(gate_bundle):
    packet, review, checks, config, head, state = gate_bundle
    assert "warnings" not in verify_gate(packet, review, checks, config, head, state)
    start(state)
    assert "unfinished_operation" in verify_gate(packet, review, checks, config, head, state)["blocking_reasons"]
    with Ledger(state) as ledger:
        assert ledger.close_run(STUCK, "apply") == {"run_id": STUCK, "command": "apply", "outcome": "unknown"}
        assert ledger.incomplete_runs() == []
        (closed,) = ledger.reconciled_runs()
        assert (closed["run_id"], closed["command"], closed["outcome"]) == (STUCK, "apply", "unknown")
        ledger.verify()
    report = verify_gate(packet, review, checks, config, head, state)
    assert report["status"] == "eligible-for-human-review" and report["warnings"] == [WARNING]


def test_the_warning_ages_out_with_the_evidence_window(gate_bundle, monkeypatch):
    packet, review, checks, config, head, state = gate_bundle
    start(state)
    close_elsewhere(state, STUCK, "apply")

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(seconds=config.readiness_max_age_seconds + 60)

    monkeypatch.setattr(readiness, "datetime", Later)
    report = verify_gate(packet, review, checks, config, head, state)
    assert "warnings" not in report and "unfinished_operation" not in report["blocking_reasons"]


def test_close_run_refuses_anything_but_a_listed_incomplete_run(tmp_path):
    state = tmp_path / "audit.sqlite"
    start(state)
    with command_audit(state, "plan", Config()):
        finished = CURRENT_RUN.get()
    with Ledger(state) as ledger:
        for identifier, name, code in (
            ("c" * 32, "apply", "audit_run_not_incomplete"),       # Never started.
            ("not-a-run-id", "apply", "audit_run_not_incomplete"),
            (finished, "plan", "audit_run_not_incomplete"),        # Already finished.
            (STUCK, "review", "audit_run_command_mismatch"),
        ):
            with pytest.raises(AssistantError, match=code):
                ledger.close_run(identifier, name)
        token = CURRENT_RUN.set(STUCK)  # A command can't close its own run.
        try:
            with pytest.raises(AssistantError, match="audit_run_not_incomplete"):
                ledger.close_run(STUCK, "apply")
        finally:
            CURRENT_RUN.reset(token)
        ledger.close_run(STUCK, "apply")
        with pytest.raises(AssistantError, match="audit_run_not_incomplete"):  # Already closed.
            ledger.close_run(STUCK, "apply")
        assert len(ledger.reconciled_runs()) == 1 and ledger.verify()


@pytest.mark.parametrize("fails", [False, True])
def test_a_late_completion_cannot_replace_the_unknown_outcome(tmp_path, fails):
    state = tmp_path / "audit.sqlite"
    expected = "audit_lifecycle_invalid" if fails else "operation_finished_audit_completion_failed"
    with pytest.raises(AssistantError, match=expected):
        with command_audit(state, "apply", Config()):
            identifier = CURRENT_RUN.get()
            close_elsewhere(state, identifier, "apply")
            if fails:
                raise AssistantError("synthetic_failure")
    with Ledger(state) as ledger:
        assert ledger.verify() == 2  # The start and the reconciliation; no completion was added.
        assert ledger.incomplete_runs() == [] and ledger.reconciled_runs()[0]["run_id"] == identifier


def test_closing_a_run_never_touches_its_spend(tmp_path):
    state = tmp_path / "audit.sqlite"
    start(state, name="review")
    token = CURRENT_RUN.set(STUCK)
    try:
        with Ledger(state) as ledger:
            reservation = ledger.reserve(Decimal("0.10"), Decimal("5"), Decimal("1"))
    finally:
        CURRENT_RUN.reset(token)
    with Ledger(state) as ledger:
        ledger.close_run(STUCK, "review")
        assert [row["id"] for row in ledger.open_reservations()] == [reservation]
        ledger.verify()


@pytest.mark.parametrize("forged", [
    {"reconciled_run_id": "c" * 32, "command": "apply", "outcome": "unknown"},   # No such run.
    {"reconciled_run_id": STUCK, "command": "review", "outcome": "unknown"},     # Another command's name.
    {"reconciled_run_id": STUCK, "command": "apply", "outcome": "succeeded"},    # A claimed success.
])
def test_a_forged_reconciliation_fails_verification(tmp_path, forged):
    state = tmp_path / "audit.sqlite"
    start(state)
    with Ledger(state) as ledger:
        ledger.append({"event": "command_reconciled", **forged})
        with pytest.raises(AssistantError, match="audit_integrity_failed"):
            ledger.verify()


def test_a_reconciliation_of_a_finished_run_fails_verification(tmp_path):
    state = tmp_path / "audit.sqlite"
    with command_audit(state, "plan", Config()):
        finished = CURRENT_RUN.get()
    with Ledger(state) as ledger:
        ledger.append({"event": "command_reconciled", "reconciled_run_id": finished, "command": "plan",
                       "outcome": "unknown"})
        with pytest.raises(AssistantError, match="audit_integrity_failed"):
            ledger.verify()


def test_cli_lists_then_closes_a_run(tmp_path, capsys):
    state = tmp_path / "state"
    start(state / "audit.sqlite")
    assert main(["audit", "--state-dir", str(state)]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["incomplete_runs"][0]["run_id"] == STUCK and "reconciled_runs" not in listed
    close = ["audit", "close-run", "--state-dir", str(state), "--run", STUCK, "--command", "apply"]
    assert main(close) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["closed_run"] == {"run_id": STUCK, "command": "apply", "outcome": "unknown"}
    assert report["incomplete_runs"] == [] and report["reconciled_runs"][0]["run_id"] == STUCK
    for argv, code in (
        (["audit", "close-run", "--state-dir", str(state)], "audit_close_run_arguments_invalid"),
        (["audit", "close-run", "--state-dir", str(state), "--run", STUCK], "audit_close_run_arguments_invalid"),
        (["audit", "--state-dir", str(state), "--run", STUCK, "--command", "apply"],
         "audit_close_run_arguments_invalid"),
        ([*close, "--export", str(tmp_path / "events.jsonl")], "audit_close_run_arguments_invalid"),
        (close, "audit_run_not_incomplete"),  # Already closed.
    ):
        assert main(argv) == 2
        assert json.loads(capsys.readouterr().err)["code"] == code
    assert not (tmp_path / "events.jsonl").exists()


# --- workflow abandon --------------------------------------------------------------------------------


def test_abandon_closes_a_damaged_run_so_its_plan_can_run_again(execution_case, tmp_path):
    _repo, _config, _packet, plan = execution_case
    with WorkflowStore(tmp_path / "state", create=True) as store:
        identifier = new_run(store, execution_case)
        assert run(store, identifier, execution_case, max_steps=1)["status"] == "paused"
        (store.run_directory(identifier) / "plan.json").unlink()
        for refused in (lambda: inspect_run(store, identifier),
                        lambda: cancel_run(store, identifier, approved_plan=plan["plan_hash"])):
            with pytest.raises(AssistantError, match="workflow_artifact_missing_or_changed"):
                refused()
        with pytest.raises(AssistantError, match="workflow_plan_run_unfinished"):
            new_run(store, execution_case)
        with pytest.raises(AssistantError, match="workflow_plan_approval_required"):
            abandon_run(store, identifier, approved_plan="0" * 64)
        report = abandon_run(store, identifier, approved_plan=plan["plan_hash"])
        assert report["status"] == report["recorded_status"] == "abandoned"
        assert report["check_records"] == [] and report["blocking_reasons"] == []
        assert [step["state"] for step in report["steps"]] == ["succeeded", "pending"]
        assert not unfinished_workflows(store.events())
        assert [row["workflow_run_id"] for row in abandoned_workflows(store.events())] == [identifier]
        assert inspect_run(store, identifier)["status"] == "abandoned"  # Status now answers from the ledger.
        # Nothing was deleted: the remaining files and the recorded check stay.
        assert (store.run_directory(identifier) / "run.json").is_file()
        assert any(payload["event"] == "check_completed" and payload.get("workflow_run_id") == identifier
                   for _seq, payload in store.events())
        with pytest.raises(AssistantError, match="workflow_abandon_not_allowed"):
            abandon_run(store, identifier, approved_plan=plan["plan_hash"])
        with pytest.raises(AssistantError, match="workflow_state_invalid"):
            store.record("workflow_run_cancelled", identifier)
        other = new_run(store, execution_case)
        assert run(store, other, execution_case)["status"] == "completed-checks"
        store.ledger.verify()


def test_a_readable_run_keeps_cancel(execution_case, tmp_path):
    _repo, _config, _packet, plan = execution_case
    with WorkflowStore(tmp_path / "state", create=True) as store:
        identifier = new_run(store, execution_case)
        with pytest.raises(AssistantError, match="workflow_abandon_not_allowed"):
            abandon_run(store, identifier, approved_plan=plan["plan_hash"])
        with pytest.raises(AssistantError, match="workflow_run_unknown"):
            abandon_run(store, "c" * 32, approved_plan=plan["plan_hash"])
        assert cancel_run(store, identifier, approved_plan=plan["plan_hash"])["status"] == "cancelled"


def test_an_interrupted_damaged_run_needs_confirmed_cleanup(execution_case, tmp_path):
    _repo, _config, _packet, plan = execution_case
    state = tmp_path / "state"
    with WorkflowStore(state, create=True) as store:
        identifier = new_run(store, execution_case)
        store.record("workflow_step_started", identifier, step_id="unit", attempt_id="a" * 32,
                     operation_id=operation_identifier(identifier, "unit"), snapshot_hash="b" * 64)
        (store.run_directory(identifier) / "packet.json").write_text("not json", encoding="utf-8")
        with pytest.raises(AssistantError, match="workflow_cleanup_confirmation_required"):
            abandon_run(store, identifier, approved_plan=plan["plan_hash"])
        assert unfinished_workflows(store.events())[0]["status"] == "running"
        report = abandon_run(store, identifier, approved_plan=plan["plan_hash"], confirm_cleanup=True)
        assert report["status"] == "abandoned" and report["steps"][0]["state"] == "running"
    timeline = workflow_timeline(state / "audit.sqlite", identifier)
    assert timeline["recorded_status"] == "abandoned"
    assert timeline["suggested_next_steps"] == ["start_a_new_run_from_the_plan"]
    last = timeline["events"][-1]
    assert (last["event"], last["code"], last["cleanup_confirmed"]) == (
        "workflow_run_abandoned", "workflow_artifact_missing_or_changed", True)
    assert {step["step_id"]: step["recorded_blockers"][0] for step in timeline["steps"]} == {
        "unit": "workflow_run_abandoned", "cash": "workflow_run_abandoned"}


def test_restored_files_do_not_revive_an_abandoned_run(execution_case, tmp_path, dispatches):
    _repo, _config, _packet, plan = execution_case
    with WorkflowStore(tmp_path / "state", create=True) as store:
        identifier = new_run(store, execution_case)
        run(store, identifier, execution_case, max_steps=1)
        file = store.run_directory(identifier) / "plan.json"
        original = file.read_bytes()
        file.unlink()
        abandon_run(store, identifier, approved_plan=plan["plan_hash"])
        file.write_bytes(original)
        report = inspect_run(store, identifier)
        assert report["status"] == "abandoned" and report["check_records"] == []
        assert run(store, identifier, execution_case)["recorded_status"] == "abandoned"
        assert dispatches == ["unit"]  # Nothing new was dispatched.
        with pytest.raises(AssistantError, match="workflow_retry_not_allowed"):
            retry_step(store, identifier, "cash", "0" * 32, approved_plan=plan["plan_hash"])
        with pytest.raises(AssistantError, match="workflow_cancel_not_allowed"):
            cancel_run(store, identifier, approved_plan=plan["plan_hash"])
        with pytest.raises(AssistantError, match="workflow_abandon_not_allowed"):
            abandon_run(store, identifier, approved_plan=plan["plan_hash"])


@pytest.mark.parametrize("event,complete", [
    ({"code": "workflow_artifact_missing_or_changed", "cleanup_confirmed": False}, True),   # A completed run.
    ({"code": "operator_choice", "cleanup_confirmed": False}, False),                        # Another reason.
    ({"code": "workflow_artifact_missing_or_changed", "cleanup_confirmed": "yes"}, False),
])
def test_replay_rejects_a_forged_abandonment(execution_case, tmp_path, event, complete):
    with WorkflowStore(tmp_path / "state", create=True) as store:
        identifier = new_run(store, execution_case)
        if complete:
            assert run(store, identifier, execution_case)["status"] == "completed-checks"
        # Bypass the store's transition guard to simulate foreign state.
        store.ledger.append({"event": "workflow_run_abandoned", "workflow_schema": 1, "workflow_run_id": identifier,
                             **event})
        with pytest.raises(AssistantError, match="workflow_state_invalid"):
            store.states()


def test_an_abandoned_runs_checks_do_not_count_as_evidence(gate_bundle):
    packet, review, checks, config, head, state = gate_bundle
    workflow = "c" * 32
    # A second passing result for the same recipe, recorded only by a workflow run.
    result = {**checks[0]["receipt"], "output_hash": "d" * 64}
    documents = [{"receipt": result, "snapshot": checks[0]["snapshot"]}]
    with Ledger(state) as ledger:
        ledger.append({"event": "workflow_run_created", "workflow_schema": 1, "workflow_run_id": workflow,
                       "execution_hash": "1" * 64, "plan_hash": "2" * 64, "head": head, "backend": "local",
                       "steps": [{"id": "unit", "depends_on": []}]})
        ledger.append({"event": "check_completed", "head": head, "receipt_hash": digest(canonical(result)),
                       "config_hash": result["config_hash"], "workflow_run_id": workflow})
    before = verify_gate(packet, review, documents, config, head, state)
    assert before["blocking_reasons"] == ["unfinished_workflow"]  # The result itself counts.
    with Ledger(state) as ledger:
        ledger.append({"event": "workflow_run_abandoned", "workflow_schema": 1, "workflow_run_id": workflow,
                       "code": "workflow_artifact_missing_or_changed", "cleanup_confirmed": False})
    after = verify_gate(packet, review, documents, config, head, state)
    assert after["blocking_reasons"] == ["check_receipt_missing_or_stale"]
    assert after["warnings"] == [{"code": "reconciled_operation", "closed_runs": 0, "abandoned_workflows": 1}]


def test_cli_abandons_a_run_that_cancel_cannot_reach(execution_case, tmp_path, capsys):
    _repo, config, _packet, plan = execution_case
    state, config_path = tmp_path / "state", tmp_path / "config.json"
    save_config(config_path, config)
    with WorkflowStore(state, create=True) as store:
        identifier = new_run(store, execution_case)
        (store.run_directory(identifier) / "packet.json").write_text("not json", encoding="utf-8")
    common = ["--config", str(config_path), "workflow"]
    target = ["--state-dir", str(state), "--run-id", identifier, "--approve-plan", plan["plan_hash"]]
    assert main([*common, "cancel", *target]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "workflow_artifact_missing_or_changed"
    assert main([*common, "abandon", *target]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "abandoned"
    assert main([*common, "status", "--state-dir", str(state)]) == 0
    assert json.loads(capsys.readouterr().out)["workflows"] == [
        {"workflow_run_id": identifier, "status": "abandoned", "plan_hash": plan["plan_hash"]}]
    assert main([*common, "status", "--state-dir", str(state), "--run-id", identifier]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "abandoned"
    assert main(["audit", "--state-dir", str(state)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["unfinished_workflows"] == []
    assert report["abandoned_workflows"][0]["workflow_run_id"] == identifier
