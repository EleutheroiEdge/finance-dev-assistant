"""The checks-only gate's outcome_class: a failed check is `fail` only when it ran and exited nonzero."""

from copy import deepcopy
import importlib
import json
from pathlib import Path

import pytest

from test_ci_gate import ci_case, gate  # noqa: F401 - fixture registration
from test_never_silently_pass import _receipt_runner
from finassist.errors import AssistantError
from finassist.github_actions import _report_identity, publish_action_report
from finassist.outcome_class import CAUSES, check_cause, ci_outcome_class
from finassist.security import canonical, digest


@pytest.mark.parametrize("receipt,cause", [
    ({"exit_code": 1, "timed_out": False, "output_limit_exceeded": False}, "nonzero_exit"),
    ({"exit_code": -9, "timed_out": False, "output_limit_exceeded": False}, "killed"),
    ({"exit_code": 0, "timed_out": True, "output_limit_exceeded": False}, "timed_out"),
    ({"exit_code": 1, "timed_out": True, "output_limit_exceeded": False}, "timed_out"),
    ({"exit_code": 0, "timed_out": False, "output_limit_exceeded": True}, "output_limit_exceeded"),
    ({"exit_code": 0, "timed_out": False, "output_limit_exceeded": False}, "unknown"),
    ({"exit_code": True}, "unknown"), (None, "unknown"), ("passed", "unknown"),
])
def test_the_cause_comes_from_the_receipt(receipt, cause):
    assert check_cause(receipt) == cause and cause in CAUSES


@pytest.mark.parametrize("status,reasons,causes,expected", [
    ("passed", [], [], "pass"),
    ("error", ["ci_action_failed"], [], "incomplete"),
    ("blocked", ["ci_guarded_change_requires_review"], [], "refused"),
    ("blocked", ["ci_check_budget_exceeded", "ci_model_review_required"], [], "refused"),
    ("blocked", ["ci_checks_incomplete", "workflow_check_failed"], ["nonzero_exit"], "fail"),
    ("blocked", ["ci_checks_incomplete", "workflow_check_failed"], ["nonzero_exit", "timed_out"], "incomplete"),
    ("blocked", ["ci_checks_incomplete", "workflow_check_failed"], ["killed"], "incomplete"),
    ("blocked", ["ci_checks_incomplete", "workflow_check_failed"], [], "incomplete"),
    ("blocked", ["ci_check_outcome_unknown"], [], "incomplete"),
    ("blocked", ["ci_guarded_change_requires_review", "ci_state_unresolved"], [], "incomplete"),
    ("blocked", ["a_reason_no_table_lists"], [], "incomplete"),
])
def test_the_class_follows_status_reasons_and_causes(status, reasons, causes, expected):
    assert ci_outcome_class(status, reasons, causes) == expected


@pytest.mark.parametrize("receipt,cause,expected", [
    ({"passed": False, "exit_code": 1}, ["nonzero_exit"], "fail"),
    ({"passed": False, "exit_code": -9}, ["killed"], "incomplete"),
    ({"passed": False, "exit_code": 0, "timed_out": True}, ["timed_out"], "incomplete"),
    ({"passed": False, "exit_code": 0, "output_limit_exceeded": True}, ["output_limit_exceeded"], "incomplete"),
    ({"passed": True, "exit_code": 1}, [], "incomplete"),  # a contradictory receipt: the outcome is unknown
], ids=["failed", "killed", "timed-out", "overflow", "contradictory"])
def test_the_gate_reports_each_failed_checks_cause(ci_case, tmp_path, monkeypatch, receipt, cause,  # noqa: F811
                                                   expected):
    calls = []
    monkeypatch.setattr("finassist.workflow_execution.run_recipe", _receipt_runner(calls, **receipt))
    report = gate(ci_case, tmp_path)
    assert report["status"] == "blocked" and report["failed_check_causes"] == cause
    assert report["outcome_class"] == expected
    _report_identity(report)


def test_a_passing_gate_is_pass_and_the_action_outputs_the_class(ci_case, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr("finassist.workflow_execution.run_recipe", _receipt_runner([]))
    report = gate(ci_case, tmp_path)
    assert report["status"] == "passed" and report["outcome_class"] == "pass" and report["failed_check_causes"] == []
    path, summary, outputs = tmp_path / "report.json", tmp_path / "summary.md", tmp_path / "outputs.txt"
    path.write_bytes(canonical(report))
    publish_action_report(report, path, summary, outputs)
    assert "outcome-class=pass\n" in outputs.read_text(encoding="utf-8")


def test_a_changed_receipt_cannot_turn_a_timeout_into_a_failure(ci_case, tmp_path, monkeypatch):  # noqa: F811
    # The cause is read from the artifact the run recorded; one changed after the run is an unknown cause.
    gate_module = importlib.import_module("finassist.ci_gate")
    real = gate_module.execute_run
    monkeypatch.setattr("finassist.workflow_execution.run_recipe",
                        _receipt_runner([], passed=False, exit_code=0, timed_out=True))

    def change_the_receipt_after_the_run(store, identifier, *args, **kwargs):
        execution = real(store, identifier, *args, **kwargs)
        row = next(row for row in execution["steps"] if row["state"] == "failed")
        path = Path(row["artifact_path"])
        document = json.loads(path.read_text(encoding="utf-8"))
        document["receipt"].update(exit_code=1, timed_out=False)
        path.write_bytes(canonical(document) + b"\n")
        return execution

    monkeypatch.setattr(gate_module, "execute_run", change_the_receipt_after_the_run)
    report = gate(ci_case, tmp_path)
    assert report["status"] == "blocked" and report["failed_check_causes"] == ["unknown"]
    assert report["outcome_class"] == "incomplete"


@pytest.mark.parametrize("status", ["passed", "error"])
def test_only_a_blocked_report_can_name_failed_checks(ci_case, tmp_path, monkeypatch, status):  # noqa: F811
    monkeypatch.setattr("finassist.workflow_execution.run_recipe", _receipt_runner([]))
    report = gate(ci_case, tmp_path)
    report.update(failed_check_causes=["timed_out"])
    if status == "error":
        report.update(status="error", blocking_reasons=["ci_action_failed"], outcome_class="incomplete")
    report["report_hash"] = digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
    with pytest.raises(AssistantError, match="^ci_report_invalid$"):
        _report_identity(report)


def test_a_report_cannot_claim_another_class(ci_case, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr("finassist.workflow_execution.run_recipe", _receipt_runner([], passed=False, exit_code=-9))
    report = gate(ci_case, tmp_path)
    for forged in (dict(deepcopy(report), outcome_class="fail"),
                   dict(deepcopy(report), failed_check_causes=["nonzero_exit"]),
                   dict(deepcopy(report), failed_check_causes=["exploded"])):
        forged["report_hash"] = digest(canonical({k: v for k, v in forged.items() if k != "report_hash"}))
        with pytest.raises(AssistantError, match="^ci_report_invalid$"):
            _report_identity(forged)
