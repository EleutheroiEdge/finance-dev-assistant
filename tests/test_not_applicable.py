"""The opt-in no-review outcome: a range whose every changed file is outside allow_paths is NOT_APPLICABLE under a
base-pinned policy that says so, and BLOCKED otherwise. It is never a review or a pass. Synthetic Git and a fake
provider only.
"""

from copy import deepcopy
import json
import os
import sys

import httpx
import pytest

from conftest import command
from test_model_gate import change_policy, gate_case, run  # noqa: F401 - fixture registration
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration
from finassist.cli import main
from finassist.errors import AssistantError
from finassist.config import Config
from finassist.github_actions import publish_action_report
from finassist.history_evaluation import evaluate_history
from finassist.history_suite import history_approval_hash, plan_history
from finassist.model_gate import EXIT_CODES, validate_model_report
from finassist.onboarding import policy_preflight
from finassist.report_trace import score_gate_report, trace_markdown
from finassist.sarif import from_document
from finassist.security import canonical, digest

OPT_IN = {"unreviewable_paths": "skip-and-report", "out_of_scope_ranges": "not-applicable"}
OUTSIDE = {"tools/build.py": b"print('synthetic')\n"}


def _only(case, files: dict, branch: str = "outside-only") -> None:
    """A head on a branch from the policy's base that changes exactly these files."""
    repo = case["repo"]
    command(repo, "switch", "-q", "-c", branch, case["base"])
    for name, content in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    command(repo, "add", "--force", "--", *files)
    command(repo, "commit", "-q", "-m", "Synthetic change")
    case["head"] = command(repo, "rev-parse", "HEAD")


def _rehash(report: dict) -> dict:
    report["report_hash"] = digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
    return report


def test_by_default_a_range_with_nothing_in_scope_blocks(gate_case):  # noqa: F811
    change_policy(gate_case, unreviewable_paths="skip-and-report")
    _only(gate_case, OUTSIDE)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["empty_model_context"] and not calls


def test_opted_in_it_is_not_applicable_with_no_key_call_or_audit(gate_case, monkeypatch):  # noqa: F811
    change_policy(gate_case, **OPT_IN)
    _only(gate_case, OUTSIDE)
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")  # the review route would refuse without it; this one never reads it
    report, calls = run(gate_case)
    assert report["verdict"] == "NOT_APPLICABLE" and report["reasons"] == ["nothing_in_scope"] and not calls
    assert report["scope"] == {"changed": 1, "outside_allow_paths": 1, "reviewed": 0}
    assert report["coverage_complete"] is False and EXIT_CODES[report["verdict"]] == 0
    assert not {"request_sha256", "usage", "spend", "findings"} & set(report)
    assert "tools/build.py" not in canonical(report).decode()  # the manifest is a digest, not a list of names
    assert not (gate_case["state"] / "audit.sqlite").exists()  # absent audit state is not created


def test_one_file_in_scope_is_reviewed_as_usual(gate_case):  # noqa: F811
    change_policy(gate_case, **OPT_IN)
    _only(gate_case, {**OUTSIDE, "src/cash.py": b"def balance(opening):\n    return opening\n"})
    report, calls = run(gate_case)
    assert report["mode"] == "model-review" and report["verdict"] == "PASS" and len(calls) == 1


@pytest.mark.parametrize("files,policy,reason", [
    ({**OUTSIDE, "src/notes.xyz": b"synthetic\n"}, {}, "empty_model_context"),  # left out in scope, another reason
    ({**OUTSIDE, "src/logo.png": b"\x89PNG\r\n\x1a\nsynthetic"}, {}, "private_or_binary_path"),
    (OUTSIDE, {"deny_paths": ["tools/"]}, "gate_denied_path"),
    ({"tools/.gitignore": b"*.log\n"}, {}, "empty_model_context"),  # a rule file, even an accepted append
    ({**OUTSIDE, "tools/.gitignore": b"*.log\n"}, {}, "empty_model_context"),
])
def test_anything_but_plain_out_of_scope_files_still_blocks(gate_case, files, policy, reason):  # noqa: F811
    change_policy(gate_case, **OPT_IN, **policy)
    _only(gate_case, files)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == [reason] and not calls


def test_a_withheld_private_file_never_qualifies(gate_case):  # noqa: F811
    change_policy(gate_case, **OPT_IN, private_paths="skip-and-report")
    _only(gate_case, {**OUTSIDE, "src/data/clients.csv": b"account,value\nsynthetic,1\n"})
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["mode"] == "model-review" and not calls


def test_a_supplied_request_hash_cannot_match_a_request_never_made(gate_case):  # noqa: F811
    change_policy(gate_case, **OPT_IN)
    _only(gate_case, OUTSIDE)
    report, calls = run(gate_case, expected_request_hash="0" * 64)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["gate_request_hash_mismatch"] and not calls


def test_unresolved_audit_state_still_blocks(gate_case):  # noqa: F811
    change_policy(gate_case, **OPT_IN)

    def timeout(_packet):
        raise httpx.ReadTimeout("synthetic")

    held, _calls = run(gate_case, timeout)  # an in-scope review leaves its spend unreconciled
    assert "unreconciled_model_usage" in held["reasons"]
    _only(gate_case, OUTSIDE)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["unreconciled_model_usage"] and not calls


def test_a_damaged_audit_file_blocks(gate_case):  # noqa: F811
    change_policy(gate_case, **OPT_IN)
    _only(gate_case, OUTSIDE)
    gate_case["state"].mkdir(parents=True)
    (gate_case["state"] / "audit.sqlite").write_bytes(b"not a database")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["gate_audit_unavailable"] and not calls


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs POSIX here")
def test_a_linked_audit_file_is_not_absence(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, **OPT_IN)
    _only(gate_case, OUTSIDE)
    gate_case["state"].mkdir(parents=True)
    os.symlink(tmp_path / "elsewhere.sqlite", gate_case["state"] / "audit.sqlite")  # dangling
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] and not calls


def _valid(case) -> dict:
    change_policy(case, **OPT_IN)
    _only(case, OUTSIDE)
    return run(case)[0]


@pytest.mark.parametrize("tamper", [
    lambda r: r["scope"].update(changed=2),
    lambda r: r["scope"].update(reviewed=1),
    lambda r: r.update(evaluation_sha256="0" * 64),
    lambda r: r.update(manifest_sha256="1" * 64),
    lambda r: r.update(request_sha256="2" * 64),
    lambda r: r.update(verdict="PASS"),
    lambda r: r.update(coverage_complete=True),
    lambda r: r.update(merge_authority=True),
    lambda r: r.update(schema_version=2),
    lambda r: r.pop("outcome_class"),
])
def test_a_changed_report_is_refused(gate_case, tamper):  # noqa: F811
    report = deepcopy(_valid(gate_case))
    validate_model_report(report)
    tamper(report)
    with pytest.raises(AssistantError, match="^gate_report_invalid$"):
        validate_model_report(_rehash(report))


def test_an_unknown_mode_or_a_wrong_hash_is_refused(gate_case):  # noqa: F811
    report = deepcopy(_valid(gate_case))
    with pytest.raises(AssistantError, match="^gate_report_invalid$"):
        validate_model_report(_rehash({**report, "mode": "model-review-skipped"}))
    with pytest.raises(AssistantError, match="^gate_report_invalid$"):
        validate_model_report({**report, "report_hash": "3" * 64})


# Every consumer says what NOT_APPLICABLE is: nothing reviewed, coverage none.
def test_the_action_reports_no_review_and_incomplete_coverage(gate_case, tmp_path):  # noqa: F811
    report = _valid(gate_case)
    report_path, summary, outputs = tmp_path / "report.json", tmp_path / "summary.md", tmp_path / "outputs.txt"
    report_path.write_text(canonical(report).decode(), encoding="utf-8")
    publish_action_report(report, report_path, summary, outputs)
    written = outputs.read_text(encoding="utf-8")
    assert "status=NOT_APPLICABLE\n" in written and "coverage-complete=false\n" in written
    assert "withheld-count=1\n" in written
    shown = summary.read_text(encoding="utf-8")
    assert "**NOT_APPLICABLE**" in shown and "nothing was reviewed" in shown and "0 reviewed" in shown
    assert "tools/build.py" not in shown + written


def test_doctor_reports_not_applicable_and_exits_zero(gate_case, capsys):  # noqa: F811
    change_policy(gate_case, **OPT_IN)
    _only(gate_case, OUTSIDE)
    report = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                              gate_case["pin"])
    assert report["status"] == "not_applicable" and not report["blockers"]
    assert report["not_applicable"] == {"changed": 1, "outside_allow_paths": 1, "reviewed": 0}
    assert report["coverage_complete"] is False and not report["ledger_opened"]
    assert main(["doctor", "--policy", "gate-policy.json", "--policy-sha256", gate_case["pin"], "--repo",
                 str(gate_case["repo"]), "--base", gate_case["base"], "--head", gate_case["head"]]) == 0
    capsys.readouterr()


def test_doctor_by_default_still_blocks(gate_case):  # noqa: F811
    change_policy(gate_case, unreviewable_paths="skip-and-report")
    _only(gate_case, OUTSIDE)
    report = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                              gate_case["pin"])
    assert report["status"] == "blocked" and "empty_model_context" in [b["code"] for b in report["blockers"]]


def test_sarif_has_no_results_and_says_nothing_was_reviewed(gate_case):  # noqa: F811
    log = from_document(_valid(gate_case))
    run_ = log["runs"][0]
    assert run_["results"] == []
    (notification,) = run_["invocations"][0]["toolExecutionNotifications"]
    assert notification["descriptor"]["id"] == "nothing_in_scope" and "nothing was reviewed" in notification["message"]["text"]
    assert run_["properties"]["kind"] == "model-gate-not-applicable"


def test_the_report_trace_refuses_a_report_that_reviewed_nothing(gate_case):  # noqa: F811
    report = _valid(gate_case)
    for trace in (score_gate_report, trace_markdown):
        with pytest.raises(AssistantError, match="^trace_report_not_a_review$"):
            trace(report)


# History suites: a case whose pinned policy puts its range out of scope is refused by name, before any key or request,
# and a range nothing was reviewed in is never a successful negative control.
def _history(case, *cases) -> dict:
    return {"version": 1, "cases": [
        {"id": f"synthetic-case-{index}", "repo_path": str(case["repo"]), "base_sha": base, "head_sha": head,
         "profile": "finance-saas", "negative_control": negative,
         "expected": [] if negative else [{"label": f"synthetic-target-{index}", "paths": ["src/cash.py"],
                                           "severity": "high"}],
         "policy": {"path": "gate-policy.json", "sha256": case["pin"]}}
        for index, (base, head, negative) in enumerate(cases)]}


@pytest.mark.parametrize("negative", [False, True])
def test_a_history_case_out_of_scope_is_refused_by_name(gate_case, monkeypatch, negative):  # noqa: F811
    change_policy(gate_case, **OPT_IN)
    _only(gate_case, OUTSIDE)
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    suite = _history(gate_case, (gate_case["base"], gate_case["head"], negative))
    with pytest.raises(AssistantError, match="^history_case_not_applicable$"):
        plan_history(suite, gate_case["repo"].parent, Config())
    calls = []
    with pytest.raises(AssistantError, match="^history_case_not_applicable$"):
        evaluate_history(suite, gate_case["repo"].parent, Config(), gate_case["state"], trials=1,
                         approved_suite_hash=history_approval_hash(suite, 1), network_approved=True,
                         transport=httpx.MockTransport(lambda request: calls.append(request)))
    assert calls == [] and not gate_case["state"].exists()


def test_a_mixed_suite_is_refused_before_any_request(gate_case):  # noqa: F811
    change_policy(gate_case, **OPT_IN)
    in_scope = gate_case["head"]
    _only(gate_case, OUTSIDE)
    suite = _history(gate_case, (gate_case["base"], in_scope, False), (gate_case["base"], gate_case["head"], False))
    calls = []
    with pytest.raises(AssistantError, match="^history_case_not_applicable$"):
        evaluate_history(suite, gate_case["repo"].parent, Config(), gate_case["state"], trials=1,
                         approved_suite_hash=history_approval_hash(suite, 1), network_approved=True,
                         transport=httpx.MockTransport(lambda request: calls.append(request)))
    assert calls == [] and not gate_case["state"].exists()


def test_the_history_command_names_the_refusal(gate_case, tmp_path, capsys, monkeypatch):  # noqa: F811
    change_policy(gate_case, **OPT_IN)
    _only(gate_case, OUTSIDE)
    monkeypatch.chdir(tmp_path)
    suite_file = gate_case["repo"].parent / "history.json"
    suite_file.write_bytes(canonical(_history(gate_case, (gate_case["base"], gate_case["head"], False))))
    assert main(["evaluate", "--history-suite", str(suite_file), "--trials", "1", "--state-dir",
                 str(tmp_path / "state"), "--output", str(tmp_path / "evaluation.json")]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "history_case_not_applicable"
    assert not (tmp_path / "evaluation.json").exists()
