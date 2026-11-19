"""outcome_class names the kind of stop behind a verdict, without changing any verdict or exit code."""

from copy import deepcopy
from importlib.resources import files
import json

import pytest

from test_model_gate import gate_case, run  # noqa: F401 - fixture registration
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration
from finassist.errors import AssistantError
from finassist.model_gate import (EXIT_CODES, NoReviewScope, _not_applicable_report, refused_model_report,
                                  validate_model_report)
from finassist.outcome_class import CLASSES, REFUSED, model_outcome_class
from finassist.security import canonical, digest
from conftest import command
from test_providers_review import envelope, response


def _hinted_codes() -> set:
    codes = set()
    for resource in files("finassist").joinpath("resources").iterdir():
        if resource.name.startswith("hints-") and resource.name.endswith(".json"):
            codes.update(json.loads(resource.read_text(encoding="utf-8")))
    return codes


def test_every_refused_code_is_a_real_error_code():
    assert REFUSED <= _hinted_codes()


@pytest.mark.parametrize("verdict,reasons,expected", [
    ("PASS", [], "pass"),
    ("FAIL", ["gate_blocking_findings"], "fail"),
    ("NOT_APPLICABLE", ["nothing_in_scope"], "not_applicable"),
    ("BLOCKED", ["sensitive_content"], "refused"),
    ("BLOCKED", ["gate_policy_change_requires_review"], "refused"),
    ("BLOCKED", ["daily_budget_exceeded"], "refused"),
    ("BLOCKED", ["provider_timeout", "unreconciled_model_usage"], "incomplete"),
    ("BLOCKED", ["review_schema_invalid"], "incomplete"),
    ("BLOCKED", ["gate_input_or_audit_unavailable"], "incomplete"),
    ("BLOCKED", ["packet_limit_exceeded", "unreconciled_model_usage"], "incomplete"),  # mixed: did not complete
    ("BLOCKED", ["a_reason_no_table_lists"], "incomplete"),  # unknown: never a pass, never a rule
    ("BLOCKED", [], "incomplete"),
])
def test_the_class_follows_the_verdict_and_every_reason(verdict, reasons, expected):
    assert model_outcome_class(verdict, reasons) == expected and expected in CLASSES


def test_reports_carry_their_class_and_exit_codes_are_unchanged(gate_case):  # noqa: F811
    passed, _ = run(gate_case)
    assert passed["verdict"] == "PASS" and passed["outcome_class"] == "pass" and EXIT_CODES["PASS"] == 0
    assert refused_model_report("sensitive_content")["outcome_class"] == "refused"
    assert refused_model_report("provider_timeout")["outcome_class"] == "incomplete"
    assert EXIT_CODES["BLOCKED"] == 2 and EXIT_CODES["FAIL"] == 1 and EXIT_CODES["NOT_APPLICABLE"] == 0
    not_applicable = _not_applicable_report("a" * 40, "b" * 40, "c" * 64, NoReviewScope(1, "d" * 64))
    assert not_applicable["outcome_class"] == "not_applicable"


def _rehash(report: dict) -> dict:
    report["report_hash"] = digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
    return report


def test_a_report_cannot_claim_another_class(gate_case):  # noqa: F811
    for report in (run(gate_case)[0], refused_model_report("provider_timeout"), refused_model_report("hidden_characters")):
        for other in CLASSES:
            if other in ("not_applicable", report["outcome_class"]):
                continue
            forged = _rehash(dict(deepcopy(report), outcome_class=other))
            with pytest.raises(AssistantError, match="^gate_report_invalid$"):
                validate_model_report(forged)


@pytest.mark.parametrize("claim,reason", [
    ("Synthetic claim with " + chr(0x200B) + " a hidden character", "hidden_characters"),
    ("Synthetic " + "api" + '_key = "fixture-only-value"', "sensitive_content"),  # joined here, so the source holds none
], ids=["hidden", "credential"])
def test_a_reply_the_output_screens_refuse_is_incomplete_not_refused(gate_case, claim, reason):  # noqa: F811
    # The same codes on the change itself are rule stops; in the model's reply they mean the reply was unusable.
    def bad(packet):
        document = response(packet)
        document["findings"][0]["claim"] = claim
        return envelope(json.dumps(document))

    report, calls = run(gate_case, bad)
    assert len(calls) == 1 and report["verdict"] == "BLOCKED" and report["reasons"] == [reason]
    assert report["outcome_phase"] == "reply" and report["outcome_class"] == "incomplete"
    assert report["spend"]["actual_usd"] is not None  # the known usage is settled, as before


def test_the_same_code_on_the_change_itself_is_refused(gate_case):  # noqa: F811
    (gate_case["repo"] / "src/cash.py").write_text(
        "def balance(opening, deposits):\n    return opening" + chr(0x200B) + " - deposits\n", encoding="utf-8")
    command(gate_case["repo"], "add", "src/cash.py")
    command(gate_case["repo"], "commit", "-m", "Synthetic hidden character in the change")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and "hidden_characters" in report["reasons"]
    assert "outcome_phase" not in report and report["outcome_class"] == "refused"


def test_a_phase_is_valid_only_on_a_blocked_report(gate_case):  # noqa: F811
    passed = deepcopy(run(gate_case)[0])
    for forged in (dict(passed, outcome_phase="reply"), dict(refused_model_report("hidden_characters"), outcome_phase="input"),
                   dict(refused_model_report("hidden_characters"), outcome_phase="reply")):
        with pytest.raises(AssistantError, match="^gate_report_invalid$"):
            validate_model_report(_rehash(forged))  # the last: a reply phase makes the class incomplete, not refused


def test_a_report_written_before_the_class_still_validates(gate_case):  # noqa: F811
    report = deepcopy(run(gate_case)[0])
    report.pop("outcome_class")
    validate_model_report(_rehash(report))
