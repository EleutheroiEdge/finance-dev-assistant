from copy import deepcopy

import pytest

from finassist.errors import AssistantError
from finassist.history_scoring import compare_history, score_history
from finassist.security import canonical, digest


def signed(value):
    value = {k: v for k, v in value.items() if k != "evaluation_hash"}
    return {**value, "evaluation_hash": digest(canonical(value))}


def evaluation():
    def run(trial, findings):
        return {"trial": trial, "status": "complete", "findings": [
            {"id": name, "path": "src/cash.py", "severity": "high"} for name in findings],
            "actual_usd": "0.10", "elapsed_seconds": 2.0}
    return signed({"schema_version": 2, "kind": "history-evaluation", "mode": "model", "trials": 2,
                   "suite_hash": "a" * 64, "cases": [
                       {"id": "positive", "source_hash": "b" * 64, "negative_control": False,
                        "expected": [{"label": "major", "paths": ["src/cash.py"], "severity": "high"},
                                     {"label": "minor", "paths": ["src/cash.py"], "severity": "low"}],
                        "runs": [run(1, ["one", "duplicate"]), run(2, ["two"])]},
                       {"id": "negative", "source_hash": "c" * 64, "negative_control": True,
                        "expected": [], "runs": [run(1, ["alarm"]), run(2, [])]}]})


def adjudication(data):
    return {"evaluation_hash": data["evaluation_hash"], "runs": [
        {"case_id": "positive", "trial": 1, "findings": {
            name: {"outcome": "confirmed-hit", "label": "major"} for name in ["one", "duplicate"]}},
        {"case_id": "positive", "trial": 2, "findings": {
            "two": {"outcome": "confirmed-hit", "label": "minor"}}},
        {"case_id": "negative", "trial": 1, "findings": {
            "alarm": {"outcome": "false-alarm", "label": None}}},
        {"case_id": "negative", "trial": 2, "findings": {}}]}


def test_weighted_recall_costs_include_misses_and_false_alarms_and_deduplicate_hits():
    data = evaluation()
    result = score_history(data, adjudication(data))
    assert result["complete"] and result["confirmed_target_hits"] == 2
    assert result["severity_weighted_recall"] == 0.5
    assert result["cases"][0]["trial_weighted_recall"] == [4 / 6, 2 / 6]
    assert result["negative_control_false_alarm_rate"] == 0.5
    assert result["dollars_per_confirmed_hit"] == "0.20"
    assert result["seconds_per_confirmed_hit"] == 4
    assert result["cases"][0]["pairwise_confirmed_label_agreement"] == 0
    assert result["cases"][1]["pairwise_false_alarm_agreement"] == 0


def test_unresolved_judgment_withholds_quality_and_efficiency():
    data = evaluation()
    labels = adjudication(data)
    labels["runs"][2]["findings"]["alarm"] = {"outcome": "unresolved", "label": None}
    result = score_history(data, labels)
    assert not result["complete"]
    assert result["severity_weighted_recall"] is None
    assert result["negative_control_false_alarm_rate"] is None
    assert result["dollars_per_confirmed_hit"] is None
    assert result["cases"][1]["trial_false_alarm"] is None


def test_confirmed_new_defect_is_not_a_false_alarm_and_contaminates_a_control():
    data = evaluation()
    labels = adjudication(data)
    labels["runs"][2]["findings"]["alarm"] = {"outcome": "confirmed-other", "label": None}
    result = score_history(data, labels)
    assert result["confirmed_other_findings"] == 1
    assert result["contaminated_controls"] == [{"id": "negative", "trial": 1}]
    assert not result["complete"] and result["negative_control_false_alarm_rate"] is None


def test_unknown_call_is_not_zero_cost_or_a_clean_control():
    data = evaluation()
    run = data["cases"][1]["runs"][0]
    run.update(status="blocked", findings=[], actual_usd=None)
    data = signed(data)
    labels = adjudication(data)
    labels["runs"].pop(2)
    result = score_history(data, labels)
    assert not result["complete"] and result["actual_usd"] is None
    assert result["negative_control_false_alarm_rate"] is None


@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate", "wrong-target", "wrong-path"])
def test_every_finding_requires_one_scope_consistent_human_judgment(mutation):
    data = evaluation()
    if mutation == "wrong-path":
        data["cases"][0]["expected"][0]["paths"] = ["src/other.py"]
        data = signed(data)
    labels = adjudication(data)
    if mutation == "missing":
        del labels["runs"][0]["findings"]["duplicate"]
    elif mutation == "extra":
        labels["runs"][0]["findings"]["invented"] = {"outcome": "confirmed-hit", "label": "major"}
    elif mutation == "duplicate":
        labels["runs"].append(deepcopy(labels["runs"][0]))
    elif mutation == "wrong-target":
        labels["runs"][0]["findings"]["one"]["label"] = "invented"
    with pytest.raises(AssistantError):
        score_history(data, labels)


@pytest.mark.parametrize("amount", ["NaN", "Infinity", "-0.1", "1e100", 0, True])
def test_invalid_costs_refused(amount):
    data = evaluation()
    data["cases"][0]["runs"][0]["actual_usd"] = amount
    data = signed(data)
    with pytest.raises(AssistantError, match="history_cost_invalid"):
        score_history(data, adjudication(data))


def test_hash_bindings_offline_refusal_and_external_overlap():
    data = evaluation()
    labels = adjudication(data)
    changed = deepcopy(data)
    changed["mode"] = "external"
    with pytest.raises(AssistantError, match="evaluation_hash_mismatch"):
        score_history(changed, labels)
    external = signed(changed)
    other_labels = adjudication(external)
    other_labels["runs"][1]["findings"]["two"] = {"outcome": "false-alarm", "label": None}
    result = compare_history(data, labels, external, other_labels)
    assert result["overlap"][0] == {"id": "positive", "both": ["major"], "left_only": ["minor"],
                                    "right_only": [], "overlap_jaccard": 0.5}
    external["cases"][0]["source_hash"] = "d" * 64
    external = signed(external)
    with pytest.raises(AssistantError, match="history_comparison_scope_mismatch"):
        compare_history(data, labels, external, adjudication(external))
    offline = signed({**data, "mode": "offline"})
    with pytest.raises(AssistantError, match="offline_run_is_not_model_evaluation"):
        score_history(offline, adjudication(offline))
