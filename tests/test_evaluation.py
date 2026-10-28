from dataclasses import replace
import json
from pathlib import Path

import pytest

from finassist.config import Config
from finassist.errors import AssistantError
from finassist.evaluation import evaluate, score, validate_suite
from finassist.security import canonical, digest


def suite():
    return json.loads((Path(__file__).parents[1] / "examples/review-cases.json").read_text())


def test_suite_constructs_reproducible_source_without_model_calls(tmp_path):
    first = evaluate(suite(), Config(), tmp_path / "state")
    second = evaluate(suite(), Config(), tmp_path / "state")
    assert first == second
    assert len(first["cases"]) == 4
    assert not first["model_quality_measured"]
    assert all(case["report"]["status"] == "offline-analysis" for case in first["cases"])
    assert not (tmp_path / "state").exists()


def test_live_suite_needs_explicit_input_approval(tmp_path):
    config = replace(Config(), provider="openai", model="selected")
    with pytest.raises(AssistantError, match="eval_suite_approval_required"):
        evaluate(suite(), config, tmp_path)


def test_offline_results_cannot_be_graded_as_model_quality(tmp_path):
    result = evaluate(suite(), Config(), tmp_path)
    with pytest.raises(AssistantError, match="offline_run_is_not_model_evaluation"):
        score(result, {"evaluation_hash": result["evaluation_hash"]})


def test_scoring_requires_integrity_complete_judgments_and_label_consistency():
    data = {
        "provider": "fictional",
        "cases": [
            {"id": "positive", "expected_defect": True},
            {"id": "negative", "expected_defect": False},
        ],
    }
    result = {**data, "evaluation_hash": digest(canonical(data))}
    labels = {
        "evaluation_hash": result["evaluation_hash"],
        "outcomes": {"positive": "confirmed-hit", "negative": "clean"},
    }
    graded = score(result, labels)
    assert graded["case_recall"] == 1 and graded["negative_control_false_alarm_rate"] == 0
    with pytest.raises(AssistantError, match="adjudication_incomplete"):
        score(result, {**labels, "outcomes": {}})
    with pytest.raises(AssistantError, match="adjudication_label_conflict"):
        score(result, {**labels, "outcomes": {"positive": "clean", "negative": "clean"}})
    result["provider"] = "changed"
    with pytest.raises(AssistantError, match="evaluation_hash_mismatch"):
        score(result, labels)


def test_eval_rejects_private_paths_and_bad_case_identity():
    data = suite()
    data["cases"][0]["path"] = ".env"
    with pytest.raises(AssistantError):
        validate_suite(data)
    data = suite()
    data["cases"][1]["id"] = data["cases"][0]["id"]
    with pytest.raises(AssistantError, match="invalid_eval_identity"):
        validate_suite(data)
