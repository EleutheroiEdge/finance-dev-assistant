"""Fictional examples for a data-only protocol, never a model-quality benchmark."""
from copy import deepcopy
import json

import pytest
from jsonschema import Draft202012Validator
from importlib.resources import files

from finassist.errors import AssistantError
from finassist.triage_contract import (
    MAX_DOCUMENT_BYTES,
    parse_triage_json,
    request_hash,
    validate_gold,
    validate_request,
    validate_result,
)


def sample_case(case_id="case_a", *, source_kind="real", family_id="family_a"):
    request = {
        "schema_version": 1, "case_id": case_id, "task_revision": "1" * 40,
        "source_digest": "2" * 64, "context": "A fictional boundary condition changed.",
        "max_selected_checks": 1,
        "candidates": {
            "patterns": [{"id": "pattern_a", "description": "Boundary handling"}],
            "files": [{"id": "file_a", "description": "Primary module"},
                      {"id": "file_b", "description": "Secondary module"}],
            "checks": [{"id": "check_a", "description": "Boundary check"},
                       {"id": "check_b", "description": "Independent check"}],
        },
    }
    manifest = {"model_id": "fictional_scorer", "model_digest": "3" * 64,
                "scorer_revision": "4" * 40, "calibration_digest": "5" * 64}
    result = {
        "schema_version": 1, "case_id": case_id, "request_hash": request_hash(request),
        "model_manifest": manifest, "action": "recommend", "reason": "scored",
        "probabilities": {
            "patterns": [{"id": "pattern_a", "probability": 0.8}],
            "files": [{"id": "file_a", "probability": 0.75}, {"id": "file_b", "probability": 0.25}],
            "checks": [{"id": "check_a", "probability": 0.9}, {"id": "check_b", "probability": 0.2}],
        },
        "selected_patterns": ["pattern_a"], "selected_checks": ["check_a"],
        "ranked_files": ["file_a", "file_b"],
    }
    gold = {
        "schema_version": 1, "case_id": case_id, "request_hash": request_hash(request),
        "source_kind": source_kind, "family_id": family_id,
        "adjudication_status": "confirmed", "applicability_reason": "applicable",
        "is_control": False, "defect_status": "confirmed_defect",
        "catalog": {key: [v["id"] for v in values] for key, values in request["candidates"].items()},
        "patterns": {"required": ["pattern_a"], "optional": [], "forbidden": []},
        "checks": {"required": ["check_a"], "optional": ["check_b"], "forbidden": []},
        "acceptable_first_files": ["file_a"],
    }
    return request, result, gold, deepcopy(manifest)


def test_complete_data_only_contract_and_canonical_hash():
    request, result, gold, manifest = sample_case()
    validate_request(request)
    validate_result(request, result, expected_model_manifest=manifest)
    validate_gold(request, gold)
    assert request_hash(dict(reversed(list(request.items())))) == request_hash(request)
    assert parse_triage_json(json.dumps(result)) == result


@pytest.mark.parametrize("kind", ["request", "result", "gold"])
def test_packaged_schemas_are_valid(kind):
    schema = json.loads(files("finassist").joinpath("resources", f"triage-{kind}.schema.json").read_text())
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("payload", [
    '{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}',
    '[]', '{"x":', b"\xff", "[" * 2000 + "]" * 2000,
])
def test_untrusted_json_rejected_without_payload_in_error(payload):
    with pytest.raises(AssistantError) as failure:
        parse_triage_json(payload)
    assert failure.value.code.startswith("triage_")
    assert "payload" not in str(failure.value)


def test_json_limit_before_parsing():
    with pytest.raises(AssistantError, match="triage_document_too_large"):
        parse_triage_json(" " * (MAX_DOCUMENT_BYTES + 1))


@pytest.mark.parametrize("field,value", [
    ("gold", {}), ("family_id", "family_a"), ("labels", []),
    ("max_selected_checks", True), ("max_selected_checks", 1.0),
    ("schema_version", 1.0), ("task_revision", "main"), ("source_digest", "short"),
    ("case_id", "case_a\n"), ("task_revision", "1" * 40 + "\n"),
    ("source_digest", "2" * 64 + "\n"),
])
def test_request_with_labels_unknown_fields_or_unpinned_identity_is_invalid(field, value):
    request, _, _, _ = sample_case()
    request[field] = value
    with pytest.raises(AssistantError):
        validate_request(request)


def test_duplicate_candidate_across_namespaces_rejected():
    request, _, _, _ = sample_case()
    request["candidates"]["files"][0]["id"] = "check_a"
    with pytest.raises(AssistantError, match="triage_candidate_duplicate"):
        validate_request(request)


@pytest.mark.parametrize("mutation", ["context", "budget", "description"])
def test_response_cannot_be_replayed_after_request_policy_change(mutation):
    request, result, _, manifest = sample_case()
    if mutation == "context":
        request["context"] += " Additional change."
    elif mutation == "budget":
        request["max_selected_checks"] = 2
    else:
        request["candidates"]["checks"][0]["description"] = "Different obligation"
    with pytest.raises(AssistantError, match="triage_request_mismatch"):
        validate_result(request, result, expected_model_manifest=manifest)


@pytest.mark.parametrize("mutation", [
    "unknown_selection", "duplicate_selection", "missing_probability", "duplicate_probability",
    "nonfinite", "boolean_probability", "probability_range", "not_normalized", "incomplete_rank",
    "inconsistent_rank", "free_text", "wrong_model", "reason", "over_budget", "abstain_selection",
])
def test_bad_advisory_output_rejected(mutation):
    request, result, _, manifest = sample_case()
    if mutation == "unknown_selection":
        result["selected_checks"] = ["unknown_check"]
    elif mutation == "duplicate_selection":
        result["selected_checks"] *= 2
    elif mutation == "missing_probability":
        result["probabilities"]["checks"].pop()
    elif mutation == "duplicate_probability":
        result["probabilities"]["checks"][1] = deepcopy(result["probabilities"]["checks"][0])
    elif mutation in {"nonfinite", "boolean_probability", "probability_range"}:
        result["probabilities"]["patterns"][0]["probability"] = {
            "nonfinite": float("nan"), "boolean_probability": True, "probability_range": 1.1,
        }[mutation]
    elif mutation == "not_normalized":
        result["probabilities"]["files"][0]["probability"] = 0.5
    elif mutation == "incomplete_rank":
        result["ranked_files"].pop()
    elif mutation == "inconsistent_rank":
        result["ranked_files"].reverse()
    elif mutation == "free_text":
        result["explanation"] = "Run a command."
    elif mutation == "wrong_model":
        result["model_manifest"]["model_digest"] = "6" * 64
    elif mutation == "reason":
        result["reason"] = "uncertain"
    elif mutation == "over_budget":
        result["selected_checks"] = ["check_a", "check_b"]
    else:
        result["action"], result["reason"] = "abstain", "uncertain"
    with pytest.raises(AssistantError):
        validate_result(request, result, expected_model_manifest=manifest)


def test_abstention_is_explicit_and_does_not_emit_selections():
    request, result, _, manifest = sample_case()
    result.update(action="abstain", reason="uncertain", selected_patterns=[], selected_checks=[], ranked_files=[])
    validate_result(request, result, expected_model_manifest=manifest)


def test_independent_probabilities_need_not_sum_to_one():
    request, result, _, manifest = sample_case()
    result["probabilities"]["checks"] = [{"id": "check_a", "probability": 0.9},
                                         {"id": "check_b", "probability": 0.9}]
    validate_result(request, result, expected_model_manifest=manifest)


@pytest.mark.parametrize("mutation", ["overlap", "unlabeled", "unknown_file", "candidate_missing", "wrong_hash"])
def test_gold_requires_disjoint_complete_catalog_partition(mutation):
    request, _, gold, _ = sample_case()
    if mutation == "overlap":
        gold["checks"]["forbidden"] = ["check_a"]
    elif mutation == "unlabeled":
        gold["checks"]["optional"] = []
    elif mutation == "unknown_file":
        gold["acceptable_first_files"] = ["file_c"]
    elif mutation == "candidate_missing":
        gold["catalog"]["checks"].pop()
    else:
        gold["request_hash"] = "0" * 64
    with pytest.raises(AssistantError):
        validate_gold(request, gold)


def test_infeasible_budget_requires_explicit_confirmed_policy_failure():
    request, _, gold, _ = sample_case()
    gold["checks"] = {"required": ["check_a", "check_b"], "optional": [], "forbidden": []}
    with pytest.raises(AssistantError, match="triage_budget_infeasible"):
        validate_gold(request, gold)
    gold["applicability_reason"] = "budget_infeasible"
    validate_gold(request, gold)
    gold["adjudication_status"] = "not_applicable"
    with pytest.raises(AssistantError, match="triage_gold_status_invalid"):
        validate_gold(request, gold)


def test_gold_can_represent_omitted_required_candidates_even_when_no_candidates():
    request, _, gold, _ = sample_case()
    request["candidates"]["checks"] = []
    gold["request_hash"] = request_hash(request)
    validate_gold(request, gold)


def test_budget_cannot_be_silently_inflated_beyond_frozen_catalog():
    request, _, gold, _ = sample_case()
    request["max_selected_checks"] = 3
    gold["request_hash"] = request_hash(request)
    with pytest.raises(AssistantError, match="triage_budget_invalid"):
        validate_gold(request, gold)
