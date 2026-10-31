from copy import deepcopy

import pytest

from finassist.errors import AssistantError
from finassist.security import canonical, digest
from finassist.triage_contract import request_hash
from finassist.triage_metrics import evaluate_triage
from test_triage_contract import sample_case


def report(cases, predictions=None):
    return evaluate_triage([c[0] for c in cases], [c[2] for c in cases],
                           [c[1] for c in cases] if predictions is None else predictions,
                           expected_model_manifest=cases[0][3])


def test_primary_is_required_check_route_not_pattern_or_file_joint_tuple():
    case = sample_case()
    case[1]["selected_patterns"] = []
    case[2]["acceptable_first_files"] = ["file_b"]
    result = report([case])
    assert result["real"]["model_only_routing"] == {"successes": 1, "total": 1, "rate": 1}
    assert result["real"]["first_file_top1"]["rate"] == 0
    assert result["real"]["first_file_top3"]["rate"] == 1
    assert result["real"]["per_pattern"]["pattern_a"]["recall"] == 0
    assert not result["deployment_certified"] and not result["fallback_evaluated"]


def test_missing_invalid_and_abstain_are_all_case_misses_not_dropped():
    cases = [sample_case(f"case_{i}", family_id=f"family_{i}") for i in range(4)]
    cases[1][1].update(action="abstain", reason="uncertain", selected_patterns=[], selected_checks=[], ranked_files=[])
    cases[2][1]["request_hash"] = "0" * 64
    result = report(cases, [c[1] for c in cases[:3]])["real"]
    assert result["model_only_routing"] == {"successes": 1, "total": 4, "rate": 0.25}
    assert result["selected_routing"]["rate"] == 1
    assert result["recommendation_coverage"]["rate"] == 0.25
    assert result["outcomes"] == {"abstain": 1, "contract_invalid": 1, "missing": 1, "recommend": 1}
    assert result["per_check"]["check_a"]["fn"] == 3


def test_candidate_retrieval_omission_is_end_to_end_miss():
    case = sample_case()
    request, result, gold, _ = case
    request["candidates"]["checks"] = []
    result.update(request_hash=request_hash(request), selected_checks=[])
    result["probabilities"]["checks"] = []
    gold["request_hash"] = request_hash(request)
    score = report([case])["real"]
    assert score["model_only_routing"]["rate"] == 0
    assert score["missing_required_candidate_cases"] == 1
    assert score["per_check"]["check_a"]["fn"] == 1


def test_optional_allowed_forbidden_and_overbudget_fail():
    cases = [sample_case(f"case_{i}") for i in range(3)]
    for request, result, gold, _ in cases:
        request["max_selected_checks"] = 2
        result.update(request_hash=request_hash(request), selected_checks=["check_a", "check_b"])
        gold["request_hash"] = request_hash(request)
    cases[1][2]["checks"] = {"required": ["check_a"], "optional": [], "forbidden": ["check_b"]}
    cases[2][0]["max_selected_checks"] = 1
    cases[2][1]["request_hash"] = request_hash(cases[2][0])
    cases[2][2]["request_hash"] = request_hash(cases[2][0])
    score = report(cases)["real"]
    assert score["model_only_routing"]["successes"] == 1
    assert score["model_only_routing"]["total"] == 3
    assert score["per_check"]["check_b"]["fp"] == 1


def test_controls_and_no_required_review_are_distinct_strata():
    clean_but_review = sample_case("case_a")
    clean_but_review[2].update(is_control=True, defect_status="no_confirmed_defect")
    no_review = sample_case("case_b")
    no_review[2]["checks"] = {"required": [], "optional": [], "forbidden": ["check_a", "check_b"]}
    no_review[1]["selected_checks"] = []
    score = report([clean_but_review, no_review])["real"]
    assert score["strata"]["control"]["total"] == 1
    assert score["strata"]["required_review"]["total"] == 1
    assert score["strata"]["no_required_review"]["total"] == 1
    assert score["model_only_routing"]["successes"] == 2


def test_synthetic_not_pooled_and_family_success_requires_every_case():
    first, second = sample_case("case_a"), sample_case("case_b")
    second[1]["selected_checks"] = []
    synthetic = sample_case("case_c", source_kind="synthetic", family_id="family_b")
    result = report([first, second, synthetic])
    assert result["real"]["model_only_routing"]["rate"] == 0.5
    assert result["real"]["declared_eligible_family_groups"] == 1
    assert result["real"]["all_cases_successful_by_family"]["rate"] == 0
    assert result["synthetic"]["model_only_routing"]["rate"] == 1
    assert "overall_accuracy" not in result


def test_zero_denominators_are_unknown_and_unconfirmed_withholds_headline_rates():
    case = sample_case()
    case[2].update(adjudication_status="unconfirmed", applicability_reason="pending_adjudication")
    score = report([case])["real"]
    assert score["unconfirmed_cases"] == 1
    assert score["model_only_routing"]["rate"] is None
    assert score["selected_routing"]["rate"] is None
    eligible = sample_case("case_b")
    score = report([case, eligible])["real"]
    assert score["model_only_routing"]["successes"] == 1
    assert score["model_only_routing"]["rate"] is None


def test_infeasible_budget_is_primary_miss_never_an_exclusion():
    case = sample_case()
    case[2]["checks"] = {"required": ["check_a", "check_b"], "optional": [], "forbidden": []}
    case[2]["applicability_reason"] = "budget_infeasible"
    passing = sample_case("case_b")
    score = report([case, passing])["real"]
    assert score["total_supplied_cases"] == 2 and score["eligible_cases"] == 2
    assert score["not_applicable_cases"] == 0 and score["budget_infeasible_cases"] == 1
    assert score["exclusion_reasons"] == {}
    assert score["model_only_routing"] == {"successes": 1, "total": 2, "rate": 0.5}


@pytest.mark.parametrize("mutation", ["duplicate_request", "duplicate_prediction", "missing_gold", "unknown_prediction"])
def test_cohort_identity_does_not_allow_cherry_picking(mutation):
    request, result, gold, manifest = sample_case()
    requests, predictions, labels = [request], [result], [gold]
    if mutation == "duplicate_request":
        requests.append(deepcopy(request))
    elif mutation == "duplicate_prediction":
        predictions.append(deepcopy(result))
    elif mutation == "missing_gold":
        labels = []
    else:
        predictions[0]["case_id"] = "unknown_case"
    with pytest.raises(AssistantError):
        evaluate_triage(requests, labels, predictions, expected_model_manifest=manifest)


def test_wrong_model_manifest_is_counted_as_invalid():
    case = sample_case()
    case[1]["model_manifest"]["calibration_digest"] = "9" * 64
    score = report([case])["real"]
    assert score["outcomes"] == {"contract_invalid": 1}
    assert score["model_only_routing"]["rate"] == 0


def test_semantic_hashes_bind_full_collections_and_preserve_array_order():
    cases = [sample_case("case_a"), sample_case("case_b")]
    baseline = report(cases)
    assert baseline["input_hashes"] == {
        "scheme": "sha256-finassist-canonical-json",
        **{field: digest(canonical({"schema_version": 1, field: [case[index] for case in cases]}))
           for field, index in (("requests", 0), ("gold", 2), ("predictions", 1))},
        "model_manifest": digest(canonical(cases[0][3])),
    }
    assert not baseline["execution_authorized"]
    reordered = report(list(reversed(cases)))
    for field in ("requests", "gold", "predictions"):
        assert baseline["input_hashes"][field] != reordered["input_hashes"][field]
    cases[0][1]["unexpected_evidence"] = "fictional malformed prediction"
    changed = report(cases)
    assert changed["real"]["outcomes"]["contract_invalid"] == 1
    assert changed["input_hashes"]["predictions"] != baseline["input_hashes"]["predictions"]
    assert changed["input_hashes"]["requests"] == baseline["input_hashes"]["requests"]
    assert "fictional malformed prediction" not in str(changed)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object()])
def test_python_predictions_without_a_json_representation_fail_clearly(value):
    case = sample_case()
    case[1]["unexpected_evidence"] = value
    with pytest.raises(AssistantError, match="triage_input_not_canonical_json"):
        report([case])


def test_declared_invalid_contract_invalid_and_missing_have_distinct_support():
    cases = [sample_case(f"case_{i}") for i in range(6)]
    cases[0][1].update(action="invalid", reason="inference_error",
                       selected_checks=[], selected_patterns=[], ranked_files=[])
    cases[1][1]["request_hash"] = "0" * 64
    cases[3][2].update(adjudication_status="unconfirmed", applicability_reason="pending_adjudication")
    cases[4][2].update(adjudication_status="not_applicable", applicability_reason="outside_scope")
    score = report(cases, [case[1] for index, case in enumerate(cases) if index != 2])["real"]
    assert score["outcomes"] == {"declared_invalid": 1, "contract_invalid": 1, "missing": 1, "recommend": 1}
    assert score["total_supplied_cases"] == 6 and score["eligible_cases"] == 4
    assert score["unconfirmed_cases"] == score["not_applicable_cases"] == 1
    assert score["exclusion_reasons"] == {"outside_scope": 1, "pending_adjudication": 1}
    assert score["model_only_routing"] == {"successes": 1, "total": 4, "rate": None}


def test_outside_scope_is_an_asserted_exclusion_even_if_budget_would_be_infeasible():
    excluded = sample_case("excluded")
    excluded[2]["checks"] = {"required": ["check_a", "check_b"], "optional": [], "forbidden": []}
    excluded[2].update(adjudication_status="not_applicable", applicability_reason="outside_scope")
    score = report([sample_case(), excluded])["real"]
    assert score["total_supplied_cases"] == 2 and score["eligible_cases"] == 1
    assert score["not_applicable_cases"] == 1 and score["budget_infeasible_cases"] == 0
    assert score["exclusion_reasons"] == {"outside_scope": 1}
    assert score["model_only_routing"] == {"successes": 1, "total": 1, "rate": 1}


def test_first_file_denominator_uses_eligible_nonempty_gold_and_keeps_missing_predictions():
    cases = [sample_case(f"case_{i}") for i in range(5)]
    cases[0][2]["acceptable_first_files"] = ["file_b"]  # top1 miss, top3 hit
    cases[2][2]["acceptable_first_files"] = []
    cases[3][2].update(adjudication_status="not_applicable", applicability_reason="outside_scope")
    cases[4][2]["acceptable_first_files"] = ["file_a", "file_b"]
    score = report(cases, [case[1] for index, case in enumerate(cases) if index != 1])["real"]
    assert score["first_file_top1"] == {"successes": 1, "total": 3, "rate": 1 / 3}
    assert score["first_file_top3"] == {"successes": 2, "total": 3, "rate": 2 / 3}
    for case in cases:
        case[2]["acceptable_first_files"] = []
    assert report(cases)["real"]["first_file_top1"] == {"successes": 0, "total": 0, "rate": None}


def test_optional_labels_never_become_positive_or_negative_metric_judgments():
    cases = [sample_case(f"case_{i}") for i in range(2)]
    request, prediction, gold, _ = cases[0]
    request["max_selected_checks"] = 2
    prediction.update(request_hash=request_hash(request), selected_checks=["check_a", "check_b"])
    gold["request_hash"] = request_hash(request)
    label = report(cases)["real"]["per_check"]["check_b"]
    assert label == {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "optional": 2,
                     "precision": None, "recall": None}
