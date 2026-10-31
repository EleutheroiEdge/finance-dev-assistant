"""Offline advisory routing metrics for a supplied, separately adjudicated cohort.

Real and synthetic cases are never pooled. Family IDs are supplied declarations,
not proof of statistical independence. This module grants no readiness, test
reduction, merge or deployment authority and performs no inference or fallback.
"""

from __future__ import annotations

from collections import Counter

from .errors import AssistantError
from .triage_contract import (
    candidate_ids,
    validate_gold,
    validate_model_manifest,
    validate_request,
    validate_result,
)


def _ratio(successes: int, total: int) -> dict:
    return {"successes": successes, "total": total, "rate": successes / total if total else None}


def _index(rows: list[dict], name: str) -> dict[str, dict]:
    if not isinstance(rows, list) or len(rows) > 100_000:
        raise AssistantError("triage_cohort_invalid")
    indexed = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("case_id"), str):
            raise AssistantError(f"triage_{name}_identity_invalid")
        if row["case_id"] in indexed:
            raise AssistantError(f"triage_{name}_duplicate")
        indexed[row["case_id"]] = row
    return indexed


def _label_metrics(rows: list[dict], group: str) -> dict:
    counts = {}
    for row in rows:
        labels = row["gold"][group]
        selected = set(row["result"][f"selected_{group}"]) if row["recommended"] else set()
        for label in row["gold"]["catalog"][group]:
            item = counts.setdefault(label, Counter())
            if label in labels["required"]:
                item["tp" if label in selected else "fn"] += 1
            elif label in labels["forbidden"]:
                item["fp" if label in selected else "tn"] += 1
            else:
                item["optional"] += 1
    return {
        label: {
            **{key: count[key] for key in ("tp", "fp", "fn", "tn", "optional")},
            "precision": count["tp"] / (count["tp"] + count["fp"]) if count["tp"] + count["fp"] else None,
            "recall": count["tp"] / (count["tp"] + count["fn"]) if count["tp"] + count["fn"] else None,
        }
        for label, count in sorted(counts.items())
    }


def _cohort(rows: list[dict]) -> dict:
    eligible = [row for row in rows if row["gold"]["adjudication_status"] == "confirmed"]
    unresolved = sum(row["gold"]["adjudication_status"] == "unconfirmed" for row in rows)
    successes = sum(row["routing_success"] for row in eligible)
    recommended = [row for row in eligible if row["recommended"]]
    families = {}
    for row in eligible:
        families.setdefault(row["gold"]["family_id"], []).append(row["routing_success"])
    first_file = [row for row in eligible if row["gold"]["acceptable_first_files"]]
    result = {
        "total_supplied_cases": len(rows),
        "eligible_cases": len(eligible),
        "unconfirmed_cases": unresolved,
        "not_applicable_cases": len(rows) - len(eligible) - unresolved,
        "budget_infeasible_cases": sum(row["gold"]["applicability_reason"] == "budget_infeasible"
                                       for row in eligible),
        "exclusion_reasons": dict(sorted(Counter(
            row["gold"]["applicability_reason"] for row in rows
            if row["gold"]["adjudication_status"] != "confirmed"
        ).items())),
        "model_only_routing": _ratio(successes, len(eligible)),
        "selected_routing": _ratio(sum(row["routing_success"] for row in recommended), len(recommended)),
        "recommendation_coverage": _ratio(len(recommended), len(eligible)),
        "declared_eligible_family_groups": len(families),
        "all_cases_successful_by_family": _ratio(sum(all(v) for v in families.values()), len(families)),
        "outcomes": dict(sorted(Counter(row["outcome"] for row in eligible).items())),
        "missing_required_candidate_cases": sum(row["missing_required_candidate"] for row in eligible),
        "first_file_top1": _ratio(sum(row["file_top1"] for row in first_file), len(first_file)),
        "first_file_top3": _ratio(sum(row["file_top3"] for row in first_file), len(first_file)),
        "strata": {},
        "per_pattern": _label_metrics(eligible, "patterns"),
        "per_check": _label_metrics(eligible, "checks"),
    }
    for name, subset in (
        ("required_review", [r for r in eligible if r["gold"]["checks"]["required"]]),
        ("no_required_review", [r for r in eligible if not r["gold"]["checks"]["required"]]),
        ("control", [r for r in eligible if r["gold"]["is_control"]]),
        ("noncontrol", [r for r in eligible if not r["gold"]["is_control"]]),
    ):
        result["strata"][name] = _ratio(sum(r["routing_success"] for r in subset), len(subset))
    if unresolved:
        # Keep numerators/counts inspectable; do not headline a selectively
        # adjudicated subset as the quality of the full supplied cohort.
        for field in ("model_only_routing", "selected_routing", "all_cases_successful_by_family",
                      "first_file_top1", "first_file_top3"):
            result[field]["rate"] = None
        for stratum in result["strata"].values():
            stratum["rate"] = None
    return result


def evaluate_triage(
    requests: list[dict],
    gold: list[dict],
    predictions: list[dict],
    *,
    expected_model_manifest: dict,
) -> dict:
    """Score every supplied case; missing, invalid and abstained predictions miss.

    Required checks must be selected, forbidden checks must not be selected,
    and the request's predeclared count budget must hold. Optional checks are
    allowed. Pattern and file metrics are separate, not part of that primary
    routing endpoint. Gold must account for every request, even when still
    unconfirmed or explicitly inapplicable. No fallback result is synthesized.
    """
    validate_model_manifest(expected_model_manifest)
    request_map = _index(requests, "request")
    gold_map = _index(gold, "gold")
    prediction_map = _index(predictions, "prediction")
    if set(gold_map) != set(request_map):
        raise AssistantError("triage_gold_coverage_invalid")
    if not set(prediction_map) <= set(request_map):
        raise AssistantError("triage_prediction_unknown_case")
    rows = []
    for case_id, request in request_map.items():
        validate_request(request)
        labels = gold_map[case_id]
        validate_gold(request, labels)
        prediction = prediction_map.get(case_id)
        outcome = "missing"
        if prediction is not None:
            try:
                validate_result(request, prediction, expected_model_manifest=expected_model_manifest)
                outcome = prediction["action"]
            except AssistantError:
                outcome = "invalid"
        recommended = outcome == "recommend"
        selected = set(prediction["selected_checks"]) if recommended else set()
        required = set(labels["checks"]["required"])
        optional = set(labels["checks"]["optional"])
        routing_success = (recommended and labels["applicability_reason"] != "budget_infeasible"
                           and required <= selected <= required | optional
                           and len(selected) <= request["max_selected_checks"])
        accepted_files = set(labels["acceptable_first_files"])
        ranking = prediction["ranked_files"] if recommended else []
        rows.append({
            "gold": labels,
            "result": prediction,
            "recommended": recommended,
            "outcome": outcome,
            "routing_success": routing_success,
            "missing_required_candidate": not required <= set(candidate_ids(request, "checks")),
            "file_top1": bool(accepted_files & set(ranking[:1])),
            "file_top3": bool(accepted_files & set(ranking[:3])),
        })
    return {
        "schema_version": 1,
        "kind": "advisory-triage-evaluation",
        "advisory_only": True,
        "deployment_certified": False,
        "fallback_evaluated": False,
        "model_manifest": dict(expected_model_manifest),
        "primary_endpoint": "required-check routing within predeclared count budget",
        "population": "supplied cases; independence and representativeness not verified",
        "real": _cohort([row for row in rows if row["gold"]["source_kind"] == "real"]),
        "synthetic": _cohort([row for row in rows if row["gold"]["source_kind"] == "synthetic"]),
    }
