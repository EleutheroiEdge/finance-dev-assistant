"""Human-adjudicated history metrics; no lexical matching or model-as-judge."""

from decimal import Decimal, InvalidOperation
from itertools import combinations
import math
import re

from .errors import AssistantError
from .history_suite import SEVERITY_WEIGHTS, identifier, validate_expected
from .security import canonical, digest


def _hash(value) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise AssistantError("history_hash_invalid")


def _money(value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise AssistantError("history_cost_invalid")
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise AssistantError("history_cost_invalid") from exc
    if not number.is_finite() or number < 0 or number > Decimal("1000000000"):
        raise AssistantError("history_cost_invalid")
    return number


def validate_history_evaluation(evaluation: dict) -> None:
    if not isinstance(evaluation, dict):
        raise AssistantError("history_evaluation_invalid")
    expected_hash = digest(canonical({k: v for k, v in evaluation.items() if k != "evaluation_hash"}))
    if evaluation.get("evaluation_hash") != expected_hash:
        raise AssistantError("evaluation_hash_mismatch")
    if (type(evaluation.get("schema_version")) is not int or evaluation["schema_version"] != 2
            or evaluation.get("kind") != "history-evaluation"
            or evaluation.get("mode") not in ("offline", "model", "external")
            or type(evaluation.get("trials")) is not int or not 1 <= evaluation["trials"] <= 20):
        raise AssistantError("history_evaluation_invalid")
    _hash(evaluation.get("suite_hash"))
    cases = evaluation.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 50:
        raise AssistantError("history_evaluation_invalid")
    names = set()
    for case in cases:
        if not isinstance(case, dict):
            raise AssistantError("history_evaluation_invalid")
        name = identifier(case.get("id"))
        if name in names:
            raise AssistantError("history_identity_invalid")
        names.add(name)
        _hash(case.get("source_hash"))
        validate_expected(case.get("expected"), case.get("negative_control"))
        runs = case.get("runs")
        if not isinstance(runs, list) or len(runs) != evaluation["trials"]:
            raise AssistantError("history_trials_incomplete")
        for index, run in enumerate(runs, 1):
            if (not isinstance(run, dict) or type(run.get("trial")) is not int or run["trial"] != index
                    or run.get("status") not in ("complete", "blocked", "not-run", "offline")):
                raise AssistantError("history_run_invalid")
            _money(run.get("actual_usd"))
            seconds = run.get("elapsed_seconds")
            if seconds is not None and (type(seconds) not in {int, float} or not math.isfinite(seconds)
                                        or not 0 <= seconds <= 86400):
                raise AssistantError("history_elapsed_invalid")
            findings = run.get("findings")
            if not isinstance(findings, list) or len(findings) > 50:
                raise AssistantError("history_findings_invalid")
            ids = set()
            for finding in findings:
                if not isinstance(finding, dict):
                    raise AssistantError("history_findings_invalid")
                name = identifier(finding.get("id"))
                if name in ids:
                    raise AssistantError("history_findings_invalid")
                ids.add(name)
                # Reuse the same mandatory path checks as expected findings.
                validate_expected([{"label": name, "paths": [finding.get("path")],
                                    "severity": finding.get("severity")}], False)
            if run["status"] != "complete" and findings:
                raise AssistantError("history_incomplete_findings")
            if run["status"] == "not-run" and (run.get("actual_usd") is not None or seconds is not None):
                raise AssistantError("history_unattempted_cost")


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _jaccard(left: set, right: set):
    return len(left & right) / len(left | right) if left | right else 1.0


def score_history(evaluation: dict, labels: dict) -> dict:
    """Labels bind every returned finding to a held-out target or a false alarm.

    One target hit counts once per trial, even if several findings describe it.
    Incomplete runs/judgments never count as clean controls or zero-cost calls.
    """
    validate_history_evaluation(evaluation)
    if evaluation["mode"] == "offline":
        raise AssistantError("offline_run_is_not_model_evaluation")
    if (not isinstance(labels, dict) or set(labels) != {"evaluation_hash", "runs"}
            or labels["evaluation_hash"] != evaluation["evaluation_hash"]):
        raise AssistantError("evaluation_hash_mismatch")
    if not isinstance(labels["runs"], list) or len(labels["runs"]) > 1000:
        raise AssistantError("history_adjudication_invalid")
    judgments = {}
    for item in labels["runs"]:
        if (not isinstance(item, dict) or set(item) != {"case_id", "trial", "findings"}
                or type(item["trial"]) is not int or not isinstance(item["findings"], dict)):
            raise AssistantError("history_adjudication_invalid")
        key = (identifier(item["case_id"]), item["trial"])
        if key in judgments:
            raise AssistantError("history_adjudication_duplicate")
        judgments[key] = item["findings"]
    required = {(case["id"], run["trial"]) for case in evaluation["cases"] for run in case["runs"]
                if run["status"] == "complete"}
    if set(judgments) != required:
        raise AssistantError("adjudication_incomplete")
    cases, target_sets = [], {}
    total_hits, total_weight, hit_weight, negative_count, alarms, other_hits = 0, 0, 0, 0, 0, 0
    contaminated_controls = []
    total_dollars, total_seconds = Decimal(0), 0.0
    known_dollars = known_seconds = complete = True
    for case in evaluation["cases"]:
        expected = {item["label"]: item for item in case["expected"]}
        hits_by_trial, false_alarms, case_complete = [], [], True
        for run in case["runs"]:
            money, seconds = _money(run.get("actual_usd")), run.get("elapsed_seconds")
            if run["status"] != "not-run":
                known_dollars &= money is not None
                known_seconds &= seconds is not None
                total_dollars += money if money is not None else Decimal(0)
                total_seconds += seconds if seconds is not None else 0
            if run["status"] != "complete":
                case_complete = complete = False
                continue
            findings = {finding["id"]: finding for finding in run["findings"]}
            judgment = judgments[(case["id"], run["trial"])]
            if set(judgment) != set(findings):
                raise AssistantError("adjudication_incomplete")
            hits, alarm = set(), False
            for name, decision in judgment.items():
                if (not isinstance(decision, dict) or set(decision) != {"outcome", "label"}
                        or decision["outcome"] not in (
                            "confirmed-hit", "confirmed-other", "false-alarm", "unresolved")):
                    raise AssistantError("history_adjudication_invalid")
                if decision["outcome"] == "confirmed-hit":
                    label = identifier(decision["label"])
                    if label not in expected or findings[name]["path"] not in expected[label]["paths"]:
                        raise AssistantError("adjudication_label_conflict")
                    hits.add(label)
                else:
                    if decision["label"] is not None:
                        raise AssistantError("adjudication_label_conflict")
                    alarm |= decision["outcome"] == "false-alarm"
                    if decision["outcome"] == "confirmed-other":
                        other_hits += 1
                        if case["negative_control"]:
                            contaminated_controls.append({"id": case["id"], "trial": run["trial"]})
                            case_complete = complete = False
                    if decision["outcome"] == "unresolved":
                        case_complete = complete = False
            hits_by_trial.append(hits)
            false_alarms.append(alarm)
            total_hits += len(hits)
            total_weight += sum(SEVERITY_WEIGHTS[item["severity"]] for item in expected.values())
            hit_weight += sum(SEVERITY_WEIGHTS[expected[label]["severity"]] for label in hits)
            if case["negative_control"]:
                negative_count += 1
                alarms += int(alarm)
        pairs = list(combinations(hits_by_trial, 2))
        weights = sum(SEVERITY_WEIGHTS[item["severity"]] for item in expected.values())
        recall = [_ratio(sum(SEVERITY_WEIGHTS[expected[label]["severity"]] for label in hits), weights)
                  for hits in hits_by_trial]
        target_sets[case["id"]] = sorted(set().union(*hits_by_trial))
        cases.append({"id": case["id"], "complete": case_complete,
                      "trial_confirmed_labels": [sorted(hits) for hits in hits_by_trial],
                      "trial_weighted_recall": recall if case_complete else None,
                      "mean_weighted_recall": (sum(recall) / len(recall)
                                               if case_complete and weights and recall else None),
                      "trial_false_alarm": false_alarms if case_complete else None,
                      "pairwise_confirmed_label_agreement": (
                          sum(_jaccard(a, b) for a, b in pairs) / len(pairs)
                          if case_complete and pairs else None),
                      "pairwise_false_alarm_agreement": (
                          sum(a == b for a, b in combinations(false_alarms, 2)) / len(pairs)
                          if case_complete and pairs else None)})
    result = {"evaluation_hash": evaluation["evaluation_hash"], "complete": complete,
              "severity_weights": SEVERITY_WEIGHTS, "cases": cases, "confirmed_target_hits": total_hits,
              "confirmed_other_findings": other_hits, "contaminated_controls": contaminated_controls,
              "severity_weighted_recall": _ratio(hit_weight, total_weight) if complete else None,
              "negative_control_false_alarm_rate": _ratio(alarms, negative_count) if complete else None,
              "actual_usd": str(total_dollars) if known_dollars else None,
              "elapsed_seconds": total_seconds if known_seconds else None,
              "dollars_per_confirmed_hit": (str(total_dollars / total_hits)
                                            if complete and known_dollars and total_hits else None),
              "seconds_per_confirmed_hit": (_ratio(total_seconds, total_hits)
                                            if complete and known_seconds else None),
              "confirmed_labels": target_sets,
              "qualification": "Human-adjudicated target recall; hits deduplicated per target per trial. "
              "Costs include misses and false alarms. Agreement is pairwise target-set Jaccard "
              "(two empty sets agree), not correctness. Incomplete quality metrics are withheld. "
              "Local hashes bind bytes, not label truth or reviewer identity."}
    return {**result, "score_hash": digest(canonical(result))}


def compare_history(left: dict, left_labels: dict, right: dict, right_labels: dict) -> dict:
    first, second = score_history(left, left_labels), score_history(right, right_labels)
    if not first["complete"] or not second["complete"]:
        raise AssistantError("history_comparison_incomplete")
    def identities(evaluation):
        return {case["id"]: (case["source_hash"], digest(canonical({
            "expected": case["expected"], "negative_control": case["negative_control"]})))
                for case in evaluation["cases"]}
    if identities(left) != identities(right):
        raise AssistantError("history_comparison_scope_mismatch")
    rows = []
    for name in first["confirmed_labels"]:
        a, b = set(first["confirmed_labels"][name]), set(second["confirmed_labels"][name])
        rows.append({"id": name, "both": sorted(a & b), "left_only": sorted(a - b),
                     "right_only": sorted(b - a), "overlap_jaccard": _jaccard(a, b) if a | b else None})
    result = {"left": first, "right": second, "overlap": rows,
              "qualification": "Overlap of independently adjudicated held-out target labels detected "
              "in any trial; unequal trial counts affect detection opportunity. External findings "
              "must use the same history-evaluation envelope with operator-attested source identity."}
    return {**result, "comparison_hash": digest(canonical(result))}
