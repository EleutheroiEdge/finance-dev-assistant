"""Data-only advisory triage contracts. Nothing here calls or loads a model.

Requests contain source context and a declared candidate/budget policy, never
evaluation labels. Gold remains a separate local object. Hashes bind bytes,
not authorship, confidentiality, label quality or permission to skip checks.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
import json
import math

from jsonschema import Draft202012Validator

from .errors import AssistantError
from .security import canonical, check_text, digest

MAX_DOCUMENT_BYTES = 2_000_000
GROUPS = ("patterns", "files", "checks")


def parse_triage_json(payload: str | bytes) -> dict:
    """Parse bounded JSON without duplicate keys, non-finite values or payload errors."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AssistantError("triage_duplicate_json_key")
            result[key] = value
        return result

    def constant(_value):
        raise AssistantError("triage_nonfinite_number")

    try:
        if not isinstance(payload, (str, bytes)):
            raise AssistantError("triage_json_invalid")
        encoded = payload.encode("utf-8") if isinstance(payload, str) else payload
        if len(encoded) > MAX_DOCUMENT_BYTES:
            raise AssistantError("triage_document_too_large")
        value = json.loads(encoded.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        if not isinstance(value, dict):
            raise AssistantError("triage_json_invalid")
        # Exponent overflow (e.g. 1e999) does not use parse_constant.
        canonical(value)
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise AssistantError("triage_json_invalid") from exc


@lru_cache(maxsize=3)
def _validator(kind: str) -> Draft202012Validator:
    schema = json.loads(files("finassist").joinpath("resources", f"triage-{kind}.schema.json").read_text())
    return Draft202012Validator(schema)


def _validate(value: dict, kind: str) -> None:
    try:
        encoded = canonical(value)
        if len(encoded) > MAX_DOCUMENT_BYTES:
            raise AssistantError("triage_document_too_large")
        if not _validator(kind).is_valid(value):
            raise AssistantError(f"triage_{kind}_invalid")
        if type(value["schema_version"]) is not int:
            raise AssistantError(f"triage_{kind}_invalid")
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise AssistantError(f"triage_{kind}_invalid") from exc


def candidate_ids(request: dict, group: str) -> list[str]:
    """Read an already validated request's candidate IDs, preserving declared order."""
    return [item["id"] for item in request["candidates"][group]]


def validate_request(request: dict) -> None:
    _validate(request, "request")
    if type(request["max_selected_checks"]) is not int:
        raise AssistantError("triage_request_invalid")
    all_ids = [item["id"] for group in GROUPS for item in request["candidates"][group]]
    if len(all_ids) != len(set(all_ids)):
        raise AssistantError("triage_candidate_duplicate")
    check_text(request["context"])
    for group in GROUPS:
        for item in request["candidates"][group]:
            check_text(item["description"])


def request_hash(request: dict) -> str:
    """Digest the complete validated request, including its predeclared budget."""
    validate_request(request)
    return digest(canonical(request))


def validate_model_manifest(manifest: dict) -> None:
    """Validate a caller-pinned model identity; do not inspect a model or its files."""
    schema = _validator("result").schema["$defs"]["model_manifest"]
    if not Draft202012Validator(schema).is_valid(manifest):
        raise AssistantError("triage_model_manifest_invalid")


def validate_result(request: dict, result: dict, *, expected_model_manifest: dict) -> None:
    """Require complete vectors and exact request/model binding, with no free text."""
    expected_hash = request_hash(request)
    validate_model_manifest(expected_model_manifest)
    _validate(result, "result")
    if result["case_id"] != request["case_id"] or result["request_hash"] != expected_hash:
        raise AssistantError("triage_request_mismatch")
    if result["model_manifest"] != expected_model_manifest:
        raise AssistantError("triage_model_mismatch")
    allowed_reasons = {
        "recommend": {"scored"},
        "abstain": {"uncertain", "insufficient_context", "out_of_distribution"},
        "invalid": {"invalid_input", "inference_error", "timeout"},
    }
    if result["reason"] not in allowed_reasons[result["action"]]:
        raise AssistantError("triage_action_reason_invalid")
    probabilities = {}
    for group in GROUPS:
        ids = candidate_ids(request, group)
        rows = result["probabilities"][group]
        found = [item["id"] for item in rows]
        if len(found) != len(set(found)) or set(found) != set(ids):
            raise AssistantError("triage_probability_coverage_invalid")
        probabilities[group] = {item["id"]: item["probability"] for item in rows}
        for probability in probabilities[group].values():
            if type(probability) not in {int, float} or not math.isfinite(probability):
                raise AssistantError("triage_probability_invalid")
        if group == "files" and ids and not math.isclose(
            math.fsum(probabilities[group].values()), 1.0, rel_tol=0, abs_tol=1e-9
        ):
            raise AssistantError("triage_file_probabilities_not_normalized")
    for field, group in (
        ("selected_patterns", "patterns"),
        ("selected_checks", "checks"),
        ("ranked_files", "files"),
    ):
        ids = result[field]
        if len(ids) != len(set(ids)) or not set(ids) <= set(candidate_ids(request, group)):
            raise AssistantError("triage_selection_invalid")
    if result["action"] != "recommend":
        if any(result[field] for field in ("selected_patterns", "selected_checks", "ranked_files")):
            raise AssistantError("triage_nonrecommend_selection")
    else:
        ranking = result["ranked_files"]
        if set(ranking) != set(candidate_ids(request, "files")):
            raise AssistantError("triage_file_ranking_incomplete")
        if any(probabilities["files"][a] < probabilities["files"][b]
               for a, b in zip(ranking, ranking[1:], strict=False)):
            raise AssistantError("triage_file_ranking_inconsistent")
    if len(result["selected_checks"]) > request["max_selected_checks"]:
        raise AssistantError("triage_budget_exceeded")


def validate_gold(request: dict, gold: dict) -> None:
    """Validate separate adjudication; its catalog may contain omitted candidates.

    A confirmed case with required checks outside the supplied candidates is
    eligible and must fail routing. An infeasible predeclared budget is a
    confirmed/budget_infeasible policy failure, not an excluded case.
    """
    expected_hash = request_hash(request)
    _validate(gold, "gold")
    if gold["case_id"] != request["case_id"] or gold["request_hash"] != expected_hash:
        raise AssistantError("triage_request_mismatch")
    all_ids = [item for group in GROUPS for item in gold["catalog"][group]]
    if len(all_ids) != len(set(all_ids)):
        raise AssistantError("triage_catalog_duplicate")
    for group in GROUPS:
        if not set(candidate_ids(request, group)) <= set(gold["catalog"][group]):
            raise AssistantError("triage_candidate_outside_catalog")
    if request["max_selected_checks"] > len(gold["catalog"]["checks"]):
        raise AssistantError("triage_budget_invalid")
    for group in ("patterns", "checks"):
        labels = gold[group]
        flattened = [item for kind in ("required", "optional", "forbidden") for item in labels[kind]]
        if len(flattened) != len(set(flattened)) or set(flattened) != set(gold["catalog"][group]):
            raise AssistantError("triage_gold_partition_invalid")
    accepted = gold["acceptable_first_files"]
    if len(accepted) != len(set(accepted)) or not set(accepted) <= set(gold["catalog"]["files"]):
        raise AssistantError("triage_gold_files_invalid")
    status, reason = gold["adjudication_status"], gold["applicability_reason"]
    allowed = {
        "confirmed": {"applicable", "budget_infeasible"},
        "unconfirmed": {"pending_adjudication"},
        "not_applicable": {"outside_scope"},
    }
    if reason not in allowed[status]:
        raise AssistantError("triage_gold_status_invalid")
    infeasible = len(gold["checks"]["required"]) > request["max_selected_checks"]
    if status == "confirmed" and infeasible and reason != "budget_infeasible":
        raise AssistantError("triage_budget_infeasible")
    if reason == "budget_infeasible" and not infeasible:
        raise AssistantError("triage_budget_feasible")
