"""Explicit offline triage file IO; never loads project configuration or models."""

from pathlib import Path

from .errors import AssistantError
from .security import canonical, digest, regular_path, write_private
from .triage_contract import MAX_DOCUMENT_BYTES, parse_triage_json, request_hash, validate_result
from .triage_metrics import evaluate_triage


def _read_document(path: Path) -> tuple[dict, str]:
    path = regular_path(path)
    if not path.is_file():
        raise AssistantError("triage_input_file_required")
    with path.open("rb") as stream:
        # Bound the actual read, not just a potentially stale preflight stat.
        raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    return parse_triage_json(raw), digest(raw)


def _collection(path: Path, field: str) -> tuple[list[dict], str]:
    document, file_hash = _read_document(path)
    if (set(document) != {"schema_version", field}
            or type(document["schema_version"]) is not int or document["schema_version"] != 1
            or not isinstance(document[field], list)):
        raise AssistantError("triage_collection_invalid")
    return document[field], file_hash


def execute_triage(args) -> tuple[dict, int]:
    output = regular_path(args.output)
    if output.exists():
        raise AssistantError("output_exists")
    manifest, manifest_file_hash = _read_document(args.model_manifest)
    if args.triage_action == "validate":
        request, request_file_hash = _read_document(args.request)
        prediction, result_file_hash = _read_document(args.result)
        validate_result(request, prediction, expected_model_manifest=manifest)
        report = {
            "schema_version": 1, "kind": "advisory-triage-validation", "valid": True,
            "request_hash": request_hash(request), "action": prediction["action"],
            "result_hash": digest(canonical(prediction)), "model_manifest": dict(manifest),
            "model_manifest_hash": digest(canonical(manifest)),
            "input_file_hashes": {"request": request_file_hash, "result": result_file_hash,
                                  "model_manifest": manifest_file_hash},
            "advisory_only": True, "default_matrix_required": True,
            "model_called": False, "execution_authorized": False,
        }
        exit_code = 0 if prediction["action"] == "recommend" else 1
    else:
        requests, requests_file_hash = _collection(args.requests, "requests")
        gold, gold_file_hash = _collection(args.gold, "gold")
        predictions, predictions_file_hash = _collection(args.predictions, "predictions")
        report = evaluate_triage(requests, gold, predictions, expected_model_manifest=manifest)
        report["input_file_hashes"] = {
            "requests": requests_file_hash, "gold": gold_file_hash,
            "predictions": predictions_file_hash, "model_manifest": manifest_file_hash,
        }
        report.update(default_matrix_required=True, model_called=False)
        # Success means the calculation completed, not that a model met a gate.
        exit_code = 0
    write_private(output, canonical(report) + b"\n")
    return report, exit_code
