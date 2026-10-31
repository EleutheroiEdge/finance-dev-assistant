"""Explicit offline triage file IO; never loads project configuration or models."""

from pathlib import Path

from .errors import AssistantError
from .security import canonical, regular_path, write_private
from .triage_contract import MAX_DOCUMENT_BYTES, parse_triage_json, request_hash, validate_result
from .triage_metrics import evaluate_triage


def _read_document(path: Path) -> dict:
    path = regular_path(path)
    if not path.is_file():
        raise AssistantError("triage_input_file_required")
    with path.open("rb") as stream:
        # Bound the actual read, not just a potentially stale preflight stat.
        return parse_triage_json(stream.read(MAX_DOCUMENT_BYTES + 1))


def _collection(path: Path, field: str) -> list[dict]:
    document = _read_document(path)
    if (set(document) != {"schema_version", field}
            or type(document["schema_version"]) is not int or document["schema_version"] != 1
            or not isinstance(document[field], list)):
        raise AssistantError("triage_collection_invalid")
    return document[field]


def execute_triage(args) -> tuple[dict, int]:
    output = regular_path(args.output)
    if output.exists():
        raise AssistantError("output_exists")
    manifest = _read_document(args.model_manifest)
    if args.triage_action == "validate":
        request, prediction = _read_document(args.request), _read_document(args.result)
        validate_result(request, prediction, expected_model_manifest=manifest)
        report = {
            "schema_version": 1, "kind": "advisory-triage-validation", "valid": True,
            "request_hash": request_hash(request), "action": prediction["action"],
            "advisory_only": True, "default_matrix_required": True,
            "model_called": False, "execution_authorized": False,
        }
        exit_code = 0 if prediction["action"] == "recommend" else 1
    else:
        report = evaluate_triage(
            _collection(args.requests, "requests"), _collection(args.gold, "gold"),
            _collection(args.predictions, "predictions"), expected_model_manifest=manifest,
        )
        report.update(default_matrix_required=True, model_called=False)
        # Success means the calculation completed, not that a model met a gate.
        exit_code = 0
    write_private(output, canonical(report) + b"\n")
    return report, exit_code
