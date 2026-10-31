"""Exercise installed public triage commands with fictional data only."""
import json

from finassist.security import canonical
from finassist.triage_contract import request_hash


def exercise_triage_cli(cli, root):
    request = {
        "schema_version": 1, "case_id": "fictional_case", "task_revision": "1" * 40,
        "source_digest": "2" * 64, "context": "Fictional boundary change.", "max_selected_checks": 1,
        "candidates": {group: [{"id": identifier, "description": "Fictional candidate"}]
                       for group, identifier in (("patterns", "pattern_a"), ("files", "file_a"), ("checks", "check_a"))},
    }
    model = {"model_id": "fictional_scorer", "model_digest": "3" * 64,
             "scorer_revision": "4" * 40, "calibration_digest": "5" * 64}
    result = {
        "schema_version": 1, "case_id": request["case_id"], "request_hash": request_hash(request),
        "model_manifest": model, "action": "recommend", "reason": "scored",
        "probabilities": {group: [{"id": row["id"], "probability": 1.0} for row in candidates]
                          for group, candidates in request["candidates"].items()},
        "selected_patterns": ["pattern_a"], "selected_checks": ["check_a"], "ranked_files": ["file_a"],
    }
    gold = {
        "schema_version": 1, "case_id": request["case_id"], "request_hash": request_hash(request),
        "source_kind": "synthetic", "family_id": "fictional_family",
        "adjudication_status": "confirmed", "applicability_reason": "applicable", "is_control": False,
        "defect_status": "confirmed_defect",
        "catalog": {group: [row["id"] for row in candidates] for group, candidates in request["candidates"].items()},
        "patterns": {"required": ["pattern_a"], "optional": [], "forbidden": []},
        "checks": {"required": ["check_a"], "optional": [], "forbidden": []},
        "acceptable_first_files": ["file_a"],
    }
    documents = {"request": request, "result": result, "model": model,
                 "requests": {"schema_version": 1, "requests": [request]},
                 "gold": {"schema_version": 1, "gold": [gold]},
                 "predictions": {"schema_version": 1, "predictions": [result]}}
    for name, document in documents.items():
        (root / f"triage-{name}.json").write_bytes(canonical(document))
    validate = ["triage", "validate", "--request", root / "triage-request.json",
                "--result", root / "triage-result.json", "--model-manifest", root / "triage-model.json",
                "--output", root / "triage-validation.json"]
    assert cli(*validate)[0]["default_matrix_required"]
    assert cli(*validate, expected_exit=2)["code"] == "output_exists"
    summary = cli("triage", "evaluate", "--requests", root / "triage-requests.json",
                  "--gold", root / "triage-gold.json", "--predictions", root / "triage-predictions.json",
                  "--model-manifest", root / "triage-model.json", "--output", root / "triage-metrics.json")[0]
    metrics = json.loads((root / "triage-metrics.json").read_text(encoding="utf-8"))
    assert summary["advisory_only"] and not summary["model_called"]
    assert metrics["synthetic"]["model_only_routing"]["rate"] == 1
    assert metrics["real"]["model_only_routing"]["rate"] is None
    assert not metrics["deployment_certified"] and metrics["default_matrix_required"]
