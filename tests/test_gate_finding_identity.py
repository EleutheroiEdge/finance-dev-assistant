"""Exact-request identities in private gate and history reports."""
from copy import deepcopy

import pytest

from finassist.errors import AssistantError
from finassist.finding_identity import finding_identifier
from finassist.model_gate import validate_model_report
from finassist.security import canonical, digest
from test_model_gate import run

pytest_plugins = ("test_model_gate", "test_model_policy")


def signed(report):
    report["report_hash"] = digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
    return report


def test_gate_ids_are_stable_across_identical_requests(gate_case):
    first, _ = run(gate_case)
    second, _ = run(gate_case)
    assert first["schema_version"] == 2
    assert first["request_sha256"] == second["request_sha256"]
    assert first["findings"] == second["findings"]
    assert first["findings"][0]["id"] == finding_identifier(first["request_sha256"], 0, first["findings"][0])


@pytest.mark.parametrize("change", ["id", "request", "claim", "missing-id"])
def test_tampered_identity_refused_even_with_rehashed_report(gate_case, change):
    report, _ = run(gate_case)
    if change == "id":
        report["findings"][0]["id"] = "f-" + "0" * 64
    elif change == "request":
        report["request_sha256"] = "0" * 64
    elif change == "claim":
        report["findings"][0]["claim"] = "Different claim"
    else:
        del report["findings"][0]["id"]
    with pytest.raises(AssistantError, match="^gate_report_invalid$"):
        validate_model_report(signed(report))


def test_legacy_report_remains_readable_but_cannot_claim_v2_ids(gate_case):
    report, _ = run(gate_case)
    legacy = deepcopy(report)
    legacy["schema_version"] = 1
    for finding in legacy["findings"]:
        del finding["id"]
    validate_model_report(signed(legacy))
    legacy["findings"][0]["id"] = report["findings"][0]["id"]
    with pytest.raises(AssistantError, match="^gate_report_invalid$"):
        validate_model_report(signed(legacy))


def test_history_uses_the_same_gate_finding_identity(gate_case):
    from pathlib import Path
    import json
    from test_history_evaluation import execute, model_suite
    result, _ = execute(gate_case, model_suite(gate_case), trials=1)
    trial = result["cases"][0]["runs"][0]
    report = json.loads((Path(result["journal"]).parent / trial["report_file"]).read_bytes())
    assert trial["findings"][0]["id"] == report["findings"][0]["id"]
