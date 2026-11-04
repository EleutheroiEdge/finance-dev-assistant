import json
import os

import pytest

from finassist import cli
from finassist import triage_cli
from finassist.security import canonical, digest
from test_triage_contract import sample_case


def inputs(tmp_path):
    request, result, gold, manifest = sample_case(source_kind="synthetic")
    documents = {
        "request": request, "result": result, "model": manifest,
        "requests": {"schema_version": 1, "requests": [request]},
        "gold": {"schema_version": 1, "gold": [gold]},
        "predictions": {"schema_version": 1, "predictions": [result]},
    }
    for name, value in documents.items():
        (tmp_path / f"{name}.json").write_bytes(canonical(value))
    return documents


def arguments(tmp_path, action="validate", output="report.json"):
    argv = ["triage", action, "--model-manifest", str(tmp_path / "model.json"),
            "--output", str(tmp_path / output)]
    fields = ("request", "result") if action == "validate" else ("requests", "gold", "predictions")
    for name in fields:
        argv.extend(["--" + name, str(tmp_path / f"{name}.json")])
    return argv


def test_validation_preserves_full_matrix_without_config_model_or_implicit_state(tmp_path, monkeypatch, capsys):
    documents = inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "finassist.json").write_text("not a configuration; must not be read", encoding="utf-8")

    def forbidden(*args, **kwargs):
        raise AssertionError("configuration/model/check execution was called")

    monkeypatch.setattr(cli, "load_config", forbidden)
    monkeypatch.setattr(cli, "review_packet", forbidden)
    monkeypatch.setattr(cli, "run_recipe", forbidden)
    assert cli.main(arguments(tmp_path)) == 0
    report = json.loads((tmp_path / "report.json").read_text())
    stdout = json.loads(capsys.readouterr().out)
    assert stdout["report_hash"] == digest(canonical(report))
    assert report["default_matrix_required"] and not report["execution_authorized"]
    assert not report["model_called"] and not (tmp_path / ".finassist").exists()
    assert documents["request"]["context"] not in json.dumps(stdout)
    if os.name != "nt":
        assert (tmp_path / "report.json").stat().st_mode & 0o777 == 0o600


def test_existing_output_is_never_overwritten(tmp_path, capsys):
    inputs(tmp_path)
    output = tmp_path / "report.json"
    output.write_bytes(b"keep exact previous report")
    assert cli.main(arguments(tmp_path)) == 2
    assert output.read_bytes() == b"keep exact previous report"
    assert json.loads(capsys.readouterr().err)["code"] == "output_exists"


def test_evaluation_reports_missing_prediction_as_miss_without_fallback(tmp_path, capsys):
    inputs(tmp_path)
    (tmp_path / "predictions.json").write_text('{"schema_version":1,"predictions":[]}', encoding="utf-8")
    assert cli.main(arguments(tmp_path, "evaluate")) == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["synthetic"]["model_only_routing"] == {"successes": 0, "total": 1, "rate": 0}
    assert report["default_matrix_required"] and not report["fallback_evaluated"]
    assert json.loads(capsys.readouterr().out)["advisory_only"]


@pytest.mark.parametrize("mutation", ["duplicate_key", "nonfinite", "wrong_hash", "extra_field", "wrong_model"])
def test_cli_refuses_bad_result_without_payload_echo_or_report(tmp_path, capsys, mutation):
    documents = inputs(tmp_path)
    if mutation == "duplicate_key":
        data = '{"private_payload_marker":1,"private_payload_marker":2}'
    elif mutation == "nonfinite":
        data = '{"private_payload_marker":NaN}'
    else:
        result = documents["result"]
        if mutation == "wrong_hash":
            result["request_hash"] = "0" * 64
        elif mutation == "wrong_model":
            result["model_manifest"]["model_digest"] = "0" * 64
        else:
            result["private_payload_marker"] = "untrusted content"
        data = json.dumps(result)
    (tmp_path / "result.json").write_text(data, encoding="utf-8")
    assert cli.main(arguments(tmp_path)) == 2
    captured = capsys.readouterr()
    assert not captured.out and "private_payload_marker" not in captured.err
    assert not (tmp_path / "report.json").exists()


def test_valid_abstention_exits_one_and_preserves_default_matrix(tmp_path, capsys):
    documents = inputs(tmp_path)
    result = documents["result"]
    result.update(action="abstain", reason="uncertain", selected_checks=[], selected_patterns=[], ranked_files=[])
    (tmp_path / "result.json").write_bytes(canonical(result))
    assert cli.main(arguments(tmp_path)) == 1
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["valid"] and report["action"] == "abstain" and report["default_matrix_required"]
    assert not capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--config", "--audit-dir"])
def test_explicit_configuration_or_audit_is_refused(tmp_path, capsys, flag):
    inputs(tmp_path)
    assert cli.main([flag, str(tmp_path / "unread.json"), *arguments(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "triage_configuration_or_audit_not_supported"


def test_collection_unknown_fields_and_wrong_versions_refused(tmp_path, capsys):
    documents = inputs(tmp_path)
    documents["requests"]["schema_version"] = True
    (tmp_path / "requests.json").write_bytes(canonical(documents["requests"]))
    assert cli.main(arguments(tmp_path, "evaluate")) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "triage_collection_invalid"


@pytest.mark.skipif(os.name == "nt", reason="native symlink creation requires a Windows privilege")
def test_linked_input_or_output_refused_without_touching_target(tmp_path, capsys):
    inputs(tmp_path)
    original = tmp_path / "original.json"
    original.write_bytes((tmp_path / "request.json").read_bytes())
    (tmp_path / "request.json").unlink()
    (tmp_path / "request.json").symlink_to(original)
    assert cli.main(arguments(tmp_path)) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "linked_path"
    (tmp_path / "request.json").unlink()
    (tmp_path / "request.json").write_bytes(original.read_bytes())
    (tmp_path / "report.json").symlink_to(original)
    before = original.read_bytes()
    assert cli.main(arguments(tmp_path)) == 2
    assert original.read_bytes() == before
    assert json.loads(capsys.readouterr().err)["code"] == "linked_path"


def test_oversized_actual_file_is_rejected_before_contract_use(tmp_path, capsys):
    inputs(tmp_path)
    (tmp_path / "request.json").write_bytes(b" " * 2_000_001)
    assert cli.main(arguments(tmp_path)) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "triage_document_too_large"


def test_validation_report_binds_result_and_expected_model_and_exact_file_bytes(tmp_path):
    documents = inputs(tmp_path)
    path = tmp_path / "result.json"
    path.write_text(json.dumps(documents["result"], indent=2) + "\n", encoding="utf-8")
    assert cli.main(arguments(tmp_path)) == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["result_hash"] == digest(canonical(documents["result"]))
    assert report["model_manifest"] == documents["model"]
    assert report["model_manifest_hash"] == digest(canonical(documents["model"]))
    assert report["input_file_hashes"] == {
        key: digest((tmp_path / f"{name}.json").read_bytes())
        for key, name in (("request", "request"), ("result", "result"), ("model_manifest", "model"))
    }
    assert report["input_file_hashes"]["result"] != report["result_hash"]
    documents["result"]["probabilities"]["checks"][0]["probability"] = 0.85
    path.write_bytes(canonical(documents["result"]))
    assert cli.main(arguments(tmp_path, output="second.json")) == 0
    changed = json.loads((tmp_path / "second.json").read_text())
    assert changed["request_hash"] == report["request_hash"]
    assert changed["result_hash"] != report["result_hash"]


def test_evaluation_file_hashes_distinguish_serialization_from_semantic_hashes(tmp_path):
    documents = inputs(tmp_path)
    assert cli.main(arguments(tmp_path, "evaluate")) == 0
    first = json.loads((tmp_path / "report.json").read_text())
    assert first["input_file_hashes"] == {
        key: digest((tmp_path / f"{name}.json").read_bytes())
        for key, name in (("requests", "requests"), ("gold", "gold"),
                          ("predictions", "predictions"), ("model_manifest", "model"))
    }
    for name in ("requests", "gold", "predictions", "model"):
        value = dict(reversed(list(documents[name].items())))
        (tmp_path / f"{name}.json").write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    assert cli.main(arguments(tmp_path, "evaluate", output="second.json")) == 0
    second = json.loads((tmp_path / "second.json").read_text())
    assert first["input_hashes"] == second["input_hashes"]
    assert all(first["input_file_hashes"][key] != second["input_file_hashes"][key]
               for key in first["input_file_hashes"])
    assert not second["execution_authorized"]


def test_file_digest_uses_the_same_bounded_read_as_parsing(tmp_path, monkeypatch):
    documents = inputs(tmp_path)
    path = tmp_path / "request.json"
    original = path.read_bytes()
    parse = triage_cli.parse_triage_json

    def replace_after_read(raw):
        value = parse(raw)
        if "context" in value:
            path.write_bytes(b"changed after the bounded read")
        return value

    monkeypatch.setattr(triage_cli, "parse_triage_json", replace_after_read)
    assert cli.main(arguments(tmp_path)) == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["input_file_hashes"]["request"] == digest(original)
    assert report["request_hash"] == digest(canonical(documents["request"]))
    assert report["input_file_hashes"]["request"] != digest(path.read_bytes())
