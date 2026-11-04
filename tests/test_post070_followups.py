"""Ordered post0.7 regressions with synthetic data and fake model transport."""
from copy import deepcopy
import hashlib
from importlib.resources import files
import json
from pathlib import Path

import comrak
import jsonschema
import pytest

from finassist.cli import main
from finassist.errors import AssistantError
from finassist.forbidden_tokens import TokenSnapshot, normalize_numeric_token, screen_text
from finassist.integrations import export_kit
from finassist.report_trace import _text, score_gate_report
from finassist.security import canonical, check_text, digest
from test_forbidden_token_gate import candidate
from test_model_gate import change_policy, run
from test_providers_review import envelope, response

pytest_plugins = ("test_model_gate", "test_model_policy")


@pytest.mark.parametrize("raw,expected", [
    ("1_234_567.89", "1234567.89"), ("$6_729_102.500", "6729102.5"),
    ("(6_729_102.50)", "-6729102.5"), ("６_７２９_１０２.５０", "6729102.5"),
    ("6_729_102.5e-2", "67291.025"),
])
def test_underscore_thousands_groups_normalize_without_rounding(raw, expected):
    assert normalize_numeric_token(raw) == expected


@pytest.mark.parametrize("raw", ["1_23", "1234_567", "1__234", "1_234,567", "1 234_567", "1.23_456", "_123", "123_"])
def test_malformed_or_mixed_underscore_groups_remain_invalid(raw):
    with pytest.raises(AssistantError, match="^forbidden_token_invalid$"):
        normalize_numeric_token(raw)


@pytest.mark.parametrize("text", ["value = 6_729_102.50", "# $6_729_102.500", "1 6_729_102.50 2"])
def test_underscore_content_refuses_before_transport_or_reservation(gate_case, text):
    change_policy(gate_case, forbidden_token_hashes=[hashlib.sha256(b"6729102.5").hexdigest()])
    candidate(gate_case, text)
    report, calls = run(gate_case)
    assert report["reasons"] == ["forbidden_token_present"] and not calls
    assert not (gate_case["state"] / "audit.sqlite").exists()
    assert "6729102" not in canonical(report).decode()



@pytest.mark.parametrize("source", ["value = 6729102.50", "value = 6_729_102.50"])
def test_underscore_external_list_matches_grouped_and_compact_source(gate_case, tmp_path, source):
    tokens = tmp_path / "numbers.txt"
    tokens.write_text("6_729_102.500\n", encoding="utf-8")
    change_policy(gate_case, forbidden_token_file=str(tokens))
    candidate(gate_case, source)
    report, calls = run(gate_case)
    assert report["reasons"] == ["forbidden_token_present"] and not calls
    assert not (gate_case["state"] / "audit.sqlite").exists()
    assert "6729102" not in canonical(report).decode()


def test_underscore_grouping_does_not_change_a_distinct_value():
    snapshot = TokenSnapshot(frozenset([hashlib.sha256(b"6729102.5").hexdigest()]))
    screen_text("value = 6_729_102.51", snapshot)


@pytest.mark.parametrize("secret", ["AbcDefGhi1234567", "A12345678901234", "ABC_DEF_1234567"])
def test_uppercase_leading_credential_literals_with_digits_are_screened(secret):
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text("access_" + "key = " + secret)


@pytest.mark.parametrize("expression", ["CryptographicKeyMaterial", "KEY_MATERIAL_REFERENCE", "config.key_material2", "resolve_key2()"])
def test_identifier_and_expression_credential_references_remain_supported(expression):
    check_text("access_" + "key = " + expression)


def test_mixed_case_credential_source_never_dispatches_or_reserves(gate_case):
    candidate(gate_case, "access_" + "key = " + "AbcDefGhi1234567")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
    assert not (gate_case["state"] / "audit.sqlite").exists()


@pytest.mark.parametrize("reference", ["GH-7", "gh-12", "Gh-123", "gH-456"])
def test_rendered_gh_number_references_cannot_form_autolink_tokens(reference):
    escaped = _text("See " + reference)
    assert "&#8203;" in escaped
    options = comrak.RenderOptions()
    options.unsafe_ = True
    rendered = comrak.render_markdown(escaped, render_options=options)
    assert reference not in rendered and "\u200b" in rendered


def test_evaluation_labels_and_adjudications_fail_with_mode_conflict(tmp_path, capsys):
    output = tmp_path / "output.json"
    result = main(["score", "--evaluation", "missing.json", "--labels", "missing-labels.json",
                   "--adjudications", "missing-judgments.json", "--output", str(output)])
    assert result == 2
    assert json.loads(capsys.readouterr().err)["code"] == "score_input_mode_conflict"
    assert not output.exists()


def test_v1_report_schema_is_public_and_exported_with_legacy_validation(gate_case, tmp_path):
    report = run(gate_case)[0]
    legacy = deepcopy(report)
    legacy["schema_version"] = 1
    for finding in legacy["findings"]:
        finding.pop("id")
    legacy["report_hash"] = digest(canonical({k: v for k, v in legacy.items() if k != "report_hash"}))
    raw = files("finassist").joinpath("resources/model-gate-report-v1.schema.json").read_bytes()
    repository = Path(__file__).resolve().parents[1]
    assert (repository / "schemas/model-gate-report-v1.schema.json").read_bytes() == raw
    exported = tmp_path / "kit"
    export_kit(exported)
    assert (exported / "schemas/model-gate-report-v1.schema.json").read_bytes() == raw
    jsonschema.Draft202012Validator(json.loads(raw)).validate(legacy)


def test_gate_retains_distinct_ids_for_duplicate_provider_findings(gate_case):
    def duplicates(packet):
        value = response(packet)
        value["findings"].append(deepcopy(value["findings"][0]))
        return envelope(json.dumps(value))
    report, calls = run(gate_case, duplicates)
    assert report["verdict"] == "PASS" and len(calls) == 1
    assert len(report["findings"]) == 2
    first, second = report["findings"]
    assert first["id"] != second["id"]
    assert {k: v for k, v in first.items() if k != "id"} == {k: v for k, v in second.items() if k != "id"}
    score = score_gate_report(report, {first["id"]: {"outcome": "Refuted", "note": "One duplicate checked"}})
    assert score["counts"]["Refuted"] == 1 and score["counts"]["Unresolved"] == 1
    assert not score["complete"]
