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
    ("1_234_567.89", "1234567.89"), ("6729_102.50", "6729102.5"),
    ("67_29_102.50", "6729102.5"), ("6_7_2_9_1_0_2.50", "6729102.5"),
    ("6_729_102.5_0", "6729102.5"), ("$6_729_102.500", "6729102.5"),
    ("(6_729_102.50)", "-6729102.5"), ("６_７２９_１０２.５０", "6729102.5"),
    ("6_729_102.5e-2", "67291.025"), ("6.7291025e0_6", "6729102.5"),
])
def test_underscore_digit_separators_normalize_without_rounding(raw, expected):
    assert normalize_numeric_token(raw) == expected


@pytest.mark.parametrize("raw", ["1__234", "_123", "123_", "1_.23", "1._23", "1_e2", "1e_2"])
def test_underscores_outside_digit_pairs_remain_invalid(raw):
    with pytest.raises(AssistantError, match="^forbidden_token_invalid$"):
        normalize_numeric_token(raw)


@pytest.mark.parametrize("text", ["value = 6_729_102.50", "# $6_729_102.500", "1 6_729_102.50 2", "value = 6729_102.50",
                                  "value = 67_29_102.50", "value = 6_7_2_9_1_0_2.50", "value = 6.7291025e0_6"])
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


@pytest.mark.parametrize("secret", ["AbcDefGhi1234567", "A12345678901234", "ABC_DEF_1234567",
                                    "AbcDefGhi/1234567", "AbcDefGhi-1234567", "AbcDefGhi+1234567", "Zq7Lm2Xp9Rt4Vw8", "Zq7/Lm2+Xp9Rt4Vw8=="])
def test_uppercase_leading_credential_literals_with_digits_are_screened(secret):
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text("access_" + "key = " + secret)


@pytest.mark.parametrize("expression", ["CryptographicKeyMaterial", "KEY_MATERIAL_REFERENCE", "config.key_material2", "resolve_key2()"])
def test_identifier_and_expression_credential_references_remain_supported(expression):
    check_text("access_" + "key = " + expression)


# In parseable Python an unquoted value is a name or an expression, not a literal
# (#61); the text rule still refuses it in other files, and Python literals refuse.
@pytest.mark.parametrize("name,source", [
    ("src/case.yaml", "access_" + "key: AbcDefGhi1234567"),
    ("src/case.yaml", "access_" + "key: AbcDefGhi/1234567"),
    ("src/cash.py", "access_" + 'key = "AbcDefGhi1234567"'),
    ("src/cash.py", "access_" + 'key = "AbcDefGhi/1234567"'),
])
def test_mixed_case_credential_source_never_dispatches_or_reserves(gate_case, name, source):
    candidate(gate_case, source, name)
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


def test_evaluation_labels_and_adjudications_fail_with_mode_conflict(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)  # Its state stays out of the checkout.
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


@pytest.mark.parametrize("line", [
    "signing_" + "key: Ed25519PrivateKey", "private_" + "key: X25519PrivateKey = None",
    "encryption_" + "key: Sha256Digest", "signing_" + "key: CryptographicKeyMaterial",
    "signing_" + "key: Optional[SigningKey] = None", "signing_key = load_signing_key(path)",
    "signing_key = settings.SIGNING_KEY", 'primary_key = "transaction_id"',
    "π = 1; signing_" + "key: Ed25519PrivateKey = load_signing_key(path)",
    "def sign(signing_" + "key: Ed25519PrivateKey): pass",
    "text = 'synthetic\u2028value'; signing_" + "key: Ed25519PrivateKey",
    "# Synthetic\r\nsigning_" + "key: Ed25519PrivateKey",
    "# Synthetic\rsigning_" + "key: Ed25519PrivateKey",
])
def test_python_types_preserve_wire_bytes_and_pass_gate(gate_case, line):
    source = "# Synthetic annotation context.\n" + line + "\n"
    candidate(gate_case, source)
    received = []
    def clear(packet):
        received.append(packet["files"][0]["after"])
        return envelope(json.dumps({"head": packet["head"], "summary": "Synthetic coverage",
                                   "reviewed_paths": [f["path"] for f in packet["files"]], "findings": []}))
    report, calls = run(gate_case, clear)
    assert received == [source]
    assert report["verdict"] == "PASS" and len(calls) == 1


@pytest.mark.parametrize("name,source", [
    ("src/case.yaml", "aws_secret_access_" + "key: Zq7Lm2Xp9Rt4Vw8Yb3"),
    ("src/case.yaml", "signing_" + "key: Ed25519PrivateKey"),
    ("src/case.py", '# signing_' + 'key: Ed25519PrivateKey'),
    ("src/case.py", 'text = "signing_' + 'key: Ed25519PrivateKey"'),
    ("src/case.py", 'signing_' + 'key: (\n# private_' + 'key = "Zq7Lm2Xp9Rt4Vw8"\nEd25519PrivateKey)'),
    ("src/case.py", 'signing_' + 'key: Ed25519Private' + 'Key = "Zq7Lm2Xp9Rt4Vw8"'),
    ("src/case.yaml", 'signing_' + 'key: Zq7Lm2Xp9Rt4Vw8'),
    ("src/case.py", 'signing_' + 'key: Ed25519Private' + 'Key = os.getenv("SIGNING", "Zq7Lm2Xp9Rt4Vw8")'),
    ("src/case.py", 'def sign(signing_' + 'key: Ed25519Private' + 'Key = "Zq7Lm2Xp9Rt4Vw8"): pass'),
])
def test_context_never_exempts_yaml_comments_strings_or_assigned_credentials(gate_case, name, source):
    candidate(gate_case, source, name)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
    assert not (gate_case["state"] / "audit.sqlite").exists()


def test_python_annotation_context_never_exempts_custom_patterns():
    with pytest.raises(AssistantError, match="^project_content_blocked$"):
        check_text("signing_" + "key: Ed25519PrivateKey", source_path="source.py", extra_patterns=("Ed25519",))


def test_python_parser_never_echoes_source_in_warnings():
    import warnings

    source = 'text = "\\q"; signing_' + 'key = "Zq7Lm2Xp9Rt4Vw8"'
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_text(source, source_path="source.py")
    assert not emitted
