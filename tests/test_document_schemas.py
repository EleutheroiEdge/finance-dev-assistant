"""Exported schemas and raw suite identity stay aligned with runtime validation."""
from copy import deepcopy
from dataclasses import replace
from importlib.resources import files
import json
from pathlib import Path

import httpx
import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from finassist import ci_policy, model_policy
from finassist.cli import main
from finassist.config import Config
from finassist.document_schemas import SCHEMA_FILES, SCHEMA_IDS, document_schema, document_schema_text
from finassist.errors import AssistantError
from finassist.evaluation import evaluate, validate_suite
from finassist.history_suite import history_approval_hash, plan_history, validate_history_suite
from finassist.model_gate import refused_model_report, validate_model_report
from finassist.review import review_packet, review_schema, validate_review
from finassist.scope import build_packet, verify_packet
from finassist.security import canonical, digest
from test_history_suite import history_suite
from test_providers_review import envelope, response

ROOT = Path(__file__).parents[1]


def exported_validator(kind):
    registry = Registry().with_resources(
        (SCHEMA_IDS[name], Resource.from_contents(document_schema(name)))
        for name in ("config", "workflow-template")
    )
    return Draft202012Validator(document_schema(kind), registry=registry)


def sample(kind):
    name = "review-cases.json" if kind == "evaluation-suite" else "history-cases.json"
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("kind,name", SCHEMA_FILES.items())
def test_published_and_packaged_schemas_equal_runtime_export(kind, name):
    schema = document_schema(kind)
    Draft202012Validator.check_schema(schema)
    assert schema["$id"] == SCHEMA_IDS[kind]
    text = document_schema_text(kind)
    assert (ROOT / "schemas" / name).read_text(encoding="utf-8") == text
    assert files("finassist").joinpath("resources/" + name).read_text(encoding="utf-8") == text


@pytest.mark.parametrize("kind", SCHEMA_FILES)
def test_schema_cli_reads_no_project_or_state(kind, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    def unexpected(*args, **kwargs):
        pytest.fail("schema export must not load project configuration or create an audit")
    monkeypatch.setattr("finassist.cli.load_config", unexpected)
    monkeypatch.setattr("finassist.cli.command_audit", unexpected)
    assert main(["--config", "absent.json", "--audit-dir", "absent-state", "config", "schema", "--kind", kind]) == 0
    output = capsys.readouterr()
    assert output.out == (canonical(document_schema(kind)) + b"\n").decode() and not output.err
    assert list(tmp_path.iterdir()) == []


def test_default_schema_and_unknown_kind(capsys):
    assert main(["config", "schema"]) == 0
    assert json.loads(capsys.readouterr().out) == document_schema("config")
    with pytest.raises(SystemExit) as exc:
        main(["config", "schema", "--kind", "unrecognized"])
    assert exc.value.code == 2


def test_export_does_not_mutate_policy_or_provider_schema():
    model, ci, review = deepcopy(model_policy._SCHEMA), deepcopy(ci_policy._SCHEMA), review_schema()
    original_request_schema = canonical(review)
    for kind in ("gate-policy", "ci-policy", "review-response"):
        exported = document_schema(kind)
        exported["properties"].clear()
        exported["$id"] = "https://example.invalid/changed"
    assert model_policy._SCHEMA == model and ci_policy._SCHEMA == ci
    assert canonical(review_schema()) == original_request_schema
    assert "schema_version" not in review_schema()["properties"]


@pytest.mark.parametrize("kind,resource", [("gate-policy", "model-gate-policy.json"),
                                         ("ci-policy", "github-ci-policy.json")])
def test_policy_examples_match_runtime_schema(kind, resource):
    document = json.loads(files("finassist").joinpath("resources/" + resource).read_text(encoding="utf-8"))
    exported_validator(kind).validate(document)
    malformed = deepcopy(document)
    malformed["schema_version"] = 99
    with pytest.raises(ValidationError):
        exported_validator(kind).validate(malformed)


@pytest.mark.parametrize("version", [1, 2])
def test_packets_match_schema_and_still_require_integrity(repository, version):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    packet["schema_version"] = version
    if version == 1:
        for item in packet["files"]:
            item.pop("before_mode")
            item.pop("after_mode")
    packet["packet_hash"] = digest(canonical({k: v for k, v in packet.items() if k != "packet_hash"}))
    schema = Draft202012Validator(document_schema("packet"))
    schema.validate(packet)
    verify_packet(packet, Config())
    malformed = deepcopy(packet)
    malformed["files"][0]["after"] = None
    with pytest.raises(ValidationError):
        schema.validate(malformed)
    tampered = deepcopy(packet)
    tampered["files"][0]["after"] += "\n# changed"
    schema.validate(tampered)
    with pytest.raises(AssistantError, match="packet_integrity_failed"):
        verify_packet(tampered, Config())


def test_review_schema_export_preserves_runtime_envelope(repository):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    report = response(packet)
    Draft202012Validator(document_schema("review-response")).validate(report)
    validate_review(report, packet, config=Config())
    report["new_field"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(document_schema("review-response")).validate(report)


@pytest.mark.parametrize("version", [1, 2])
def test_gate_report_exports_current_and_legacy_contracts(version):
    report = refused_model_report("synthetic_refusal")
    report["schema_version"] = version
    report["report_hash"] = digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
    kind = "gate-report-v1" if version == 1 else "gate-report"
    Draft202012Validator(document_schema(kind)).validate(report)
    validate_model_report(report)
    report["report_hash"] = "0" * 64
    with pytest.raises(AssistantError, match="gate_report_invalid"):
        validate_model_report(report)


@pytest.mark.parametrize("kind", ["evaluation-suite", "history-suite"])
@pytest.mark.parametrize("spelling", ["version", "schema_version", "both"])
def test_suite_aliases_validate_without_normalizing_input(kind, spelling):
    document = sample(kind)
    if spelling != "version":
        document["schema_version"] = 1
    if spelling == "schema_version":
        del document["version"]
    original = canonical(document)
    exported_validator(kind).validate(document)
    if kind == "evaluation-suite":
        validate_suite(document)
    else:
        assert validate_history_suite(document) == digest(original)
    assert canonical(document) == original


@pytest.mark.parametrize("kind,code", [("evaluation-suite", "invalid_eval_suite"),
                                      ("history-suite", "history_suite_invalid")])
@pytest.mark.parametrize("header", [{}, {"version": 2}, {"schema_version": 2}, {"version": True},
    {"schema_version": False}, {"version": 1.0}, {"schema_version": 1.0},
    {"version": 1, "schema_version": 2}, {"version": 1, "schema_version": True},
    {"version": 1, "schema_version": 1, "unknown": 1}])
def test_invalid_suite_versions_refused_before_actions(kind, code, header):
    document = {**header, "cases": sample(kind)["cases"]}
    validator = validate_suite if kind == "evaluation-suite" else validate_history_suite
    with pytest.raises(AssistantError, match=code):
        validator(document)


def test_alias_does_not_transfer_evaluation_approval(tmp_path):
    document = sample("evaluation-suite")
    old_hash = digest(canonical(document))
    document["schema_version"] = document.pop("version")
    config = replace(Config(), provider="openai", model="selected")
    with pytest.raises(AssistantError, match="eval_suite_approval_required"):
        evaluate(document, config, tmp_path, approved_suite_hash=old_hash)
    assert not list(tmp_path.iterdir())


def test_history_alias_and_trials_bind_approval_but_preserve_source(repository):
    repo, _, _ = repository
    original = history_suite(repository)
    alias = deepcopy(original)
    alias["schema_version"] = alias.pop("version")
    first = plan_history(original, repo.parent, Config())
    second = plan_history(alias, repo.parent, Config())
    assert first["cases"][0]["packet"] == second["cases"][0]["packet"]
    assert first["suite_hash"] != second["suite_hash"]
    assert history_approval_hash(alias, 1) != history_approval_hash(original, 1)
    assert history_approval_hash(alias, 1) != history_approval_hash(alias, 2)


@pytest.mark.parametrize("kind", ["evaluation-suite", "history-suite"])
def test_schema_does_not_replace_path_screening(kind):
    document = sample(kind)
    if kind == "evaluation-suite":
        document["cases"][0]["path"] = ".env"
    else:
        document["cases"][0]["expected"][0]["paths"] = [".env"]
    exported_validator(kind).validate(document)
    with pytest.raises(AssistantError):
        (validate_suite if kind == "evaluation-suite" else validate_history_suite)(document)


def test_alias_evaluation_runs_offline_with_distinct_raw_identity(tmp_path):
    original = sample("evaluation-suite")
    original["cases"] = original["cases"][:1]
    alias = deepcopy(original)
    alias["schema_version"] = alias.pop("version")
    first = evaluate(original, Config(), tmp_path / "first")
    second = evaluate(alias, Config(), tmp_path / "second")
    assert first["cases"] == second["cases"]
    assert first["suite_hash"] != second["suite_hash"]
    assert not list(tmp_path.iterdir())



@pytest.mark.parametrize("provider", ["offline", "openai"])
def test_saved_review_report_matches_installed_schema(repository, tmp_path, monkeypatch, provider):
    repo, base, head = repository
    config = replace(Config(), provider=provider, model="" if provider == "offline" else "synthetic",
                     api_key_env="REVIEW_TEST_KEY", allow_network=provider != "offline",
                     input_usd_per_million=1, output_usd_per_million=1)
    monkeypatch.setenv("REVIEW_TEST_KEY", "fictional-test-value")
    packet = build_packet(repo, base, head, config)
    calls = []
    def transport(request):
        calls.append(request)
        return httpx.Response(200, json=envelope(json.dumps(response(packet))))
    report = review_packet(packet, config, tmp_path / "audit.sqlite",
                           network_approved=provider != "offline", approved_packet_hash=packet["packet_hash"],
                           transport=httpx.MockTransport(transport))
    Draft202012Validator(document_schema("review-report")).validate(report)
    assert bool(calls) == (provider != "offline")
    assert not report["merge_authority"]
    malformed = deepcopy(report)
    malformed["merge_authority"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(document_schema("review-report")).validate(malformed)
