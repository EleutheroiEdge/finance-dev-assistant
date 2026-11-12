"""Boundary parity and enforcement checks for the four shared document contracts."""
from copy import deepcopy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path

import httpx
from jsonschema import Draft202012Validator, ValidationError
import pytest

from finassist import document_contracts as contracts
from finassist.cli import main
from finassist.config import Config
from finassist.document_schemas import SCHEMA_FILES, SCHEMA_IDS, document_schema
from finassist.errors import AssistantError
from finassist.evaluation import validate_suite
from finassist.history_suite import validate_history_suite
from finassist.related import verify_related
from finassist.review import review_packet
from finassist.scope import WITHHELD_REASON, build_packet, verify_packet
from finassist.security import canonical, digest
from test_providers_review import envelope, response
from test_document_schemas import exported_validator

ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def fresh_contract_cache():
    contracts._validator.cache_clear()
    yield
    contracts._validator.cache_clear()


def evaluation():
    return {"version": 1, "cases": [{"id": "case", "path": "src/cash.py",
             "before": "a", "after": "b", "expected_defect": False}]}


def history():
    return {"version": 1, "cases": [{"id": "case", "repo_path": ".", "base_sha": "a" * 40,
             "head_sha": "b" * 40, "profile": "general", "negative_control": False,
             "expected": [{"label": "cash", "severity": "high", "paths": ["src/cash.py"]}]}]}


def rehash(packet):
    packet["packet_hash"] = digest(canonical({k: v for k, v in packet.items() if k != "packet_hash"}))
    return packet


def parity(kind, valid, invalid, runtime):
    schema = Draft202012Validator(document_schema(kind))
    schema.validate(valid)
    runtime(valid)
    with pytest.raises(ValidationError):
        schema.validate(invalid)
    with pytest.raises(AssistantError):
        runtime(invalid)


@pytest.mark.parametrize("kind,factory,runtime", [
    ("evaluation-suite", evaluation, validate_suite), ("history-suite", history, validate_history_suite)])
def test_case_count_boundary(kind, factory, runtime):
    valid = factory()
    item = valid["cases"][0]
    valid["cases"] = [{**deepcopy(item), "id": f"case-{i}"} for i in range(50)]
    invalid = deepcopy(valid)
    invalid["cases"].append({**deepcopy(item), "id": "case-50"})
    parity(kind, valid, invalid, runtime)
    invalid["cases"] = []
    parity(kind, factory(), invalid, runtime)


@pytest.mark.parametrize("field", ["before", "after"])
def test_evaluation_source_character_and_byte_boundaries(field):
    valid = evaluation()
    valid["cases"][0][field] = "x" * 48_000
    invalid = deepcopy(valid)
    invalid["cases"][0][field] += "x"
    parity("evaluation-suite", valid, invalid, validate_suite)
    invalid["cases"][0][field] = ""
    parity("evaluation-suite", valid, invalid, validate_suite)
    valid["cases"][0][field] = "é" * 24_000
    validate_suite(valid)
    valid["cases"][0][field] += "é"
    Draft202012Validator(document_schema("evaluation-suite")).validate(valid)
    with pytest.raises(AssistantError, match="invalid_eval_source"):
        validate_suite(valid)  # JSON Schema counts characters; runtime counts UTF-8 bytes.


@pytest.mark.parametrize("field", ["id", "profile", "label"])
def test_history_identifier_boundary(field):
    valid = history()
    target = valid["cases"][0] if field != "label" else valid["cases"][0]["expected"][0]
    target[field] = "a" * 80
    invalid = deepcopy(valid)
    target = invalid["cases"][0] if field != "label" else invalid["cases"][0]["expected"][0]
    target[field] += "a"
    parity("history-suite", valid, invalid, validate_history_suite)
    target[field] = "a\n"
    parity("history-suite", valid, invalid, validate_history_suite)


@pytest.mark.parametrize("policy", [False, True])
def test_history_repository_length_boundary(policy):
    valid = history()
    case = valid["cases"][0]
    if policy:
        case["policy"] = {"path": "gate.json", "sha256": "a" * 64, "repo_path": "r" * 4096}
    else:
        case["repo_path"] = "r" * 4096
    invalid = deepcopy(valid)
    target = invalid["cases"][0]["policy"] if policy else invalid["cases"][0]
    target["repo_path"] += "r"
    parity("history-suite", valid, invalid, validate_history_suite)
    target["repo_path"] = ""
    parity("history-suite", valid, invalid, validate_history_suite)


@pytest.mark.parametrize("field", ["expected", "paths"])
def test_history_expected_count_boundary(field):
    valid = history()
    case = valid["cases"][0]
    if field == "expected":
        case["expected"] = [{**deepcopy(case["expected"][0]), "label": f"label-{i}"} for i in range(50)]
    else:
        case["expected"][0]["paths"] = [f"src/cash{i}.py" for i in range(50)]
    invalid = deepcopy(valid)
    target = invalid["cases"][0]
    if field == "expected":
        target["expected"].append({**deepcopy(case["expected"][0]), "label": "label-50"})
    else:
        target["expected"][0]["paths"].append("src/cash50.py")
    parity("history-suite", valid, invalid, validate_history_suite)


@pytest.mark.parametrize("size", [40, 64])
def test_history_revision_lengths_and_policy_commit(size):
    valid = history()
    valid["cases"][0].update(base_sha="a" * size, head_sha="b" * size)
    invalid = deepcopy(valid)
    invalid["cases"][0]["head_sha"] += "b"
    parity("history-suite", valid, invalid, validate_history_suite)
    valid["cases"][0]["policy"] = {"path": "gate.json", "sha256": "c" * 64, "commit": "d" * 40}
    invalid = deepcopy(valid)
    invalid["cases"][0]["policy"]["commit"] += "d"
    parity("history-suite", valid, invalid, validate_history_suite)
    if size == 64:
        invalid = deepcopy(valid)
        del invalid["cases"][0]["policy"]["commit"]
        parity("history-suite", valid, invalid, validate_history_suite)
        with pytest.raises(AssistantError, match="history_policy_commit_invalid"):
            validate_history_suite(invalid)


def related():
    return {"rule_version": 1, "budget_bytes": 24_000, "snippets": [], "skipped": [], "skipped_count": 0}


def snippet(i=0):
    return {"path": f"src/other{i}.py", "symbol": "helper", "relation": "callee",
            "reference": {"path": "src/cash.py", "line": 1}, "lines": [[1, "def helper(): pass"]],
            "sha256": "a" * 64}


def check_related(block):
    verify_related(block, ["src/cash.py"], replace(Config(), related_context="related"), lambda _: False)


@pytest.mark.parametrize("field,limit", [("snippets", 40), ("skipped", 50)])
def test_related_array_boundaries(field, limit):
    from finassist.packet_schema import _related_schema
    valid = related()
    def item(i):
        return snippet(i) if field == "snippets" else {"path": f"src/other{i}.py", "symbol": None, "reason": "omitted"}
    valid[field] = [item(i) for i in range(limit)]
    if field == "skipped":
        valid["skipped_count"] = limit + 1
    check_related(valid)
    schema = Draft202012Validator(_related_schema())
    schema.validate(valid)
    invalid = deepcopy(valid)
    invalid[field].append(item(limit))
    with pytest.raises(ValidationError):
        schema.validate(invalid)
    with pytest.raises(AssistantError, match="packet_related_invalid"):
        check_related(invalid)


@pytest.mark.parametrize("field,value,bad", [("skipped_count", 1_000_000, 1_000_001),
                                            ("skipped_count", 0, -1), ("budget_bytes", 0, -1)])
def test_related_numeric_boundaries(field, value, bad):
    from finassist.packet_schema import _related_schema
    valid = related()
    valid[field] = value
    schema = Draft202012Validator(_related_schema())
    schema.validate(valid)
    check_related(valid)
    invalid = {**valid, field: bad}
    with pytest.raises(ValidationError):
        schema.validate(invalid)
    with pytest.raises(AssistantError, match="packet_related_invalid"):
        check_related(invalid)


def test_related_reason_and_line_boundaries():
    from finassist.packet_schema import _related_schema
    schema = Draft202012Validator(_related_schema())
    valid = related()
    valid.update(snippets=[snippet()], skipped=[{"path": "src/other.py", "symbol": None, "reason": "a" * 81}],
                 skipped_count=1)
    schema.validate(valid)
    check_related(valid)
    for mutate in (lambda x: x["skipped"][0].update(reason="a" * 82),
                   lambda x: x["snippets"][0]["reference"].update(line=0),
                   lambda x: x["snippets"][0].update(lines=[[0, "source"]]),
                   lambda x: x["snippets"][0].update(lines=[]),
                   lambda x: x["snippets"][0].update(lines=[[1, "source", "extra"]])):
        invalid = deepcopy(valid)
        mutate(invalid)
        with pytest.raises(ValidationError):
            schema.validate(invalid)
        with pytest.raises(AssistantError, match="packet_related_invalid"):
            check_related(invalid)


def test_packet_path_count_and_withheld_boundaries(repository):
    packet = build_packet(*repository, Config())
    packet["files"] = []
    packet["changed_paths"] = [f"src/cash{i}.py" for i in range(2000)]
    packet["omitted"] = [{"path": p, "reason": "synthetic_omission"} for p in packet["changed_paths"]]
    invalid = deepcopy(packet)
    invalid["changed_paths"].append("src/cash2000.py")
    invalid["omitted"].append({"path": "src/cash2000.py", "reason": "synthetic_omission"})
    parity("packet", rehash(packet), rehash(invalid), lambda p: verify_packet(p, Config()))
    packet.update(changed_paths=[], files=[], omitted=[], withheld={"count": 2000, "reason": WITHHELD_REASON})
    invalid = deepcopy(packet)
    invalid["withheld"]["count"] += 1
    config = replace(Config(), private_paths="skip-and-report")
    parity("packet", rehash(packet), rehash(invalid), lambda p: verify_packet(p, config))
    invalid["withheld"]["count"] = 0
    parity("packet", rehash(packet), rehash(invalid), lambda p: verify_packet(p, config))


def test_review_withheld_count_and_status_boundaries(repository, tmp_path):
    report = review_packet(build_packet(*repository, Config()), Config(), tmp_path / "audit")
    report["withheld"] = {"count": 2000, "reason": WITHHELD_REASON}
    def runtime(d):
        contracts.validate_document_shape(d, "review-report", "review_schema_invalid")
    invalid = deepcopy(report)
    invalid["withheld"]["count"] = 2001
    parity("review-report", report, invalid, runtime)
    for count in [0, True]:
        invalid["withheld"]["count"] = count
        parity("review-report", report, invalid, runtime)
    invalid = deepcopy(report)
    invalid["status"] = "invented-status"
    parity("review-report", report, invalid, runtime)
    invalid = deepcopy(report)
    invalid["findings"] = [{}]
    parity("review-report", report, invalid, runtime)


def missing_fields(kind, document, fields, runtime, path=()):
    Draft202012Validator(document_schema(kind)).validate(document)
    runtime(document)
    for field in fields.split():
        invalid = deepcopy(document)
        target = invalid
        for key in path:
            target = target[key]
        del target[field]
        with pytest.raises(ValidationError):
            Draft202012Validator(document_schema(kind)).validate(invalid)
        with pytest.raises(AssistantError):
            runtime(invalid)


def test_suite_required_fields():
    for kind, factory, runtime in [("evaluation-suite", evaluation, validate_suite),
                                    ("history-suite", history, validate_history_suite)]:
        missing_fields(kind, factory(), "version cases", runtime)
    missing_fields("evaluation-suite", evaluation(), "id path before after expected_defect", validate_suite, ("cases", 0))
    missing_fields("history-suite", history(), "id repo_path base_sha head_sha profile expected negative_control",
                   validate_history_suite, ("cases", 0))
    missing_fields("history-suite", history(), "label severity paths", validate_history_suite, ("cases", 0, "expected", 0))
    suite = history()
    suite["cases"][0]["policy"] = {"path": "gate.json", "sha256": "a" * 64}
    missing_fields("history-suite", suite, "path sha256", validate_history_suite, ("cases", 0, "policy"))


def test_packet_and_related_required_fields(repository):
    packet = build_packet(*repository, Config())
    missing_fields("packet", packet,
                   "schema_version base head merge_base profile changed_paths files omitted data_class classification_limit generated_paths packet_hash",
                   lambda p: verify_packet(p, Config()))
    missing_fields("packet", packet, "path status before after before_hash after_hash before_mode after_mode",
                   lambda p: verify_packet(p, Config()), ("files", 0))
    legacy = deepcopy(packet)
    legacy["schema_version"] = 1
    for item in legacy["files"]:
        del item["before_mode"]
        del item["after_mode"]
    missing_fields("packet", rehash(legacy), "path status before after before_hash after_hash",
                   lambda p: verify_packet(p, Config()), ("files", 0))
    counted = deepcopy(packet)
    counted["withheld"] = {"count": 1, "reason": WITHHELD_REASON}
    missing_fields("packet", rehash(counted), "count reason",
                   lambda p: verify_packet(p, replace(Config(), private_paths="skip-and-report")), ("withheld",))
    omitted = deepcopy(packet)
    omitted["files"] = []
    omitted["omitted"] = [{"path": name, "reason": "synthetic_omission"} for name in omitted["changed_paths"]]
    missing_fields("packet", rehash(omitted), "path reason", lambda p: verify_packet(p, Config()), ("omitted", 0))
    config = replace(Config(), related_context="related")
    packet["related"] = related()
    packet["related"]["snippets"] = [snippet()]
    packet["related"]["skipped"] = [{"path": "src/skipped.py", "symbol": None, "reason": "omitted"}]
    packet["related"]["skipped_count"] = 1
    rehash(packet)
    def runtime(p):
        verify_packet(p, config)
    for fields, path in [("rule_version budget_bytes snippets skipped skipped_count", ("related",)),
                         ("path symbol relation reference lines sha256", ("related", "snippets", 0)),
                         ("path line", ("related", "snippets", 0, "reference")),
                         ("path symbol reason", ("related", "skipped", 0))]:
        missing_fields("packet", packet, fields, runtime, path)
    packet["related"]["snippets"][0]["reference"] = {"path": "src/cash.py", "symbol": "changed"}
    missing_fields("packet", rehash(packet), "path symbol", runtime, ("related", "snippets", 0, "reference"))


@pytest.mark.parametrize("provider", ["offline", "openai"])
def test_saved_report_required_fields_and_runtime_invocation(repository, tmp_path, monkeypatch, provider):
    import finassist.review_report_schema as builder
    config = replace(Config(), provider=provider, model="" if provider == "offline" else "synthetic",
                     api_key_env="REVIEW_TEST_KEY", allow_network=provider != "offline",
                     input_usd_per_million=1, output_usd_per_million=1)
    monkeypatch.setenv("REVIEW_TEST_KEY", "fictional-test-value")
    packet = build_packet(*repository, config)
    def run():
        return review_packet(packet, config, tmp_path / "audit", network_approved=provider != "offline",
                             approved_packet_hash=packet["packet_hash"],
                             transport=httpx.MockTransport(lambda _: httpx.Response(
                                 200, json=envelope(json.dumps(response(packet))))))

    report = run()
    def runtime(d):
        contracts.validate_document_shape(d, "review-report", "review_schema_invalid")
    common = "head packet_hash triage qualification merge_authority status provider"
    fields = common + (" findings" if provider == "offline" else " base model config_hash review reservation omitted receipt")
    missing_fields("review-report", report, fields, runtime)
    missing_fields("review-report", report, "risks recommended_checks coverage_complete changes_present next_action",
                   runtime, ("triage",))
    if provider != "offline":
        missing_fields("review-report", report, "head summary reviewed_paths findings", runtime, ("review",))
        missing_fields("review-report", report, "severity path line claim impact reproduction evidence",
                       runtime, ("review", "findings", 0))
        missing_fields("review-report", report, "path side line sha256",
                       runtime, ("review", "findings", 0, "evidence", 0))
    report["withheld"] = {"count": 1, "reason": WITHHELD_REASON}
    missing_fields("review-report", report, "count reason", runtime, ("withheld",))
    original = builder.review_report_schema
    monkeypatch.setattr(builder, "review_report_schema",
                        lambda: {"allOf": [original(), {"required": ["contract_enforcement_probe"]}]})
    contracts._validator.cache_clear()
    from finassist.ledger import Ledger
    events = []
    append = Ledger.append
    def record(ledger, event):
        events.append(event["event"])
        return append(ledger, event)
    monkeypatch.setattr(Ledger, "append", record)
    with pytest.raises(AssistantError, match="review_schema_invalid"):
        run()  # Fails if either report producer stops applying the shared contract.
    assert "review_completed" not in events


@pytest.mark.parametrize("kind,factory,build_name", [
    ("evaluation-suite", evaluation, "evaluation_suite_schema"),
    ("history-suite", history, "history_suite_schema"), ("packet", None, "packet_schema")])
def test_runtime_structural_contract_cannot_be_removed(kind, factory, build_name, repository, monkeypatch):
    from finassist import packet_schema as packet_builder
    builder = packet_builder if kind == "packet" else contracts
    original = getattr(builder, build_name)
    monkeypatch.setattr(builder, build_name,
                        lambda: {"allOf": [original(), {"required": ["contract_enforcement_probe"]}]})
    document = build_packet(*repository, Config()) if kind == "packet" else factory()
    runtime = {"packet": verify_packet, "evaluation-suite": validate_suite, "history-suite": validate_history_suite}[kind]
    with pytest.raises(AssistantError, match={"packet": "packet_schema_invalid", "evaluation-suite": "invalid_eval_suite",
                                             "history-suite": "history_suite_invalid"}[kind]):
        runtime(document)


def test_documented_acceptance_changes(repository, tmp_path, capsys):
    config = replace(Config(), related_context="related")
    packet = build_packet(*repository, config)
    packet["related"]["rule_version"] = True
    with pytest.raises(AssistantError, match="packet_schema_invalid"):
        verify_packet(rehash(packet), config)
    suite = tmp_path / "cases.json"
    suite.write_text(json.dumps({"version": 1, "cases": [False]}), encoding="utf-8")
    assert main(["--audit-dir", str(tmp_path / "audit"), "evaluate", "--suite", str(suite),
                 "--output", str(tmp_path / "report.json")]) == 2
    assert "invalid_eval_case" in capsys.readouterr().err


def test_schema_identifiers_are_independent_of_distribution_release(monkeypatch):
    import finassist
    ids = {kind: document_schema(kind)["$id"] for kind in SCHEMA_FILES}
    monkeypatch.setattr(finassist, "__version__", "999.0.0")
    assert {kind: document_schema(kind)["$id"] for kind in SCHEMA_FILES} == ids == SCHEMA_IDS
    assert all(value.startswith("urn:finledgerpoli:schema:") for value in ids.values())
    assert ids["gate-report"] != ids["gate-report-v1"]


def test_schema_cli_reads_packaged_contract_without_rebuilding(monkeypatch, capsys):
    def unexpected(*_args):
        pytest.fail("schema CLI must read its installed resource")
    monkeypatch.setattr("finassist.document_schemas.document_schema", unexpected)
    assert main(["config", "schema", "--kind", "packet"]) == 0
    assert json.loads(capsys.readouterr().out)["$id"] == SCHEMA_IDS["packet"]


def test_schema_generator_check_is_read_only_and_detects_drift(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("document_generator", ROOT / "scripts/generate_document_schemas.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    assert generator.main(["--check"]) is None
    # Redirect its explicit repository root to an isolated miniature fixture.
    monkeypatch.setattr(generator, "__file__", str(tmp_path / "scripts/generate_document_schemas.py"))
    generator.main(["--kind", "packet"])
    target = tmp_path / "schemas" / SCHEMA_FILES["packet"]
    target.write_text("{}\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="drift"):
        generator.main(["--kind", "packet", "--check"])
    assert target.read_text(encoding="utf-8") == "{}\n"


def test_ci_schema_repository_and_config_constraints():
    from importlib.resources import files
    from finassist.ci_policy import repository_name
    document = json.loads(files("finassist").joinpath("resources/github-ci-policy.json").read_text())
    schema = exported_validator("ci-policy")
    schema.validate(document)
    for repository in ["owner", "owner/repo/extra", "./repo", "owner/..", "a" * 101 + "/repo", "owner/repo\n"]:
        invalid = {**deepcopy(document), "repository": repository}
        with pytest.raises(ValidationError):
            schema.validate(invalid)
        with pytest.raises(AssistantError, match="ci_repository_invalid"):
            repository_name(repository)
    document["repository"] = "a" * 100 + "/" + "b" * 100
    schema.validate(document)
    repository_name(document["repository"])
    for changes in [{"invented_option": True}, {"related_max_bytes": 400_001}, {"schema_version": True}]:
        invalid = deepcopy(document)
        invalid["config"].update(changes)
        with pytest.raises(ValidationError):
            schema.validate(invalid)
    assert document_schema("ci-policy")["properties"]["config"]["$ref"] == SCHEMA_IDS["config"]
    assert "separate follow-up" in document_schema("ci-policy")["properties"]["workflow"]["description"]


def test_export_kit_carries_every_canonical_installed_schema(tmp_path):
    from importlib.resources import files
    from finassist.integrations import export_kit
    destination = tmp_path / "kit"
    export_kit(destination)
    assert {p.name for p in (destination / "schemas").iterdir()} == set(SCHEMA_FILES.values())
    for name in SCHEMA_FILES.values():
        assert (destination / "schemas" / name).read_bytes() == files("finassist").joinpath("resources/" + name).read_bytes()


def test_gate_report_retains_integral_float_version_acceptance():
    from finassist.model_gate import refused_model_report, validate_model_report
    report = refused_model_report("synthetic_refusal")
    report["schema_version"] = 2.0
    report["report_hash"] = digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
    Draft202012Validator(document_schema("gate-report")).validate(report)
    validate_model_report(report)


def test_embedded_review_response_has_no_dialect_and_provider_bytes_stay_exact():
    from finassist.review import review_schema
    before = canonical(review_schema())
    saved = document_schema("review-report")["oneOf"][1]["properties"]["review"]
    assert "$schema" not in saved and "$id" not in saved
    assert canonical(review_schema()) == before
