"""Review regressions at public loaders and their byte/count boundaries."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from finassist import ci_policy, scope
from finassist.config import Config
from finassist.document_schemas import SCHEMA_FILES, document_schema_text
from finassist.errors import AssistantError
from finassist.history_scoring import validate_history_evaluation
from finassist.history_suite import validate_history_suite
from finassist.security import canonical, digest
from test_ci_gate import base_policy
from test_document_schema_boundaries import history, related, snippet, check_related, rehash
from test_document_schemas import exported_validator
from test_history_scoring import evaluation, signed

pytest_plugins = ("test_ci_gate",)


@pytest.mark.parametrize("options,code", [
    ({"allow_pathz": []}, "unknown_config_option"),
    ({"min_version": "99.0.0", "future_option": True}, "minimum_version_required"),
    ({"timeout_seconds": 0}, "invalid_limit"),
])
def test_ci_config_keeps_specific_codes_and_version_precedence(ci_case, options, code):
    base_policy(ci_case, lambda p: p["config"].update(options))
    with pytest.raises(AssistantError) as caught:
        ci_policy.load_ci_policy(ci_case["repo"], ci_case["context"].base_sha,
                                 "finassist-ci.json", ci_case["pin"])
    assert caught.value.code == code
    if code == "unknown_config_option":
        assert "allow_pathz" in json.dumps(caught.value.public_details)


@pytest.mark.parametrize("mutation", ["negative-target", "urgent", "extra", "missing", "wrong-type"])
def test_history_scoring_must_enforce_expected_schema(mutation):
    data = evaluation()
    case = data["cases"][0]
    if mutation == "negative-target":
        case["negative_control"] = True
    elif mutation == "urgent":
        case["runs"][0]["findings"][0]["severity"] = "urgent"
    elif mutation == "extra":
        case["expected"][0]["unexpected"] = True
    elif mutation == "missing":
        del case["expected"][0]["paths"]
    else:
        case["expected"] = 42
    with pytest.raises(AssistantError, match="history_expected_invalid"):
        validate_history_evaluation(signed(data))


def test_history_trial_upper_boundary():
    validate_history_suite(history(), trials=20)
    with pytest.raises(AssistantError, match="history_suite_invalid"):
        validate_history_suite(history(), trials=21)


def test_history_suite_encoded_byte_boundary():
    suite = history()
    case = suite["cases"][0]
    suite["cases"] = [{**deepcopy(case), "id": f"case-{i:02}"} for i in range(50)]
    for case in suite["cases"]:
        case["expected"][0]["paths"] = [f"src/file-{i:02}.py" for i in range(50)]
    padding, extra = divmod(1_000_000 - len(canonical(suite)), 2500)
    index = 0
    for case in suite["cases"]:
        paths = case["expected"][0]["paths"]
        for i, path in enumerate(paths):
            paths[i] = path[:-3] + "q" * (padding + (index < extra)) + ".py"
            index += 1
    assert len(canonical(suite)) == 1_000_000
    validate_history_suite(suite)
    suite["cases"][-1]["expected"][0]["paths"][-1] += "q"
    assert len(canonical(suite)) == 1_000_001
    with pytest.raises(AssistantError, match="history_suite_too_large"):
        validate_history_suite(suite)


def test_packet_builder_changed_path_upper_boundary(repository, monkeypatch):
    original = scope.git
    count = 2000

    def git(repo, *args, **kwargs):
        if args[0] == "diff":
            return "".join(f"M\0src/generated/file-{i}.py\0" for i in range(count)).encode()
        return original(repo, *args, **kwargs)

    monkeypatch.setattr(scope, "git", git)
    cfg = replace(Config(), generated_paths=("src/generated/",), max_packet_bytes=2_000_000)
    packet = scope.build_packet(*repository, cfg)
    assert len(packet["changed_paths"]) == len(packet["omitted"]) == 2000
    count = 2001
    with pytest.raises(AssistantError, match="packet_file_count_limit"):
        scope.build_packet(*repository, cfg)


def test_related_snippet_encoded_byte_boundary():
    block = related()
    item = snippet()
    item["lines"] = [[1, ""]]
    item["lines"][0][1] = "q" * (4000 - len(canonical(item)))
    assert len(canonical(item)) == 4000
    block["snippets"] = [item]
    check_related(block)
    item["lines"][0][1] += "q"
    assert len(canonical(item)) == 4001
    with pytest.raises(AssistantError, match="packet_related_invalid"):
        check_related(block)


def test_packet_type_change_status_remains_accepted(repository):
    packet = scope.build_packet(*repository, Config())
    packet["files"][0]["status"] = "T"
    scope.verify_packet(rehash(packet), Config())
    packet["files"][0]["status"] = "Z"
    with pytest.raises(AssistantError, match="packet_schema_invalid"):
        scope.verify_packet(rehash(packet), Config())


@pytest.mark.parametrize("field,value,code", [
    ("changed_paths", None, "packet_schema_invalid"),
    ("allow_paths", None, "packet_allow_paths_mismatch"),
    ("generated_paths", None, "packet_generated_paths_mismatch"),
    ("profile", None, "packet_profile_mismatch"),
])
def test_packet_shape_preserves_field_refusals(repository, field, value, code):
    packet = scope.build_packet(*repository, Config())
    packet[field] = value
    with pytest.raises(AssistantError) as caught:
        scope.verify_packet(rehash(packet), Config())
    assert caught.value.code == code


@pytest.mark.parametrize("version", [0, 2, "1", False])
def test_related_version_refusal_stays_specific(repository, version):
    cfg = replace(Config(), related_context="related")
    packet = scope.build_packet(*repository, cfg)
    packet["related"]["rule_version"] = version
    with pytest.raises(AssistantError, match="packet_related_invalid"):
        scope.verify_packet(rehash(packet), cfg)


@pytest.mark.parametrize("mode", [None, "120000", 7])
def test_mode_refusal_precedes_file_integrity(repository, mode):
    packet = scope.build_packet(*repository, Config())
    packet["files"][0].update(after_mode=mode, after_hash=None)
    with pytest.raises(AssistantError, match="packet_mode_invalid"):
        scope.verify_packet(rehash(packet), Config())


@pytest.mark.parametrize("branch", ["bad..branch", "-bad", "bad\n", "a" * 257])
def test_ci_export_checks_branch_names(branch):
    from importlib.resources import files
    doc = json.loads(files("finassist").joinpath("resources/github-ci-policy.json").read_text())
    exported_validator("ci-policy").validate(doc)
    doc["base_branches"] = [branch]
    with pytest.raises(ValidationError):
        exported_validator("ci-policy").validate(doc)


def test_schema_identifiers_pin_exact_contract_bytes():
    pins = json.loads((Path(__file__).parent / "schema_contract_digests.json").read_text())
    actual = {}
    for kind in SCHEMA_FILES:
        text = document_schema_text(kind)
        actual[json.loads(text)["$id"]] = digest(text.encode())
    assert actual == pins, (
        "From the first published release carrying these schemas, a contract change needs a "
        "reviewed identifier revision and digest update. Before then, review and update the digest."
    )


@pytest.mark.parametrize("kind,paths,code", [
    ("evaluation", None, "unsafe_path"),
    ("history-expected", [""], "unsafe_path"),
    ("history-expected", "", "history_expected_invalid"),
    ("history-scoring", [""], "unsafe_path"),
    ("history-scoring", "", "history_expected_invalid"),
    ("history-policy", None, "unsafe_path"),
])
def test_empty_suite_paths_keep_unsafe_path(kind, paths, code):
    from finassist.evaluation import validate_suite
    from test_document_schema_boundaries import evaluation as synthetic_suite
    if kind == "history-scoring":
        data = evaluation()
        data["cases"][0]["expected"][0]["paths"] = paths
        with pytest.raises(AssistantError, match=code):
            validate_history_evaluation(signed(data))
        return
    suite = synthetic_suite() if kind == "evaluation" else history()
    if kind == "evaluation":
        suite["cases"][0]["path"] = ""
    elif kind == "history-expected":
        suite["cases"][0]["expected"][0]["paths"] = paths
    else:
        suite["cases"][0]["policy"] = {"path": "", "sha256": "a" * 64}
    with pytest.raises(AssistantError, match=code):
        (validate_suite if kind == "evaluation" else validate_history_suite)(suite)


@pytest.mark.parametrize("repository_value", [None, 7, [], {}])
def test_ci_repository_type_keeps_policy_error(ci_case, repository_value):
    base_policy(ci_case, lambda p: p.update(repository=repository_value))
    with pytest.raises(AssistantError, match="ci_policy_invalid"):
        ci_policy.load_ci_policy(ci_case["repo"], ci_case["context"].base_sha,
                                 "finassist-ci.json", ci_case["pin"])
