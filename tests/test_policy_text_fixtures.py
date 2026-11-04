"""Only reviewed base policy can attest narrowly scoped synthetic text fixtures."""
from dataclasses import replace
import json

import pytest

from conftest import command, synthetic_symlink
from finassist.errors import AssistantError
from finassist.model_policy import load_model_policy
from finassist.scope import build_packet, verify_packet
from finassist.config import Config, load_config
from finassist.security import canonical
from test_model_gate import change_policy, run
from test_model_policy import model_policy
from test_providers_review import envelope
from test_ci_gate import base_policy, gate

pytest_plugins = ("test_model_gate", "test_model_policy", "test_ci_gate")


def candidate(case, name, raw=b"symbol,price\nSYNTHETIC,1.25\n"):
    target = case["repo"] / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    command(case["repo"], "add", "--force", name)
    command(case["repo"], "commit", "-m", "Synthetic text fixture candidate")
    case["head"] = command(case["repo"], "rev-parse", "HEAD")


@pytest.mark.parametrize("listed", [["tests/fixtures/prices.csv"], ["tests/fixtures/"]])
def test_base_policy_fixture_enters_packet_and_revalidation(gate_case, listed):
    change_policy(gate_case, allow_paths=["src/", "tests/"], fixture_roots=listed)
    candidate(gate_case, "tests/fixtures/prices.csv")
    policy = load_model_policy(gate_case["repo"], gate_case["base"], "gate-policy.json", gate_case["pin"])
    packet = build_packet(gate_case["repo"], gate_case["base"], gate_case["head"], policy.config)
    verify_packet(packet, config=policy.config)
    assert "tests/fixtures/prices.csv" in [item["path"] for item in packet["files"]]


@pytest.mark.parametrize("listed,name", [
    (["tests/fixtures/prices.csv"], "tests/fixtures/other.csv"),
    (["tests/fixtures/public/"], "tests/fixtures/public-extra/prices.csv"),
    ([], "tests/fixtures/prices.csv"),
])
def test_unlisted_fixture_is_refused_before_provider(gate_case, listed, name):
    change_policy(gate_case, allow_paths=["src/", "tests/"], fixture_roots=listed)
    candidate(gate_case, name)
    report, calls = run(gate_case)
    assert report["reasons"] == ["private_or_binary_path"] and not calls


@pytest.mark.parametrize("raw,reason", [
    (b"access_" + b'token = "' + b"x" * 30 + b'"\n', "sensitive_content"),
    (b"synthetic\0binary", "binary_input"),
    (b"\xff\xfe", "non_text_blob"),
])
def test_listed_fixture_still_has_mandatory_text_screening(gate_case, raw, reason):
    change_policy(gate_case, allow_paths=["src/", "tests/"], fixture_roots=["tests/fixtures/"])
    candidate(gate_case, "tests/fixtures/prices.csv", raw)
    report, calls = run(gate_case)
    assert report["reasons"] == [reason] and not calls


@pytest.mark.parametrize("prefix", ["data/", "tests/fixtures/data/", "tests/fixtures/DATA/"])
def test_policy_cannot_list_data_component(policy_case, prefix):
    document = model_policy()
    document["model_review"]["fixture_roots"] = [prefix]
    repo, base, pin = policy_case(document)
    with pytest.raises(AssistantError, match="^fixture_root_contains_data$"):
        load_model_policy(repo, base, "gate-policy.json", pin)


def test_manual_configuration_cannot_supply_fixture_authority():
    with pytest.raises(AssistantError):
        load_config(content=canonical({"fixture_roots": ["tests/fixtures/"]}))
    with pytest.raises(AssistantError, match="^private_or_binary_path$"):
        replace(Config(), text_suffixes=(*Config().text_suffixes, ".csv")).check_path("tests/fixtures/prices.csv")


def test_existing_per_policy_size_limit_accepts_engine_and_retains_hard_ceiling(gate_case, policy_case):
    raw = b"#" + b"x" * 195704 + b"\n"
    change_policy(gate_case, max_file_bytes=200000, max_request_bytes=1000000)
    candidate(gate_case, "src/engine.py", raw)
    policy = load_model_policy(gate_case["repo"], gate_case["base"], "gate-policy.json", gate_case["pin"])
    packet = build_packet(gate_case["repo"], gate_case["base"], gate_case["head"], policy.config)
    assert any(item["path"] == "src/engine.py" for item in packet["files"])
    document = model_policy()
    document["model_review"]["max_file_bytes"] = 2000001
    repo, base, pin = policy_case(document)
    with pytest.raises(AssistantError, match="^gate_policy_invalid$"):
        load_model_policy(repo, base, "gate-policy.json", pin)


def reviewed(packet):
    return envelope(json.dumps({"head": packet["head"], "summary": "Synthetic review complete.",
                                "reviewed_paths": [item["path"] for item in packet["files"]],
                                "findings": []}))


@pytest.mark.parametrize("root", ["tests/fixtures/", "a/b/tests/fixtures/", "fixtures/", "tests/one.csv"])
def test_structural_roots_send_screened_fixtures_to_fake_provider(gate_case, root):
    change_policy(gate_case, allow_paths=["src/", root], fixture_roots=[root])
    name = root + "one.csv" if root.endswith("/") else root
    candidate(gate_case, name)
    report, calls = run(gate_case, reviewed)
    assert report["verdict"] == "PASS" and len(calls) == 1
    assert not report["merge_authority"]


@pytest.mark.parametrize("root,reason", [
    ("synthetic/", "fixture_root_unqualified"), ("tests-old/", "fixture_root_unqualified"),
    ("../tests/", "unsafe_path"), ("/tests/", "unsafe_path"),
    ("tests/**", "fixture_root_invalid"), ("tests/data/", "fixture_root_contains_data"),
])
def test_roots_fail_closed_before_provider(gate_case, root, reason):
    change_policy(gate_case, fixture_roots=[root])
    report, calls = run(gate_case)
    assert report["reasons"] == [reason] and not calls


@pytest.mark.parametrize("root", ["synthetic/", "synthetic/one.csv"])
def test_base_marker_qualifies_exact_or_directory_root_without_becoming_context(gate_case, root):
    candidate(gate_case, "synthetic/.finledgerpoli-synthetic", b"synthetic: true\n")
    change_policy(gate_case, allow_paths=["src/", "synthetic/"], fixture_roots=[root])
    candidate(gate_case, "synthetic/one.csv")
    report, calls = run(gate_case, reviewed)
    assert report["verdict"] == "PASS" and len(calls) == 1
    assert b"synthetic: true" not in calls[0].content


def test_head_only_marker_cannot_qualify_root(gate_case):
    change_policy(gate_case, allow_paths=["src/", "synthetic/"], fixture_roots=["synthetic/"])
    candidate(gate_case, "synthetic/.finledgerpoli-synthetic", b"synthetic: true\n")
    candidate(gate_case, "synthetic/one.csv")
    report, calls = run(gate_case)
    assert report["reasons"] == ["fixture_root_unqualified"] and not calls


@pytest.mark.parametrize("raw", [b"synthetic: false\n", b" synthetic: true\n", b"synthetic: true \n", b"", b"\xff"])
def test_marker_first_line_must_be_exact(gate_case, raw):
    candidate(gate_case, "synthetic/.finledgerpoli-synthetic", raw)
    change_policy(gate_case, fixture_roots=["synthetic/"])
    report, calls = run(gate_case)
    assert report["reasons"] == ["fixture_root_unqualified"] and not calls


def test_marker_head_tampering_blocks_review(gate_case):
    candidate(gate_case, "synthetic/.finledgerpoli-synthetic", b"synthetic: true\n")
    change_policy(gate_case, allow_paths=["src/", "synthetic/"], fixture_roots=["synthetic/"])
    candidate(gate_case, "synthetic/.finledgerpoli-synthetic", b"synthetic: false\n")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_fixture_marker_change_requires_review"] and not calls


@pytest.mark.parametrize("folder", ["private", "clients", "households", "holdings", "credentials", ".env-local", "data"])
def test_listed_root_cannot_relax_private_descendants(gate_case, folder):
    change_policy(gate_case, allow_paths=["src/", "tests/"], fixture_roots=["tests/fixtures/"])
    candidate(gate_case, "tests/fixtures/" + folder + "/one.csv")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
    if folder == "data":
        assert report["reasons"] == ["fixture_root_contains_data"]


@pytest.mark.parametrize("changes,reason", [
    ({"fixture_max_file_bytes": 8}, "file_limit_exceeded"),
    ({"fixture_max_file_bytes": 2000001}, "gate_policy_invalid"),
    ({"fixture_max_file_bytes": True}, "gate_policy_invalid"),
    ({"deny_paths": ["tests/fixtures/"]}, "gate_denied_path"),
    ({"allow_paths": ["src/"]}, "gate_path_not_allowed"),
])
def test_fixture_cap_and_original_scope_gates_still_apply(gate_case, changes, reason):
    options = {"allow_paths": ["src/", "tests/"], "fixture_roots": ["tests/fixtures/"]}
    options.update(changes)
    change_policy(gate_case, **options)
    candidate(gate_case, "tests/fixtures/one.csv")
    report, calls = run(gate_case)
    assert report["reasons"] == [reason] and not calls


def test_fixture_limit_is_independent_and_rechecked_on_packet(gate_case):
    change_policy(gate_case, allow_paths=["src/", "tests/"], fixture_roots=["tests/fixtures/"],
                  fixture_max_file_bytes=200000, max_request_bytes=1000000)
    candidate(gate_case, "tests/fixtures/one.csv", b"SYNTHETIC," + b"1" * 60000 + b"\n")
    report, calls = run(gate_case, reviewed)
    assert report["verdict"] == "PASS" and len(calls) == 1
    config = load_model_policy(gate_case["repo"], gate_case["base"], "gate-policy.json", gate_case["pin"]).config
    packet = build_packet(gate_case["repo"], gate_case["base"], gate_case["head"], config)
    with pytest.raises(AssistantError, match="^file_limit_exceeded$"):
        verify_packet(packet, replace(config, fixture_max_file_bytes=48000))


def test_head_policy_cannot_grant_fixture_allowance(gate_case):
    document = model_policy()
    document["model_review"].update(fixture_roots=["tests/fixtures/"], allow_paths=["src/", "tests/"])
    candidate(gate_case, "gate-policy.json", canonical(document))
    candidate(gate_case, "tests/fixtures/one.csv")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_policy_change_requires_review"] and not calls


def test_immutable_ignore_rules_still_refuse_listed_fixtures(gate_case):
    candidate(gate_case, ".gitignore", b"tests/fixtures/one.csv\n")
    change_policy(gate_case, fixture_roots=["tests/fixtures/"], allow_paths=["src/", "tests/"])
    candidate(gate_case, "tests/fixtures/one.csv")
    (gate_case["repo"] / ".gitignore").write_text("")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_ignored_path"] and not calls


def test_ci_policy_fixture_reaches_isolated_recipe_snapshot(ci_case, tmp_path, dispatch, monkeypatch):
    import finassist.workflow_execution as execution
    base_policy(ci_case, lambda p: p.update(fixture_roots=["tests/fixtures/"], guard_paths=[]))
    candidate(ci_case, "tests/fixtures/one.csv")
    ci_case["context"] = replace(ci_case["context"], head_sha=ci_case["head"])
    original = execution.run_recipe
    seen = []
    def inspect(config, name, snapshot, **kwargs):
        seen.append((snapshot / "tests/fixtures/one.csv").read_text())
        return original(config, name, snapshot, **kwargs)
    monkeypatch.setattr(execution, "run_recipe", inspect)
    report = gate(ci_case, tmp_path)
    assert report["status"] == "passed" and dispatch == ["unit", "cash"] and len(seen) == 2


def test_ci_listed_fixture_cannot_bypass_immutable_ignores(ci_case, tmp_path, dispatch):
    candidate(ci_case, ".gitignore", b"tests/fixtures/one.csv\n")
    base_policy(ci_case, lambda p: p.update(fixture_roots=["tests/fixtures/"], guard_paths=[]))
    candidate(ci_case, "tests/fixtures/one.csv")
    ci_case["context"] = replace(ci_case["context"], head_sha=ci_case["head"])
    with pytest.raises(AssistantError, match="^gate_ignored_path$"):
        gate(ci_case, tmp_path)
    assert not dispatch


@pytest.mark.parametrize("target_kind", ["root", "marker", "fixture"])
def test_links_never_qualify_roots_or_enter_context(gate_case, target_kind):
    repo = gate_case["repo"]
    target = repo / "public-marker.txt"
    target.write_text("synthetic: true\n")
    if target_kind == "root":
        link = repo / "tests/link"
        root = "tests/link/"
    elif target_kind == "marker":
        link = repo / "synthetic/.finledgerpoli-synthetic"
        root = "synthetic/"
    else:
        root = "tests/fixtures/"
        change_policy(gate_case, allow_paths=["src/", "tests/"], fixture_roots=[root])
        link = repo / "tests/fixtures/one.csv"
    link.parent.mkdir(parents=True, exist_ok=True)
    synthetic_symlink(link, target)
    command(repo, "add", str(link.relative_to(repo)))
    command(repo, "commit", "-m", "Synthetic link counterexample")
    gate_case["head"] = command(repo, "rev-parse", "HEAD")
    if target_kind != "fixture":
        change_policy(gate_case, fixture_roots=[root])
    report, calls = run(gate_case)
    assert report["reasons"] == ["linked_or_special_git_object"] and not calls


@pytest.mark.parametrize("suffix", [".csv", ".tsv", ".yaml", ".yml"])
def test_allowance_stays_text_only(gate_case, suffix):
    change_policy(gate_case, allow_paths=["src/", "tests/"], fixture_roots=["tests/fixtures/"])
    candidate(gate_case, "tests/fixtures/one" + suffix)
    report, calls = run(gate_case, reviewed)
    assert report["verdict"] == "PASS" and len(calls) == 1


@pytest.mark.parametrize("suffix", [".parquet", ".xlsx", ".db", ".pem"])
def test_fixture_root_cannot_admit_other_denied_formats(gate_case, suffix):
    change_policy(gate_case, allow_paths=["src/", "tests/"], fixture_roots=["tests/fixtures/"])
    candidate(gate_case, "tests/fixtures/one" + suffix)
    report, calls = run(gate_case)
    assert report["reasons"] == ["private_or_binary_path"] and not calls


def test_ci_marker_is_guarded_and_omitted_from_recipe_inputs(ci_case, tmp_path, dispatch, monkeypatch):
    import finassist.workflow_execution as execution
    candidate(ci_case, "synthetic/.finledgerpoli-synthetic", b"synthetic: true\n")
    def options(policy):
        policy.update(fixture_roots=["synthetic/"], guard_paths=[])
        policy["config"]["allow_paths"] = [*policy["config"]["allow_paths"], "synthetic/"]
    base_policy(ci_case, options)
    candidate(ci_case, "synthetic/one.csv")
    ci_case["context"] = replace(ci_case["context"], head_sha=ci_case["head"])
    original = execution.run_recipe
    def inspect(config, name, snapshot, **kwargs):
        assert (snapshot / "synthetic/one.csv").is_file()
        assert not (snapshot / "synthetic/.finledgerpoli-synthetic").exists()
        return original(config, name, snapshot, **kwargs)
    monkeypatch.setattr(execution, "run_recipe", inspect)
    assert gate(ci_case, tmp_path)["status"] == "passed"
    candidate(ci_case, "synthetic/.finledgerpoli-synthetic", b"synthetic: false\n")
    ci_case["context"] = replace(ci_case["context"], head_sha=ci_case["head"])
    report = gate(ci_case, tmp_path / "second")
    assert "ci_guarded_change_requires_review" in report["blocking_reasons"]
    assert dispatch == ["unit", "cash"]
