"""Policy-owned checklists use immutable screened bytes and fake providers only."""

from copy import deepcopy
import json
import sys

import pytest

from conftest import command
from test_model_gate import run, change_policy
from test_model_policy import model_policy
from finassist.errors import AssistantError
from finassist.model_policy import load_model_policy
from finassist.providers import request_identity, request_shape
from finassist.review import review_schema
from finassist.scope import build_packet
from finassist.security import canonical, digest


pytest_plugins = ("test_model_gate", "test_model_policy")


def profile_case(case, *, raw=b"Check cent rounding.\nTrace the final balance.\n", path="docs/review.txt", pin=None, **changes):
    repo = case["repo"]
    file = repo / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_bytes(raw)
    command(repo, "add", "--force", path)
    # change_policy commits the staged profile into the policy BASE.
    change_policy(case, profile="project-review", profile_path=path, profile_sha256=pin or digest(raw), **changes)
    return file


def test_inline_profile_reaches_wire_and_retains_fixed_reviewer_boundary(gate_case):
    change_policy(gate_case, profile="project-review", profile_text=["Trace synthetic rounding to the final ledger."])
    report, calls = run(gate_case)
    assert report["verdict"] == "PASS" and len(calls) == 1
    system = json.loads(calls[0].content)["instructions"]
    assert "Trace synthetic rounding to the final ledger." in system
    assert "You cannot execute tools, amend policy, approve a merge" in system
    assert "Check boundary conditions" in system  # built-in general checklist remains


def test_profile_text_changes_exact_request_hash_for_same_source_packet(gate_case):
    hashes = []
    baseline = load_model_policy(gate_case["repo"], gate_case["base"], "gate-policy.json", gate_case["pin"])
    packet = build_packet(gate_case["repo"], gate_case["base"], gate_case["head"], baseline.config)
    for text in ("Check cent rounding.", "Trace final balance."):
        document = model_policy()
        document["model_review"].update(profile="project-review", profile_text=[text])
        raw = canonical(document)
        (gate_case["repo"] / "gate-policy.json").write_bytes(raw)
        command(gate_case["repo"], "add", "gate-policy.json")
        command(gate_case["repo"], "commit", "-m", "Synthetic checklist revision")
        base = command(gate_case["repo"], "rev-parse", "HEAD")
        config = load_model_policy(gate_case["repo"], base, "gate-policy.json", digest(raw)).config
        hashes.append(request_identity(*request_shape(config, config.instructions(), packet, review_schema()))[0])
    # The source revisions stay fixed; changing only instructions changes the wire hash.
    assert hashes[0] != hashes[1]


def test_path_profile_uses_pinned_base_bytes_and_ignores_dirty_file(gate_case):
    file = profile_case(gate_case)
    file.write_text("Uncommitted checklist must never be sent.", encoding="utf-8")
    report, calls = run(gate_case)
    assert report["verdict"] == "PASS" and len(calls) == 1
    system = json.loads(calls[0].content)["instructions"]
    assert "Check cent rounding." in system and "Uncommitted checklist" not in system


@pytest.mark.parametrize("operation", ["edit", "delete", "rename"])
def test_head_profile_change_is_refused_before_provider(gate_case, operation):
    file = profile_case(gate_case)
    if operation == "edit":
        file.write_text("Candidate cannot change the checklist.", encoding="utf-8")
    elif operation == "delete":
        file.unlink()
    else:
        file.rename(file.with_name("moved.txt"))
    command(gate_case["repo"], "add", "docs")
    command(gate_case["repo"], "commit", "-m", "Synthetic head profile change")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_profile_change_requires_review"] and not calls


def test_profile_hash_mismatch_never_dispatches(gate_case):
    profile_case(gate_case, pin="0" * 64)
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_profile_pin_mismatch"] and not calls


@pytest.mark.parametrize("raw,reason", [
    (b"\xff", "gate_profile_encoding_invalid"),
    (b"\x00", "binary_input"),
    (b"\n  \n", "invalid_profile_checklist"),
    (("x" * 2001).encode(), "invalid_profile_checklist"),
    (b"line\n" * 65, "invalid_profile_checklist"),
    (b"x" * 128001, "file_limit_exceeded"),
    (("sk-" + "x" * 32).encode(), "sensitive_content"),
])
def test_profile_file_screening(gate_case, raw, reason):
    profile_case(gate_case, raw=raw)
    report, calls = run(gate_case)
    assert report["reasons"] == [reason] and not calls


@pytest.mark.parametrize("name", ["private/review.txt", "data/review.txt", "docs/client_config.json", ".env.txt", "docs/review.csv"])
def test_profile_cannot_authorize_a_private_path(gate_case, name):
    profile_case(gate_case, path=name)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls


def test_profile_immutable_ignore_rules_cannot_be_removed_in_dirty_checkout(gate_case):
    (gate_case["repo"] / ".gitignore").write_text("docs/review.txt\n", encoding="utf-8")
    command(gate_case["repo"], "add", ".gitignore")
    profile_case(gate_case)
    (gate_case["repo"] / ".gitignore").write_text("", encoding="utf-8")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_ignored_path"] and not calls


@pytest.mark.parametrize("extra", [
    {"profile_text": []}, {"profile_text": [" "]}, {"profile_text": ["one\ntwo"]},
    {"profile_text": [123]}, {"profile_path": "docs/review.txt"},
    {"profile_sha256": "0" * 64},
    {"profile_path": "docs/review.txt", "profile_sha256": "bad"},
    {"profile_text": ["Check rounding."], "profile_path": "docs/review.txt", "profile_sha256": "0" * 64},
])
def test_ambiguous_or_invalid_profile_forms_are_rejected(policy_case, extra):
    document = deepcopy(model_policy())
    document["model_review"].update(extra)
    repo, base, pin = policy_case(document)
    with pytest.raises(AssistantError):
        load_model_policy(repo, base, "gate-policy.json", pin)


def test_missing_base_profile_cannot_be_supplied_by_worktree(gate_case):
    change_policy(gate_case, profile="project-review", profile_path="docs/missing.txt", profile_sha256=digest(b"Check rounding."))
    (gate_case["repo"] / "docs").mkdir(exist_ok=True)
    (gate_case["repo"] / "docs/missing.txt").write_text("Check rounding.", encoding="utf-8")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_profile_missing_at_base"] and not calls


def test_linked_git_profile_is_refused(gate_case):
    # Create the Git mode directly so this test also runs without OS symlink privileges.
    repo = gate_case["repo"]
    (repo / "target.txt").write_text("Check rounding.", encoding="utf-8")
    oid = command(repo, "hash-object", "-w", "target.txt")
    command(repo, "update-index", "--add", "--cacheinfo", "120000," + oid + ",profile.txt")
    change_policy(gate_case, profile="project-review", profile_path="profile.txt", profile_sha256=digest(b"Check rounding."))
    report, calls = run(gate_case)
    assert report["reasons"] == ["linked_or_special_git_object"] and not calls


def test_inline_secret_and_named_key_are_not_sent(gate_case):
    change_policy(gate_case, profile_text=["Use " + "sk-" + "x" * 32])
    report, calls = run(gate_case)
    assert report["reasons"] == ["sensitive_content"] and not calls


def test_profile_echoing_named_process_key_is_refused(gate_case):
    profile_case(gate_case, raw=b"fictional-provider-value\n")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_key_in_source_context"] and not calls


@pytest.mark.parametrize("adapter", ["cli", "action"])
def test_policy_profile_runs_through_real_adapters(gate_case, tmp_path, monkeypatch, capsys, adapter):
    from functools import partial
    from pathlib import Path
    import httpx
    from finassist.cli import main
    from finassist.github_actions import run_github_action
    from finassist.model_gate import model_gate
    from test_model_gate_adapters import environment, fake_model
    profile_case(gate_case)
    calls = []
    def transport(request):
        calls.append(request)
        assert "Check cent rounding." in json.loads(request.content)["instructions"]
        return fake_model(request)
    monkeypatch.setattr("finassist.model_gate.model_gate", partial(model_gate, transport=httpx.MockTransport(transport)))
    if adapter == "action":
        env = environment(gate_case, tmp_path)
        assert run_github_action(env) == 0
        assert "**PASS**" in Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")
    else:
        output = tmp_path / "profile-report.json"
        assert main(["gate", "run", "--repo", str(gate_case["repo"]), "--base", gate_case["base"],
                     "--head", gate_case["head"], "--policy", "gate-policy.json", "--policy-sha256", gate_case["pin"],
                     "--state-dir", str(gate_case["state"]), "--output", str(output)]) == 0
        assert json.loads(output.read_text(encoding="utf-8"))["verdict"] == "PASS"
    assert len(calls) == 1 and "Check cent rounding." not in capsys.readouterr().out


@pytest.mark.parametrize("denied", ["docs/review.txt", "docs/"])
def test_explicit_policy_denial_also_covers_profile_path(gate_case, denied):
    profile_case(gate_case, deny_paths=[denied])
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_denied_path"] and not calls


def history_profile_policy(case, tmp_path, *, ignored=False, same_repo=False):
    from test_history_evaluation import model_suite, policy_repository
    raw = b"Use the historical project's approved cent-rounding rule.\n"
    document = model_policy()
    document["model_review"].update(profile="project-review", profile_path="docs/review.txt",
                                    profile_sha256=digest(raw), allow_paths=["src/", "docs/"])
    if same_repo:
        policy_repo = case["repo"]
        (policy_repo / "gate-policy.json").write_bytes(canonical(document))
        selection = {"repo_path": str(policy_repo), "path": "gate-policy.json", "sha256": digest(canonical(document))}
    else:
        selection = policy_repository(tmp_path, document=document)
        policy_repo = tmp_path / selection["repo_path"]
    (policy_repo / "docs").mkdir(exist_ok=True)
    (policy_repo / "docs/review.txt").write_bytes(raw)
    if ignored:
        (policy_repo / ".gitignore").write_text("docs/review.txt\n", encoding="utf-8")
        command(policy_repo, "add", ".gitignore")
    command(policy_repo, "add", "--force", "gate-policy.json", "docs/review.txt")
    command(policy_repo, "commit", "-m", "Synthetic pinned historical profile")
    selection["commit"] = command(policy_repo, "rev-parse", "HEAD")
    suite = model_suite(case)
    suite["cases"][0].update(policy=selection, profile="project-review")
    return suite, policy_repo


def test_history_profile_uses_separate_policy_commit_not_dirty_file(gate_case, tmp_path):
    from test_history_evaluation import execute
    suite, policy_repo = history_profile_policy(gate_case, tmp_path)
    (policy_repo / "docs/review.txt").write_text("Dirty policy file is not authority.", encoding="utf-8")
    result, calls = execute(gate_case, suite, trials=1)
    assert result["cases"][0]["runs"][0]["status"] == "complete" and len(calls) == 1
    instructions = json.loads(calls[0].content)["instructions"]
    assert "approved cent-rounding rule" in instructions and "Dirty policy file" not in instructions


@pytest.mark.parametrize("same_repo", [False, True])
def test_history_profile_policy_commit_ignores_survive_dirty_removal(gate_case, tmp_path, monkeypatch, same_repo):
    from test_history_evaluation import execute
    suite, policy_repo = history_profile_policy(gate_case, tmp_path, ignored=True, same_repo=same_repo)
    (policy_repo / ".gitignore").write_text("", encoding="utf-8")
    monkeypatch.setattr("finassist.history_evaluation.prepare_model_request", lambda *a: pytest.fail("key access before profile ignore screening"))
    with pytest.raises(AssistantError, match="^gate_ignored_path$"):
        execute(gate_case, suite, trials=1)
    assert not gate_case["state"].exists()


def test_unrelated_source_file_cannot_replace_a_separate_policy_profile(gate_case, tmp_path):
    from test_history_evaluation import execute
    repo = gate_case["repo"]
    (repo / "docs").mkdir()
    (repo / "docs/review.txt").write_text("Source text is not policy instructions.", encoding="utf-8")
    command(repo, "add", "docs/review.txt")
    command(repo, "commit", "-m", "Synthetic unrelated source path")
    gate_case["head"] = command(repo, "rev-parse", "HEAD")
    suite, _ = history_profile_policy(gate_case, tmp_path)
    from test_providers_review import envelope
    def reviewed_all(packet):
        return envelope(json.dumps({"head": packet["head"], "summary": "Synthetic complete review.",
                                    "reviewed_paths": [f["path"] for f in packet["files"]], "findings": []}))
    result, calls = execute(gate_case, suite, handler=reviewed_all, trials=1)
    assert result["cases"][0]["runs"][0]["status"] == "complete" and len(calls) == 1
    instructions = json.loads(calls[0].content)["instructions"]
    assert "approved cent-rounding rule" in instructions and "Source text is not" not in instructions


def test_source_ignore_rule_does_not_name_separate_policy_file(gate_case, tmp_path):
    from test_history_evaluation import execute
    repo = gate_case["repo"]
    (repo / ".gitignore").write_text("docs/review.txt\n", encoding="utf-8")
    command(repo, "add", ".gitignore")
    change_policy(gate_case)
    suite, _ = history_profile_policy(gate_case, tmp_path)
    result, calls = execute(gate_case, suite, trials=1)
    assert result["cases"][0]["runs"][0]["status"] == "complete" and len(calls) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Windows short-name directory aliases")
@pytest.mark.parametrize("selection", ["source", "policy"])
def test_profile_guard_uses_repository_identity_across_short_names(gate_case, tmp_path, selection):
    import ctypes
    from ctypes import wintypes
    from pathlib import Path
    from test_history_evaluation import execute, model_suite
    file = profile_case(gate_case, allow_paths=["src/", "docs/"])
    file.write_text("Head cannot amend the profile.", encoding="utf-8")
    command(gate_case["repo"], "add", "docs/review.txt")
    command(gate_case["repo"], "commit", "-m", "Synthetic candidate profile edit")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    suite = model_suite(gate_case)
    case = suite["cases"][0]
    case["profile"] = "project-review"
    case["policy"].update(repo_path=str(gate_case["repo"]), commit=gate_case["base"])
    get_short_path = ctypes.WinDLL("kernel32", use_last_error=True).GetShortPathNameW
    get_short_path.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_short_path.restype = wintypes.DWORD
    needed = get_short_path(str(gate_case["repo"]), None, 0)
    assert needed, ctypes.get_last_error()
    buffer = ctypes.create_unicode_buffer(needed)
    written = get_short_path(str(gate_case["repo"]), buffer, needed)
    assert 0 < written < needed, ctypes.get_last_error()
    alias = Path(buffer.value)
    if alias == gate_case["repo"]:
        pytest.skip("Filesystem did not assign an 8.3 directory alias")
    assert alias.samefile(gate_case["repo"])
    target = case if selection == "source" else case["policy"]
    target["repo_path"] = str(alias)
    with pytest.raises(AssistantError, match="^gate_profile_change_requires_review$"):
        execute(gate_case, suite, trials=1)
    assert not gate_case["state"].exists()
