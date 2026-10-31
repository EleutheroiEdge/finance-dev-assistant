from copy import deepcopy
from pathlib import Path

import pytest

from conftest import command, synthetic_symlink
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.history_suite import plan_history, source_identity, validate_history_suite
from finassist.security import canonical


def history_suite(repository):
    repo, base, head = repository
    return {"version": 1, "cases": [{"id": "held-out-case-marker", "repo_path": repo.name,
            "base_sha": base, "head_sha": head, "profile": "finance-saas",
            "expected": [{"label": "held-out-target-marker", "paths": ["src/cash.py"], "severity": "high"}],
            "negative_control": False}]}


def test_history_plan_is_local_deterministic_and_label_free(repository, monkeypatch):
    repo, _, _ = repository
    suite = history_suite(repository)
    monkeypatch.chdir(repo / "src")
    first = plan_history(suite, repo.parent, Config(), trials=2)
    second = plan_history(suite, repo.parent, Config(), trials=2)
    assert first == second
    packet = first["cases"][0]["packet"]
    serialized = canonical(packet).decode()
    assert "held-out-case-marker" not in serialized and "held-out-target-marker" not in serialized
    assert str(repo) not in serialized and "negative_control" not in serialized
    assert not first["network_authorized"]
    assert first["plan_hash"] != plan_history(suite, repo.parent, Config(), trials=3)["plan_hash"]
    altered = deepcopy(suite)
    altered["cases"][0]["expected"][0]["severity"] = "critical"
    changed = plan_history(altered, repo.parent, Config(), trials=2)
    assert changed["suite_hash"] != first["suite_hash"]
    assert changed["cases"][0]["packet"] == packet
    other_profile = deepcopy(packet)
    other_profile["profile"] = "another-profile"
    assert source_identity(other_profile) == source_identity(packet)


@pytest.mark.parametrize("trials", [True, 0, 21, 1.5])
def test_trials_are_bounded(repository, trials):
    with pytest.raises(AssistantError, match="history_suite_invalid"):
        validate_history_suite(history_suite(repository), trials=trials)


@pytest.mark.parametrize("field,value", [
    ("base_sha", "main"), ("head_sha", "HEAD"), ("repo_path", "https://example.invalid/repo"),
    ("negative_control", 1), ("expected", []),
])
def test_invalid_cases_rejected_before_reading_source(repository, field, value):
    suite = history_suite(repository)
    suite["cases"][0][field] = value
    with pytest.raises(AssistantError):
        plan_history(suite, Path("unavailable"), Config())


def test_duplicate_cases_and_labels_rejected(repository):
    suite = history_suite(repository)
    suite["cases"].append(deepcopy(suite["cases"][0]))
    with pytest.raises(AssistantError, match="history_identity_invalid"):
        validate_history_suite(suite)
    suite = history_suite(repository)
    suite["cases"][0]["expected"] *= 2
    with pytest.raises(AssistantError, match="history_expected_invalid"):
        validate_history_suite(suite)


def test_no_missing_commit_fetch_or_checkout(repository, monkeypatch):
    repo, _, head = repository
    suite = history_suite(repository)
    suite["cases"][0]["base_sha"] = "1" * 40
    (repo / "src/cash.py").write_text("dirty but preserved\n")
    import finassist.scope as scope
    original = scope.git_command
    def checked(*args, **kwargs):
        assert not {"fetch", "checkout", "switch", "pull"} & set(map(str, args))
        return original(*args, **kwargs)
    monkeypatch.setattr(scope, "git_command", checked)
    with pytest.raises(AssistantError):
        plan_history(suite, repo.parent, Config())
    assert command(repo, "rev-parse", "HEAD") == head
    assert (repo / "src/cash.py").read_text() == "dirty but preserved\n"


def test_expected_paths_must_be_in_complete_review_scope(repository):
    repo, _, _ = repository
    suite = history_suite(repository)
    suite["cases"][0]["expected"][0]["paths"] = ["src/unchanged.py"]
    with pytest.raises(AssistantError, match="history_expected_outside_scope"):
        plan_history(suite, repo.parent, Config())
    suite["cases"][0]["expected"][0]["paths"] = ["clients/profile.py"]
    with pytest.raises(AssistantError, match="gate_private_path"):
        validate_history_suite(suite)


def test_current_ignore_cannot_be_bypassed(repository):
    repo, _, _ = repository
    (repo / ".gitignore").write_text("src/cash.py\n")
    with pytest.raises(AssistantError, match="gate_ignored_path"):
        plan_history(history_suite(repository), repo.parent, Config())


def test_repository_links_refused(repository):
    repo, _, _ = repository
    link = repo.parent / "alias"
    synthetic_symlink(link, repo, target_is_directory=True)
    suite = history_suite(repository)
    suite["cases"][0]["repo_path"] = "alias"
    with pytest.raises(AssistantError, match="linked_path"):
        plan_history(suite, repo.parent, Config())


def test_published_history_suite_validates_with_two_negative_controls():
    import json
    suite = json.loads((Path(__file__).parents[1] / "examples/history-cases.json").read_text(encoding="utf-8"))
    assert len(validate_history_suite(suite)) == 64
    assert sum(case["negative_control"] for case in suite["cases"]) >= 2
