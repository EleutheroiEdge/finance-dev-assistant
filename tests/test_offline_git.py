"""Actual local partial clones and replacement refs must not alter offline reads."""

from functools import partial

import pytest

from conftest import command
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.history_suite import plan_history
from finassist.scope import build_packet, read_blob, resolve
from test_history_suite import history_suite


@pytest.fixture
def partial_clone(repository):
    source, base, head = repository
    command(source, "config", "uploadpack.allowFilter", "true")
    clone = source.parent / "partial"
    command(source.parent, "clone", "--no-checkout", "--filter=blob:none", source.as_uri(), str(clone))
    missing = command(clone, "rev-list", "--objects", "--missing=print", "--all")
    assert any(line.startswith("?") for line in missing.splitlines())
    return clone, base, head


def packs(repo):
    return {p.name: p.read_bytes() for p in (repo / ".git/objects/pack").iterdir()}


def test_partial_clone_history_refuses_without_fetching_or_changing_packs(partial_clone):
    clone, _, _ = partial_clone
    before = packs(clone)
    with pytest.raises(AssistantError) as caught:
        plan_history(history_suite(partial_clone), clone.parent, Config())
    assert caught.value.code in {"git_partial_clone_unsupported", "git_read_failed"}
    assert packs(clone) == before
    missing = command(clone, "rev-list", "--objects", "--missing=print", "--all")
    assert any(line.startswith("?") for line in missing.splitlines())


def test_upstream_only_commit_is_never_lazily_resolved(repository, partial_clone):
    source, _, _ = repository
    clone, _, _ = partial_clone
    (source / "src/cash.py").write_text("upstream only\n", encoding="utf-8")
    command(source, "add", "src/cash.py")
    command(source, "commit", "-m", "Synthetic upstream-only revision")
    sha = command(source, "rev-parse", "HEAD")
    before = packs(clone)
    with pytest.raises(AssistantError) as caught:
        resolve(clone, sha)
    assert caught.value.code in {"git_partial_clone_unsupported", "git_commit_unavailable"}
    assert packs(clone) == before


@pytest.mark.parametrize("key,value", [
    ("remote.origin.promisor", "false"),
    ("remote.example.partialclonefilter", "blob:none"),
    ("extensions.partialclone", "origin"),
])
def test_git_without_lazy_fetch_guard_refuses_each_partial_config(repository, monkeypatch, key, value):
    import finassist.scope as scope
    repo, base, _ = repository
    monkeypatch.setattr(scope, "_supports_no_lazy_fetch", lambda _exe: False)
    command(repo, "config", key, value)
    with pytest.raises(AssistantError, match="^git_partial_clone_unsupported$"):
        read_blob(repo, base, "src/cash.py", 48000)


def test_replacement_blob_cannot_change_frozen_source(repository):
    repo, base, head = repository
    original = read_blob(repo, head, "src/cash.py", 48000)
    packet = build_packet(repo, base, head, Config())
    old = command(repo, "rev-parse", head + ":src/cash.py")
    (repo / "replacement.txt").write_text("replacement must be ignored\n", encoding="utf-8")
    replacement = command(repo, "hash-object", "-w", "replacement.txt")
    command(repo, "replace", old, replacement)
    assert command(repo, "replace", "-l") == old
    assert read_blob(repo, head, "src/cash.py", 48000) == original
    assert build_packet(repo, base, head, Config()) == packet


def test_replacement_commit_cannot_change_frozen_tree(repository):
    repo, base, head = repository
    original = build_packet(repo, base, head, Config())
    (repo / "src/cash.py").write_text("replacement tree\n", encoding="utf-8")
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Synthetic replacement commit")
    command(repo, "replace", head, command(repo, "rev-parse", "HEAD"))
    assert build_packet(repo, base, head, Config()) == original


@pytest.mark.parametrize("status,expected", [(0, True), (129, False), (2, None)])
def test_lazy_fetch_capability_probe_is_bounded_and_fail_closed(monkeypatch, status, expected):
    import subprocess
    import finassist.scope as scope
    calls = []
    def probe(argv, **kwargs):
        calls.append(argv)
        assert argv == ["synthetic-git", "--no-lazy-fetch", "--version"]
        assert kwargs["timeout"] == 10
        assert kwargs["env"]["GIT_NO_LAZY_FETCH"] == "1"
        return subprocess.CompletedProcess(argv, status)
    monkeypatch.setattr(scope.subprocess, "run", probe)
    scope._supports_no_lazy_fetch.cache_clear()
    try:
        if expected is None:
            with pytest.raises(AssistantError, match="^git_capability_check_failed$"):
                scope._supports_no_lazy_fetch("synthetic-git")
        else:
            assert scope._supports_no_lazy_fetch("synthetic-git") is expected
            assert scope._supports_no_lazy_fetch("synthetic-git") is expected
            assert len(calls) == 1
    finally:
        scope._supports_no_lazy_fetch.cache_clear()


@pytest.mark.parametrize("stage,code", [("probe", "git_capability_check_failed"), ("config", "git_read_failed"), ("resolve", "git_read_failed")])
@pytest.mark.parametrize("kind", ["os", "timeout"])
def test_git_preflight_process_failures_have_named_codes(tmp_path, monkeypatch, stage, code, kind):
    import subprocess
    import finassist.scope as scope
    error = OSError("synthetic") if kind == "os" else subprocess.TimeoutExpired("synthetic", 10)
    def fail(*args, **kwargs):
        raise error
    scope._supports_no_lazy_fetch.cache_clear()
    monkeypatch.setattr(scope.subprocess, "run", fail)
    if stage == "config":
        monkeypatch.setattr(scope, "_supports_no_lazy_fetch", lambda _: False)
        call = partial(scope._offline_git_options, tmp_path, "synthetic-git")
    elif stage == "resolve":
        monkeypatch.setattr(scope, "git_command", lambda *args: ["synthetic-git"])
        call = partial(scope.resolve, tmp_path, "1" * 40)
    else:
        call = partial(scope._supports_no_lazy_fetch, "synthetic-git")
    with pytest.raises(AssistantError, match="^" + code + "$"):
        call()


def test_nonrepo_and_missing_commit_have_distinct_codes(repository, tmp_path):
    repo, _, _ = repository
    with pytest.raises(AssistantError, match="^git_commit_unavailable$"):
        resolve(repo, "1" * 40)
    nonrepo = tmp_path / "not-a-repo"
    nonrepo.mkdir()
    with pytest.raises(AssistantError, match="^git_read_failed$"):
        resolve(nonrepo, "1" * 40)


def test_corrupt_config_does_not_masquerade_as_missing_commit(repository):
    repo, base, _ = repository
    (repo / ".git/config").write_text("[broken", encoding="utf-8")
    with pytest.raises(AssistantError, match="^git_read_failed$"):
        resolve(repo, base)
