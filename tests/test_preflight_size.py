"""Synthetic doctor lower bounds; no provider calls or private repository inputs."""

from dataclasses import replace

import pytest

from conftest import command
from test_model_policy import model_policy
from finassist import config_preflight as config_module, onboarding, preflight_size, scope
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.model_gate import prepare_model_source
from finassist.model_policy import load_model_policy
from finassist.security import canonical, digest

CODE = "request_lower_bound_exceeded"


def text(size):
    return b"# " + b"x" * (size - 3) + b"\n"


@pytest.fixture
def change(repository):
    repo, _, _ = repository

    def make(before=None, after=None):
        before = before if before is not None else {"src/large.py": text(180), "src/small.py": text(40)}
        after = after if after is not None else {"src/large.py": text(200), "src/small.py": text(50)}
        for name, data in before.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_bytes(data)
        command(repo, "add", "-A")
        command(repo, "commit", "--allow-empty", "-m", "Synthetic size baseline")
        base = command(repo, "rev-parse", "HEAD")
        for name in before.keys() - after.keys():
            (repo / name).unlink()
        for name, data in after.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_bytes(data)
        command(repo, "add", "-A")
        command(repo, "commit", "--allow-empty", "-m", "Synthetic size candidate")
        return repo, base, command(repo, "rev-parse", "HEAD")

    return make


@pytest.fixture(params=["gate", "configuration"])
def route(request, tmp_path):
    kind = request.param

    def run(case, *, limit=469, file_limit=128, **settings):
        repo, base, head = case
        if kind == "gate":
            document = model_policy()
            document["model_review"].update(max_file_bytes=file_limit, max_request_bytes=limit, **settings)
            policy_file = tmp_path / "policy.json"
            policy_file.write_bytes(canonical(document))
            return onboarding.policy_preflight(repo, base, head, "", policy_file=str(policy_file),
                                               environment={"REVIEW_PROVIDER_KEY": "synthetic"})
        config = replace(Config(), allow_paths=("src/",), max_file_bytes=file_limit,
                         max_packet_bytes=limit, **settings)
        return config_module.config_preflight(repo, base, head, config, environment={})

    run.kind = kind
    run.module = onboarding if kind == "gate" else config_module
    return run


def lower(report):
    return [w for w in report["warnings"] if w["code"] == CODE]


def without_lower(report):
    return {**report, "warnings": [w for w in report["warnings"] if w["code"] != CODE]}


@pytest.mark.parametrize("limit,warns", [(469, True), (470, False), (471, False)])
def test_both_versions_and_included_files_form_a_strict_lower_bound(change, route, monkeypatch, limit, warns):
    case = change()
    report = route(case, limit=limit)
    assert report["status"] == "blocked"
    assert [b["code"] for b in report["blockers"]] == ["file_limit_exceeded"]
    assert bool(lower(report)) == warns
    if warns:
        warning = lower(report)[0]
        assert warning["lower_bound_bytes"] == 470
        assert warning["limit"] == limit
        assert warning["limit_setting"] == ("max_request_bytes" if route.kind == "gate" else "max_packet_bytes")
        assert len(warning["hint"]) <= 300
        assert all(name in warning["hint"] for name in
                   ("max_file_bytes", "max_request_bytes", "max_packet_bytes", "smaller range"))
    # Remove only the advisory: all previous report semantics are identical.
    with monkeypatch.context() as patch:
        patch.setattr(route.module, "size_warning", lambda *a: None)
        assert without_lower(report) == route(case, limit=limit)
    assert report["request"] is None
    assert not report["network_used"] and not report["key_values_returned"] and not report["ledger_opened"]


@pytest.mark.parametrize("before,after,total", [
    ({}, {"src/large.py": text(200)}, 200),
    ({"src/large.py": text(200)}, {}, 200),
    ({"src/large.py": text(180)}, {"src/renamed.py": text(200)}, 380),
])
def test_add_delete_and_rename_count_only_existing_versions(change, route, before, after, total):
    report = route(change(before, after), limit=total - 1)
    assert lower(report)[0]["lower_bound_bytes"] == total


def test_skip_and_report_does_not_count_an_oversized_file(change, route, monkeypatch):
    case = change({"src/large.py": text(30_000), "src/small.py": text(40)},
                  {"src/large.py": text(31_000), "src/small.py": text(50)})
    def unexpected(*args):
        pytest.fail("No size blockers remain: no lower-bound metadata should be read")
    monkeypatch.setattr(preflight_size, "git", unexpected)
    report = route(case, limit=20_000, unreviewable_paths="skip-and-report")
    assert not lower(report) and report["status"] == "ready"
    assert next(r for r in report["paths"] if r["path"] == "src/large.py")["status"] == "omitted"


def test_metadata_only_excludes_withheld_and_omitted_paths(change, route, monkeypatch):
    case = change({"src/large.py": text(180), "src/small.py": text(40),
                   "data/private.csv": text(1000), "src/image.png": text(1000)},
                  {"src/large.py": text(200), "src/small.py": text(50),
                   "data/private.csv": text(2000), "src/image.png": text(2000)})
    # Binary/private names are withheld under this setting, and must never be sized.
    real = preflight_size.git
    metadata = []
    def observed(repo, *args, **kwargs):
        assert args[:4] == ("--literal-pathspecs", "ls-tree", "-l", "-z")
        assert set(args[6:]) == {"src/large.py", "src/small.py"}
        metadata.append(args)
        return real(repo, *args, **kwargs)
    monkeypatch.setattr(preflight_size, "git", observed)
    report = route(case, private_paths="skip-and-report")
    assert lower(report)[0]["lower_bound_bytes"] == 470
    assert len(metadata) == 2
    assert all(r["status"] in {"withheld", "omitted"} for r in report["paths"]
               if r["path"] in {"data/private.csv", "src/image.png"})


@pytest.mark.parametrize("other", ["src/private.csv", "src/hidden.py"])
def test_another_path_refusal_suppresses_the_advisory(change, route, monkeypatch, other):
    value = text(50) if other.endswith(".csv") else "# hidden\u200b\n".encode()
    case = change(after={"src/large.py": text(200), "src/small.py": text(50), other: value})
    def unexpected(*args):
        pytest.fail("Other path blockers must suppress the lower-bound calculation")
    monkeypatch.setattr(preflight_size, "git", unexpected)
    report = route(case)
    assert not lower(report)
    assert len(report["blockers"]) > 1


def test_advisory_does_not_add_content_reads(change, route, monkeypatch):
    case = change()
    real = scope.git
    reads = []
    def observed(repo, *args, **kwargs):
        if args[:2] == ("cat-file", "blob"):
            reads.append(args[-1])
        return real(repo, *args, **kwargs)
    monkeypatch.setattr(scope, "git", observed)
    report = route(case)
    first = list(reads)
    reads.clear()
    with monkeypatch.context() as patch:
        patch.setattr(route.module, "size_warning", lambda *a: None)
        previous = route(case)
    assert reads == first and first
    assert without_lower(report) == previous


@pytest.mark.parametrize("failure", [AssistantError("git_read_failed"), ValueError("bad metadata"), OSError("read")])
def test_failed_metadata_is_only_a_missing_warning(change, route, monkeypatch, failure):
    case = change()
    def broken(*args, **kwargs):
        raise failure
    monkeypatch.setattr(preflight_size, "git", broken)
    report = route(case)
    assert not lower(report)
    assert [b["code"] for b in report["blockers"]] == ["file_limit_exceeded"]


def test_the_real_builders_still_refuse_the_same_file(change, route, tmp_path):
    repo, base, head = change()
    report = route((repo, base, head))
    assert lower(report) and report["status"] == "blocked"
    if route.kind == "configuration":
        with pytest.raises(AssistantError, match="file_limit_exceeded"):
            scope.build_packet(repo, base, head, replace(Config(), allow_paths=("src/",),
                                                        max_file_bytes=128, max_packet_bytes=469))
    else:
        # Pin policy at a new base, then recreate the exact two-file change above it.
        command(repo, "switch", "--detach", base)
        document = model_policy()
        document["model_review"].update(max_file_bytes=128, max_request_bytes=469)
        raw = canonical(document)
        (repo / "policy.json").write_bytes(raw)
        command(repo, "add", "policy.json")
        command(repo, "commit", "-m", "Synthetic pinned policy")
        pinned_base = command(repo, "rev-parse", "HEAD")
        (repo / "src/large.py").write_bytes(text(200))
        (repo / "src/small.py").write_bytes(text(50))
        command(repo, "add", "-A")
        command(repo, "commit", "-m", "Synthetic blocked change")
        pinned_head = command(repo, "rev-parse", "HEAD")
        policy = load_model_policy(repo, pinned_base, "policy.json", digest(raw))
        with pytest.raises(AssistantError, match="file_limit_exceeded"):
            prepare_model_source(repo, pinned_base, pinned_head, policy)


# A change with more files than the policy allows is never read. One run still names the request size it would need.

def _gate(case, tmp_path, **settings):
    repo, base, head = case
    document = model_policy()
    document["model_review"].update(**settings)
    policy_file = tmp_path / "count-policy.json"
    policy_file.write_bytes(canonical(document))
    return onboarding.policy_preflight(repo, base, head, "", policy_file=str(policy_file),
                                       environment={"REVIEW_PROVIDER_KEY": "synthetic"})


def _many(count, size, prefix="src/part"):
    return {f"{prefix}{index:02d}.py": text(size) for index in range(count)}


@pytest.mark.parametrize("limit,warns", [(799, True), (800, False)])
def test_too_many_files_still_name_the_request_bound(change, tmp_path, limit, warns):
    report = _gate(change({}, _many(4, 200)), tmp_path, max_files=3, max_request_bytes=limit)
    assert [b["code"] for b in report["blockers"]] == ["gate_file_count_exceeded"]
    assert {row["status"] for row in report["paths"]} == {"unchecked"}
    assert bool(lower(report)) == warns
    if warns:
        assert lower(report)[0]["lower_bound_bytes"] == 800 and lower(report)[0]["limit"] == limit
        assert lower(report)[0]["limit_setting"] == "max_request_bytes"


def test_both_versions_count_and_nothing_else_changes(change, tmp_path, monkeypatch):
    case = change(_many(4, 100), _many(4, 150))
    report = _gate(case, tmp_path, max_files=3, max_request_bytes=999)
    assert lower(report)[0]["lower_bound_bytes"] == 1000
    with monkeypatch.context() as patch:
        patch.setattr(onboarding, "size_warning", lambda *a, **k: None)
        assert without_lower(report) == _gate(case, tmp_path, max_files=3, max_request_bytes=999)


def test_the_bound_reads_no_changed_file(change, tmp_path, monkeypatch):
    case = change(_many(4, 100), _many(4, 200))
    repo, base, head = case
    changed = {command(repo, "rev-parse", f"{revision}:{name}") for revision in (base, head) for name in _many(4, 1)}
    real, reads = scope.git, []

    def observed(repo, *args, **kwargs):
        if args[:2] == ("cat-file", "blob"):
            reads.append(args[-1])
        return real(repo, *args, **kwargs)
    monkeypatch.setattr(scope, "git", observed)
    report = _gate(case, tmp_path, max_files=3, max_request_bytes=100)
    assert lower(report) and not changed & set(reads)


def test_files_withheld_by_name_do_not_count(change, tmp_path):
    files = {**_many(3, 200), "data/private.csv": text(5000)}
    report = _gate(change({}, files), tmp_path, max_files=3, max_request_bytes=500, private_paths="skip-and-report")
    assert next(r for r in report["paths"] if r["path"] == "data/private.csv")["status"] == "withheld"
    assert lower(report)[0]["lower_bound_bytes"] == 600


def test_an_ignored_file_means_no_bound(repository, tmp_path):
    repo, _, _ = repository
    (repo / ".gitignore").write_text("src/ignored.py\n", encoding="utf-8")
    command(repo, "add", ".gitignore")
    command(repo, "commit", "-m", "Synthetic ignore rule")
    base = command(repo, "rev-parse", "HEAD")
    for name, data in {**_many(3, 200), "src/ignored.py": text(200)}.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_bytes(data)
    command(repo, "add", "--force", "--", "src")
    command(repo, "commit", "-m", "Synthetic change with an ignored file")
    report = _gate((repo, base, command(repo, "rev-parse", "HEAD")), tmp_path, max_files=3, max_request_bytes=100)
    assert "gate_file_count_exceeded" in [b["code"] for b in report["blockers"]] and not lower(report)


def test_a_rule_file_change_means_no_bound(change, tmp_path):
    case = change({".gitignore": b"build/\n"}, {".gitignore": b"!keep/\n", **_many(4, 200)})
    report = _gate(case, tmp_path, max_files=3, max_request_bytes=100)
    assert "gate_ignore_change_requires_review" in [b["code"] for b in report["blockers"]] and not lower(report)


def test_failed_metadata_is_only_a_missing_warning_here_too(change, tmp_path, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("read")
    monkeypatch.setattr(preflight_size, "git", broken)
    report = _gate(change({}, _many(4, 200)), tmp_path, max_files=3, max_request_bytes=100)
    assert [b["code"] for b in report["blockers"]] == ["gate_file_count_exceeded"] and not lower(report)
