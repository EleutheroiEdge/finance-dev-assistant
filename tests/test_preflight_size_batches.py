"""Batched doctor metadata stays bounded and independent of Git output order."""

import subprocess

import pytest

from finassist import preflight_size
from finassist.errors import AssistantError
from finassist.scope import git_command, git_environment
from test_preflight_size import lower, text

pytest_plugins = ("test_preflight_size",)


def test_forty_five_changed_files_need_two_size_reads(change, route, monkeypatch):
    before = {f"src/file{i:02}.py": text(180 if i == 0 else 40) for i in range(45)}
    after = {f"src/file{i:02}.py": text(200 if i == 0 else 50) for i in range(45)}
    case = change(before, after)
    total = 380 + 44 * 90
    real, calls = preflight_size.git, []
    def observed(repo, *args, **kwargs):
        assert args[:4] == ("--literal-pathspecs", "ls-tree", "-l", "-z")
        assert set(args[6:]) == set(before)
        calls.append(args)
        return real(repo, *args, **kwargs)
    monkeypatch.setattr(preflight_size, "git", observed)
    settings = {"max_files": 100} if route.kind == "gate" else {}
    report = route(case, limit=total - 1, **settings)
    assert lower(report)[0]["lower_bound_bytes"] == total
    assert len(calls) == 2
    assert {c[4] for c in calls} == set(case[1:])


def test_long_argument_lists_use_bounded_batches(change, route, monkeypatch):
    case = change()
    real, calls = preflight_size.git, []
    monkeypatch.setattr(preflight_size, "_PATH_ARGUMENT_BUDGET", 30)
    def observed(repo, *args, **kwargs):
        assert sum(2 * len(p.encode("utf-8")) + 3 for p in args[6:]) <= 30
        calls.append(args)
        return real(repo, *args, **kwargs)
    monkeypatch.setattr(preflight_size, "git", observed)
    report = route(case)
    assert lower(report)[0]["lower_bound_bytes"] == 470
    assert len(calls) == 4


def test_matches_literal_names_in_tree_order_and_one_sided_files(repository, monkeypatch):
    # The helper sees already classified names. Delimiters and Unicode must not
    # confuse its metadata parser; paths are not parsed as shell arguments.
    before = {"src/zeta.py": text(180), "src/a\tname.py": text(40)}
    after = {"src/zeta.py": text(200), "src/unicode-\u00e9.py": text(50)}
    repo = repository[0]
    # A tab is legal in Git's tree but not in a Windows working-tree filename.
    # Construct the exact objects without trying to materialize that filename.
    def plumbing(*args, data=None):
        return subprocess.run(git_command(repo, *args), input=data, capture_output=True,
                              env=git_environment(), timeout=30, check=True).stdout.strip()
    def revision(files):
        entries = []
        for name, content in files.items():
            blob = plumbing("hash-object", "-w", "--stdin", data=content)
            entries.append(b"100644 blob " + blob + b"\t" + name.removeprefix("src/").encode())
        source = plumbing("mktree", "-z", data=b"\0".join(entries) + b"\0")
        root = plumbing("mktree", "-z", data=b"040000 tree " + source + b"\tsrc\0")
        return plumbing("commit-tree", root.decode(), "-m", "Synthetic filename metadata").decode()
    base, head = revision(before), revision(after)
    paths = ["src/zeta.py", "src/unicode-\u00e9.py", "src/a\tname.py"]
    rows = [{"status": "refused", "code": "file_limit_exceeded"}, {"status": "included"}, {"status": "included"}]
    real, calls = preflight_size.git, []
    def observed(repo, *args, **kwargs):
        assert list(args[6:]) == paths
        raw = real(repo, *args, **kwargs)
        names = [entry.split(b"\t", 1)[1] for entry in raw.split(b"\0")[:-1]]
        assert names == sorted(names)
        calls.append(args)
        return raw
    monkeypatch.setattr(preflight_size, "git", observed)
    warning = preflight_size.size_warning(repo, (base, head), paths, rows, 469, "max_packet_bytes")
    assert warning["lower_bound_bytes"] == 470 and len(calls) == 2


@pytest.mark.parametrize("bad", ["link", "tree", "unexpected", "duplicate", "size", "negative", "truncated", "header"])
def test_invalid_entry_drops_the_whole_advisory(change, route, monkeypatch, bad):
    case = change()
    def invalid(repo, *args, **kwargs):
        name = args[6].encode()
        header = b"100644 blob " + b"a" * 40 + b" 180"
        if bad == "link":
            header = header.replace(b"100644", b"120000")
        elif bad == "tree":
            header = header.replace(b"100644 blob", b"040000 tree")
        elif bad == "unexpected":
            name = b"src/not-requested.py"
        elif bad == "size":
            header = header.replace(b"180", b"unknown")
        elif bad == "negative":
            header = header.replace(b"180", b"-1")
        elif bad == "header":
            header = b"missing fields"
        record = header + b"\t" + name + b"\0"
        if bad == "duplicate":
            record += record
        if bad == "truncated":
            record = record[:-1]
        return record
    monkeypatch.setattr(preflight_size, "git", invalid)
    report = route(case)
    assert not lower(report)
    assert [b["code"] for b in report["blockers"]] == ["file_limit_exceeded"]


def test_later_chunk_failure_does_not_keep_a_partial_warning(change, route, monkeypatch):
    case = change()
    real, calls = preflight_size.git, []
    monkeypatch.setattr(preflight_size, "_PATH_ARGUMENT_BUDGET", 30)
    def failing(repo, *args, **kwargs):
        calls.append(args)
        if len(calls) == 2:
            raise AssistantError("git_read_failed")
        return real(repo, *args, **kwargs)
    monkeypatch.setattr(preflight_size, "git", failing)
    report = route(case, limit=1)
    assert len(calls) == 2 and not lower(report)
    assert [b["code"] for b in report["blockers"]] == ["file_limit_exceeded"]


def test_unbounded_single_argument_is_never_dispatched(monkeypatch, tmp_path):
    def unexpected(*args, **kwargs):
        pytest.fail("Argument cannot fit: do not dispatch Git")
    monkeypatch.setattr(preflight_size, "git", unexpected)
    assert preflight_size.size_warning(
        tmp_path, ("before", "after"), ["x" * 4000],
        [{"status": "refused", "code": "file_limit_exceeded"}], 1, "max_packet_bytes"
    ) is None
