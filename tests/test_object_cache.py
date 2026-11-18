"""Git reads addressed by a full object ID run once per command; nothing else is remembered, nothing outlives it."""

import contextvars
import threading

import pytest

import finassist.scope as scope
from finassist.config import Config

PATH = "src/cash.py"


def _counting(monkeypatch):
    calls = []
    real = scope._run_git

    def counting(repo, *args, binary=False):
        calls.append(args)
        return real(repo, *args, binary=binary)

    monkeypatch.setattr(scope, "_run_git", counting)
    return calls


def test_reads_by_object_id_run_once_within_a_command(repository, monkeypatch):
    repo, _base, head = repository
    calls = _counting(monkeypatch)
    with scope.object_cache():
        first = scope.read_entry(repo, head, PATH, 100_000, Config())
        once = len(calls)
        second = scope.read_entry(repo, head, PATH, 100_000, Config())
    assert first == second and first[0] is not None
    assert once == 3 and len(calls) == once  # ls-tree, cat-file -s, cat-file blob; then nothing.
    # Outside a command nothing is remembered.
    scope.read_entry(repo, head, PATH, 100_000, Config())
    assert len(calls) == once + 3


def test_a_read_that_names_a_ref_is_never_remembered(repository, monkeypatch):
    repo, _base, _head = repository
    calls = _counting(monkeypatch)
    with scope.object_cache():
        for _ in range(2):
            scope.git(repo, "rev-parse", "HEAD")
            scope.git(repo, "cat-file", "-s", "HEAD:" + PATH)
            scope.git(repo, "--literal-pathspecs", "ls-tree", "-z", "HEAD", "--", PATH, binary=True)
    assert len(calls) == 6


def test_output_past_the_byte_limit_is_not_remembered(repository, monkeypatch):
    repo, _base, head = repository
    calls = _counting(monkeypatch)
    monkeypatch.setattr(scope, "_OBJECT_BYTES", 8)
    with scope.object_cache():
        scope.read_entry(repo, head, PATH, 100_000, Config())
        scope.read_entry(repo, head, PATH, 100_000, Config())
    # Only the size fits under the limit; the tree entry and the content are read again.
    assert len(calls) == 5


def test_nothing_is_kept_after_the_command(repository):
    repo, _base, head = repository
    with scope.object_cache():
        scope.read_entry(repo, head, PATH, 100_000, Config())
        assert scope._OBJECTS.get().reads
    assert scope._OBJECTS.get() is None


def test_a_context_copied_inside_the_command_does_not_outlive_it(repository, monkeypatch):
    repo, _base, head = repository
    calls = _counting(monkeypatch)
    with scope.object_cache():
        scope.read_entry(repo, head, PATH, 100_000, Config())
        copied = contextvars.copy_context()
        copied.run(scope.read_entry, repo, head, PATH, 100_000, Config())
        assert len(calls) == 3  # inside the command the copy shares what was remembered
    copied.run(scope.read_entry, repo, head, PATH, 100_000, Config())
    copied.run(scope.read_entry, repo, head, PATH, 100_000, Config())
    assert len(calls) == 9  # after it, the copy runs Git every time
    remembered = copied.run(scope._OBJECTS.get)
    assert remembered.open is False and remembered.reads == {} and remembered.size == 0


def test_a_read_that_ends_after_the_command_leaves_nothing_behind(repository, monkeypatch):
    # The command ends while a read is running: the read returns its output, and nothing is remembered.
    repo, _base, head = repository
    real = scope._run_git
    with scope.object_cache():
        remembered = scope._OBJECTS.get()

        def closing(repo_, *args, binary=False):
            try:
                return real(repo_, *args, binary=binary)
            finally:
                remembered.open = False  # what closing the scope does, without its lock
                remembered.reads.clear()

        monkeypatch.setattr(scope, "_run_git", closing)
        entry = scope.read_entry(repo, head, PATH, 100_000, Config())
        assert entry[0] is not None
        assert remembered.open is False and remembered.reads == {}


def test_a_thread_started_inside_the_command_reads_again_after_it(repository, monkeypatch):
    repo, _base, head = repository
    calls = _counting(monkeypatch)
    ended = threading.Event()
    seen = []

    def later():
        ended.wait(10)
        scope.read_entry(repo, head, PATH, 100_000, Config())
        scope.read_entry(repo, head, PATH, 100_000, Config())
        seen.append(scope._OBJECTS.get().reads)

    with scope.object_cache():
        scope.read_entry(repo, head, PATH, 100_000, Config())
        worker = threading.Thread(target=contextvars.copy_context().run, args=(later,))
        worker.start()
    ended.set()
    worker.join(10)
    assert not worker.is_alive()
    assert len(calls) == 9 and seen == [{}]


@pytest.mark.parametrize("args", [("cat-file", "-s", "a" * 39), ("cat-file", "blob", "HEAD"),
                                  ("--literal-pathspecs", "ls-tree", "-z", "main", "--", PATH)])
def test_only_a_full_object_id_counts_as_addressed_by_object(args):
    assert not scope._addressed_by_object(args)
