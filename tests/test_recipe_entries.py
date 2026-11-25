"""How a local recipe's program path is read: entries that can't be read, junctions, the implied .exe."""

from dataclasses import replace
import os
from pathlib import Path
import shutil

import pytest

from test_recipe_python import _path, _program, _refused, _repository, _run, _track
from finassist import runner
from finassist.config import Config
from finassist.errors import AssistantError


@pytest.fixture
def captured(monkeypatch):
    """Record each argv the runner would start, and report a passing run without starting it."""
    calls = []

    def fake(argv, *, cwd, env, timeout, max_bytes=1_000_000):
        calls.append(list(argv))
        return {"exit_code": 0, "timed_out": False, "output_limit_exceeded": False, "passed": True,
                "output": "", "elapsed_seconds": 0.0}

    monkeypatch.setattr(runner, "run_bounded", fake)
    return calls


_BOUND_BY_PERMISSIONS = pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0, reason="needs POSIX permission bits that bind the account running the tests")


@_BOUND_BY_PERMISSIONS
def test_a_program_below_a_folder_that_cannot_be_searched_is_refused(tmp_path, monkeypatch, captured):
    # What is below the folder can't be read, so it can't be told whether an entry there is a link.
    locked = tmp_path / "locked"
    tool = _program(locked, "tool")
    locked.chmod(0)
    try:
        with pytest.raises(AssistantError) as caught:
            runner._entries(str(tool))
        assert caught.value.code == "recipe_program_not_found"
        with pytest.raises(AssistantError) as caught:
            _run(Config(), tmp_path, [str(tool), "--check"])
        assert caught.value.code == "recipe_program_not_found"
        assert caught.value.public_details == {"program": str(tool)[:64]}
        with pytest.raises(AssistantError) as caught:
            _run(replace(Config(), recipe_python=str(tool)), tmp_path, ["python", "-V"])
        assert caught.value.code == "recipe_python_not_found"
        # On PATH, the folder is passed over as the system's own search passes over it.
        _path(monkeypatch, locked)
        with pytest.raises(AssistantError) as caught:
            _run(Config(), tmp_path, ["tool", "--check"])
        assert caught.value.code == "recipe_program_not_found"
    finally:
        locked.chmod(0o755)
    assert captured == []


@pytest.mark.skipif(os.name == "nt", reason="Windows reports a name that is too long as a missing path")
def test_a_name_too_long_to_read_is_refused(tmp_path, captured):
    program = str(tmp_path / ("n" * 300) / "tool")
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, [program])
    assert caught.value.code == "recipe_program_not_found"
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=program), tmp_path, ["python", "-V"])
    assert caught.value.code == "recipe_python_not_found"
    assert captured == []


@_BOUND_BY_PERMISSIONS
def test_a_repository_listing_that_cannot_be_read_is_refused(tmp_path, captured):
    repo = _repository(tmp_path / "project")
    environment = _program(repo / ".venv" / "bin", "python")
    config = replace(Config(), recipe_python=str(environment))
    _run(config, tmp_path, ["python", "-V"], repo=repo)
    repo.chmod(0o300)  # entries can be reached by name, but their names can't be listed
    try:
        with pytest.raises(AssistantError) as caught:
            runner._names(repo, repo / ".venv")
        assert caught.value.code == "recipe_program_inside_change"
        # Git may itself decline to work in such a folder; either way nothing runs.
        with pytest.raises(AssistantError) as caught:
            _run(config, tmp_path, ["python", "-V"], repo=repo)
        assert caught.value.code in {"recipe_program_inside_change", "git_read_failed"}
    finally:
        repo.chmod(0o755)
    assert captured == [[str(environment), "-V"]]


@_BOUND_BY_PERMISSIONS
def test_a_listed_entry_that_cannot_be_read_is_refused(tmp_path):
    # The names can be listed but not the entries: one of them could be the child under a second name.
    listing = tmp_path / "listing"
    (listing / "other").mkdir(parents=True)
    child = tmp_path / "child"
    child.mkdir()
    assert runner._names(listing, child) == {"child"}
    assert runner._names(listing, tmp_path / "missing") == {"missing"}
    listing.chmod(0o600)
    try:
        with pytest.raises(AssistantError) as caught:
            runner._names(listing, child)
        assert caught.value.code == "recipe_program_inside_change"
        # The child itself can't be read either: not the same as a child that is missing.
        with pytest.raises(AssistantError) as caught:
            runner._names(tmp_path, listing / "other")
        assert caught.value.code == "recipe_program_inside_change"
    finally:
        listing.chmod(0o755)


def test_what_an_entry_is_comes_from_its_own_record(tmp_path, monkeypatch):
    # The same answers on every system and Python version: the record is given here, not read from a disk.
    import errno
    import stat as modes
    from types import SimpleNamespace

    def record(mode, tag=None):
        return SimpleNamespace(st_mode=mode, **({} if tag is None else {"st_reparse_tag": tag}))

    entry = tmp_path / "entry"
    junction, alias, other = 0xA0000003, 0x8000001B, 0xA000001D
    for found, expected in (
            (record(modes.S_IFLNK | 0o777), True), (record(modes.S_IFDIR | 0o777, junction), True),
            (record(modes.S_IFDIR | 0o755), False), (record(modes.S_IFDIR | 0o755, 0), False),
            (record(modes.S_IFREG | 0o755, alias), False),
            (FileNotFoundError(errno.ENOENT, "synthetic"), False),
            (NotADirectoryError(errno.ENOTDIR, "synthetic"), False)):
        with monkeypatch.context() as patch:
            patch.setattr(os, "lstat", lambda item, found=found: _give(found))
            assert runner._is_link(entry) is expected, found
    for found in (record(modes.S_IFDIR | 0o755, other), record(modes.S_IFREG | 0o644, 0x80000017),
                  PermissionError(errno.EACCES, "synthetic"), OSError(errno.ENAMETOOLONG, "synthetic"),
                  OSError(errno.EIO, "synthetic")):
        with monkeypatch.context() as patch:
            patch.setattr(os, "lstat", lambda item, found=found: _give(found))
            with pytest.raises(OSError):
                runner._is_link(entry)
            with pytest.raises(AssistantError) as caught:
                runner._entries(str(entry))
        assert caught.value.code == "recipe_program_not_found", found


def _give(found):
    if isinstance(found, BaseException):
        raise found
    return found


def test_the_implied_exe_is_named_before_the_path_is_resolved(tmp_path):
    program = str(tmp_path / "outside" / "check")
    assert runner._readings(program, windows=False) == {program, os.path.abspath(program), os.path.realpath(program)}
    assert runner._readings(program, windows=True) == {
        program, os.path.abspath(program), os.path.realpath(program),
        program + ".exe", os.path.abspath(program + ".exe"), os.path.realpath(program + ".exe")}
    # Windows drops trailing dots and spaces before it adds the suffix; a name with a suffix gets none.
    assert program + ".exe" in runner._readings(program + ". .", windows=True)
    assert not any(item.endswith(".exe") for item in runner._readings(program + ".com", windows=True))


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_the_exe_a_suffixless_path_runs_is_resolved_under_its_own_name(tmp_path, monkeypatch, captured):
    # The Windows rule, read on this system: outside/check runs outside/check.exe, a link to a tracked
    # program that only the system's own resolution of that name finds.
    repo = _repository(tmp_path / "project")
    tool = _program(repo / "tools", "python")
    _track(repo, "tools/" + tool.name)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "check.exe").symlink_to(tool)
    original = runner._readings
    monkeypatch.setattr(runner, "_readings", lambda program: original(program, windows=True))
    monkeypatch.setattr(runner, "_is_link", lambda item: False)
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, [str(tmp_path / "outside" / "check")], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"
    assert captured == []


@pytest.mark.skipif(os.name != "nt", reason="the implied .exe is a Windows rule")
def test_windows_resolves_the_exe_a_suffixless_path_runs(tmp_path, monkeypatch, captured):
    repo = _repository(tmp_path / "project")
    tool = _program(repo / "tools", "python")
    _track(repo, "tools/" + tool.name)
    (tmp_path / "outside").mkdir()
    try:
        (tmp_path / "outside" / "check.exe").symlink_to(tool)
    except OSError:
        pytest.skip("this account may not create symbolic links")
    # Only the system's own resolution of check.exe can find the tracked program here.
    monkeypatch.setattr(runner, "_is_link", lambda item: False)
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, [str(tmp_path / "outside" / "check")], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"
    assert captured == []


_JUNCTIONS = pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows kind of link")


def _junction(link: Path, target: Path) -> None:
    """A directory junction at link, which any Windows account may create, unlike a symbolic link."""
    import _winapi
    import stat

    _winapi.CreateJunction(str(target), str(link))
    assert os.lstat(link).st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT and not link.is_symlink()


def _tracked_junction(repo: Path, name: str, target: Path) -> None:
    """A top-level entry that Git tracks and that is a junction on disk.

    It is tracked as a folder first and then replaced, so the test does not depend on how Git reads a junction.
    """
    (repo / name).mkdir()
    (repo / name / "keep").write_text("synthetic\n", encoding="utf-8")
    _track(repo, name + "/keep")
    shutil.rmtree(repo / name)
    _junction(repo / name, target)


@_JUNCTIONS
def test_windows_a_chain_of_junctions_is_followed_one_hop_at_a_time(tmp_path, captured):
    # outside\alias-bin -> project\bin, a tracked entry that is itself a junction -> elsewhere\real-bin.
    tool = _program(tmp_path / "elsewhere" / "real-bin", "python")
    repo = _repository(tmp_path / "project")
    _tracked_junction(repo, "bin", tool.parent)
    (tmp_path / "outside").mkdir()
    _junction(tmp_path / "outside" / "alias-bin", repo / "bin")
    program = tmp_path / "outside" / "alias-bin" / tool.name
    assert program.is_file()  # the system does reach the program this way
    assert {tmp_path / "outside" / "alias-bin", repo / "bin", tool} <= runner._entries(str(program))
    assert _refused(tmp_path, program, repo) == "recipe_program_inside_change"
    assert _refused(tmp_path, repo / "bin" / tool.name, repo) == "recipe_program_inside_change"
    assert captured == []
    # The program under its own name is not one the change supplies.
    _run(replace(Config(), recipe_python=str(tool)), tmp_path, ["python", "-V"], repo=repo)
    assert captured == [[str(tool), "-V"]]


@_JUNCTIONS
def test_windows_dot_dot_after_a_junction_goes_up_from_its_target(tmp_path, captured):
    repo = _repository(tmp_path / "project")
    tool = _program(repo / "tools", "python")
    _track(repo, "tools/" + tool.name)
    (repo / "sub").mkdir()
    planted = _program(tmp_path / "snapshot" / "bin", "python")
    (tmp_path / "snapshot" / "sub").mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _junction(elsewhere / "into-repo", repo / "sub")
    _junction(elsewhere / "into-snapshot", tmp_path / "snapshot" / "sub")
    for link, rest in (("into-repo", ("tools", tool.name)), ("into-snapshot", ("bin", planted.name))):
        # Written in the recipe: the path is checked as written, before anything tidies its `..` away.
        winding = "\\".join([str(elsewhere / link), "..", *rest])
        with pytest.raises(AssistantError) as caught:
            _run(Config(), tmp_path, [winding], repo=repo)
        assert caught.value.code == "recipe_program_inside_change", winding
    assert captured == []


@_JUNCTIONS
def test_windows_dot_dot_after_a_tracked_junction_is_still_seen_at_the_junction(tmp_path, captured):
    (tmp_path / "outside" / "sub").mkdir(parents=True)
    repo = _repository(tmp_path / "project")
    _tracked_junction(repo, "tools", tmp_path / "outside" / "sub")
    environment = _program(repo / ".venv" / "Scripts", "python")
    winding = "\\".join([str(repo), "tools", "..", ".venv", "Scripts", environment.name])
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, [winding], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"
    assert captured == []
    # The ignored environment itself, written plainly, is still allowed.
    _run(replace(Config(), recipe_python=str(environment)), tmp_path, ["python", "-V"], repo=repo)
    assert captured == [[str(environment), "-V"]]


@_JUNCTIONS
def test_windows_a_junction_from_outside_to_an_ignored_environment_is_allowed(tmp_path, captured):
    repo = _repository(tmp_path / "project")
    environment = _program(repo / ".venv" / "Scripts", "python")
    (tmp_path / "links").mkdir()
    _junction(tmp_path / "links" / "scripts", environment.parent)
    program = tmp_path / "links" / "scripts" / environment.name
    _run(replace(Config(), recipe_python=str(program)), tmp_path, ["python", "-V"], repo=repo)
    assert captured == [[str(program), "-V"]]
