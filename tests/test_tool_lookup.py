"""A tool is taken from PATH's absolute entries only, never from the directory a command runs in."""

import ast
import os
from pathlib import Path

import pytest

from finassist.errors import AssistantError
from finassist.platform_support import find_tool, locate_tool

SOURCE = Path(__file__).resolve().parents[1] / "src" / "finassist"
NATIVE = "git.exe" if os.name == "nt" else "git"


def _tool(directory: Path, name: str = NATIVE) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    file = directory / name
    file.write_bytes(b"")
    file.chmod(0o755)
    return file


def test_a_file_named_like_a_tool_in_the_current_directory_is_never_taken(tmp_path, monkeypatch):
    here, trusted = tmp_path / "checkout", tmp_path / "trusted"
    _tool(here)
    expected = _tool(trusted)
    monkeypatch.chdir(here)
    monkeypatch.setenv("PATH", str(trusted))
    found = Path(find_tool("git"))
    assert found.is_absolute() and found == expected


def test_only_a_file_in_the_current_directory_means_the_tool_is_missing(tmp_path, monkeypatch):
    here, empty = tmp_path / "checkout", tmp_path / "empty"
    _tool(here)
    empty.mkdir()
    monkeypatch.chdir(here)
    monkeypatch.setenv("PATH", str(empty))
    assert locate_tool("git") is None
    with pytest.raises(AssistantError, match="git_executable_missing"):
        find_tool("git")


@pytest.mark.parametrize("entries", [[""], ["."], ["", "."], ["tools"], [os.curdir + os.sep]])
def test_an_empty_or_relative_path_entry_is_not_searched(tmp_path, monkeypatch, entries):
    here, empty = tmp_path / "checkout", tmp_path / "empty"
    _tool(here)
    _tool(here / "tools")
    empty.mkdir()
    monkeypatch.chdir(here)
    monkeypatch.setenv("PATH", os.pathsep.join([*entries, str(empty)]))
    assert locate_tool("git") is None
    with pytest.raises(AssistantError, match="git_executable_missing"):
        find_tool("git")


def test_path_order_decides_and_the_current_directory_counts_only_when_named_in_full(tmp_path, monkeypatch):
    first, second = _tool(tmp_path / "first"), _tool(tmp_path / "second")
    monkeypatch.setenv("PATH", os.pathsep.join([str(second.parent), str(first.parent)]))
    assert Path(find_tool("git")) == second
    # Naming a directory in full is the user's own statement, wherever the command then runs.
    monkeypatch.chdir(first.parent)
    monkeypatch.setenv("PATH", str(first.parent))
    assert Path(find_tool("git")) == first


@pytest.mark.skipif(os.name == "nt", reason="Windows has no executable bit")
def test_a_file_without_the_executable_bit_is_passed_over(tmp_path, monkeypatch):
    plain, real = _tool(tmp_path / "first"), _tool(tmp_path / "second")
    plain.chmod(0o644)
    monkeypatch.setenv("PATH", os.pathsep.join([str(plain.parent), str(real.parent)]))
    assert Path(find_tool("git")) == real


def test_the_windows_rules_hold_on_any_platform(tmp_path):
    here, trusted = tmp_path / "checkout", tmp_path / "trusted"
    _tool(here, "git.EXE")
    found = _tool(trusted, "git.EXE")
    listed = {"PATH": ";".join(["", ".", "relative", '"%s"' % trusted]), "PATHEXT": ".COM;.EXE;.BAT;.CMD"}
    assert locate_tool("git", listed, windows=True) == str(found)
    # Without PATHEXT the usual four suffixes apply.
    assert locate_tool("git", {"PATH": str(trusted)}, windows=True) == str(found)
    # A name with no suffix is not a program there.
    _tool(tmp_path / "bare", "git")
    assert locate_tool("git", {"PATH": str(tmp_path / "bare")}, windows=True) is None
    # No PATH at all never falls back to the current directory.
    assert locate_tool("git", {"PATH": ""}, windows=True) is None


def test_a_batch_shim_found_first_is_refused_and_not_skipped(tmp_path, monkeypatch):
    shim = _tool(tmp_path / "shims", "git.CMD")
    _tool(tmp_path / "later", "git.EXE")
    listed = {"PATH": ";".join([str(shim.parent), str(tmp_path / "later")]), "PATHEXT": ".EXE;.CMD"}
    assert locate_tool("git", listed, windows=True) == str(shim)
    monkeypatch.setattr("finassist.platform_support.locate_tool", lambda name: str(shim))
    with pytest.raises(AssistantError, match="batch_tool_not_supported"):
        find_tool("git")


def test_no_module_asks_the_standard_library_to_find_a_program():
    """shutil.which searches the current directory on Windows. The one finder here does not."""
    offenders = []
    for file in sorted(SOURCE.glob("*.py")):
        for node in ast.walk(ast.parse(file.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr == "which":
                offenders.append(file.name)
            if isinstance(node, ast.ImportFrom) and node.module == "shutil":
                offenders.extend(file.name for alias in node.names if alias.name == "which")
    assert offenders == []
