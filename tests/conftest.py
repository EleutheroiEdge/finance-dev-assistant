from pathlib import Path
import os
import re
import subprocess

import pytest
from finassist.platform_support import find_tool
from finassist.scope import git_environment


@pytest.fixture(autouse=True)
def _no_state_folder_left_in_the_working_directory():
    # A test leaves the checkout as it found it: its state goes under tmp_path or an explicit --state-dir (#134).
    # Test groups run side by side in one checkout, so the test named may be one running alongside the culprit.
    state = Path.cwd() / ".finassist"
    existed = state.exists()
    yield
    if not existed and state.exists():
        pytest.fail("a .finassist folder appeared in the working directory during this test")


def holds_number(text: str, digits: str) -> bool:
    """Whether `digits` occur in `text` as a number, not as a run inside a hash, an identifier or a time stamp.

    Reports, requests and audit events carry run identifiers, hashes and time stamps. Seven given digits turn up inside
    one of them by chance now and then, so a bare substring test can fail although no figure leaked.
    """
    return re.search(r"(?<![0-9A-Fa-f])" + re.escape(digits) + r"(?![0-9A-Fa-f])", text) is not None


def command(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        [
            find_tool("git"),
            "-c",
            "core.hooksPath=" + os.devnull,
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(repo),
            *args,
        ],
        env=git_environment(),
        text=True,
        encoding="utf-8",
    ).strip()


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "repository"
    repo.mkdir()
    command(repo, "init", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    (repo / "src").mkdir()
    (repo / "src/cash.py").write_text(
        "def balance(opening, deposits):\n    return opening + deposits\n", encoding="utf-8", newline="\n"
    )
    (repo / ".gitignore").write_text(".finassist/\n", encoding="utf-8", newline="\n")
    command(repo, "add", "src/cash.py", ".gitignore")
    command(repo, "commit", "-m", "Synthetic baseline")
    base = command(repo, "rev-parse", "HEAD")
    command(repo, "switch", "-c", "test/candidate")
    (repo / "src/cash.py").write_text(
        "def balance(opening, deposits):\n    return opening - deposits\n", encoding="utf-8", newline="\n"
    )
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Synthetic candidate")
    return repo, base, command(repo, "rev-parse", "HEAD")


def synthetic_symlink(path, target, *, target_is_directory=False):
    try:
        path.symlink_to(target, target_is_directory=target_is_directory)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows did not grant symlink creation; Git object-mode tests still run")
        raise
