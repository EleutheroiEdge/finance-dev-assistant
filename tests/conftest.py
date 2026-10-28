from pathlib import Path
import os
import subprocess

import pytest
from finassist.platform_support import find_tool
from finassist.scope import git_environment


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
