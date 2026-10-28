from pathlib import Path
import subprocess

import pytest


def command(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "repository"
    repo.mkdir()
    command(repo, "init", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    (repo / "src").mkdir()
    (repo / "src/cash.py").write_text("def balance(opening, deposits):\n    return opening + deposits\n")
    (repo / ".gitignore").write_text(".finassist/\n")
    command(repo, "add", "src/cash.py", ".gitignore")
    command(repo, "commit", "-m", "Synthetic baseline")
    base = command(repo, "rev-parse", "HEAD")
    command(repo, "switch", "-c", "test/candidate")
    (repo / "src/cash.py").write_text("def balance(opening, deposits):\n    return opening - deposits\n")
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Synthetic candidate")
    return repo, base, command(repo, "rev-parse", "HEAD")
