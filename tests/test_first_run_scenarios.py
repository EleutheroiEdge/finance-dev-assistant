"""The first-run scenario script on a synthetic repository: counts and codes only, nothing written into it."""

import importlib.util
import json
from pathlib import Path
import sys

import pytest

from conftest import command

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("first_run_scenarios", ROOT / "scripts/first_run_scenarios.py")
scenarios = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scenarios)

CHANGES = [
    {"src/cash.py": "def balance(opening, deposits):\n    return opening + deposits\n"},
    {"src/fees.py": "def fee(amount):\n    return amount // 100\n"},
    # A private data file beside an ordinary change: refused, or withheld under skip-and-report.
    {"data/positions.csv": "symbol,quantity\nSYNTHETIC,1\n", "src/fees.py": "def fee(amount):\n    return amount // 50\n"},
]


def _history(repo: Path) -> None:
    command(repo, "switch", "-q", "main")
    command(repo, "merge", "-q", "--ff-only", "test/candidate")
    for index, files in enumerate(CHANGES):
        for name, text in files.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(text, encoding="utf-8", newline="\n")
            command(repo, "add", "-f", name)
        command(repo, "commit", "-q", "-m", f"Synthetic change {index}")


def test_the_script_reports_counts_and_leaves_the_repository_alone(repository, tmp_path, capsys):
    repo, _base, _head = repository
    _history(repo)
    before = command(repo, "status", "--porcelain")
    output = tmp_path / "private-output"
    assert scenarios.main([str(repo), "--changes", "3", "--branch", "main", "--output", str(output),
                           "--python", sys.executable]) == 0
    shown = capsys.readouterr().out
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))[repo.name]
    assert summary["changes"] == 3 and set(summary["variants"]) == set(scenarios.VARIANTS)
    gate, skipping = summary["variants"]["gate"], summary["variants"]["gate+skip"]
    assert gate["ready"] == 2 and skipping["ready"] == 3
    assert summary["variants"]["config"]["ready_but_for_authorization"] == 2
    assert summary["variants"]["config+skip"]["ready_but_for_authorization"] == 3
    assert "ALL gate" in shown and "positions" not in shown and "cash.py" not in shown
    assert command(repo, "status", "--porcelain") == before


def test_the_output_folder_must_be_outside_every_repository(repository):
    repo, _base, _head = repository
    with pytest.raises(SystemExit) as stopped:
        scenarios.main([str(repo), "--output", str(repo / "results")])
    assert stopped.value.code == 2 and not (repo / "results").exists()
