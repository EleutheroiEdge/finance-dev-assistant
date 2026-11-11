"""The seeded figure-screen script on a synthetic repository. Every figure here is made up."""

import importlib.util
from pathlib import Path

from conftest import command

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("seeded_figure_screen", ROOT / "scripts/seeded_figure_screen.py")
seeded = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seeded)


def _change(repo: Path, text: str) -> None:
    (repo / "src/cash.py").write_text(text, encoding="utf-8", newline="\n")
    command(repo, "commit", "-q", "-am", "Synthetic change with numbers")


def test_added_numbers_are_listed_one_at_a_time_and_only_counts_are_printed(repository, capsys):
    repo, _base, _head = repository
    _change(repo, "OPENING = 48_213.57  # was (6,729,102.50 before)\nLIMITS = [3, 12, 250000]\nRATE = 0.25\n")
    assert seeded.main([str(repo), "--changes", "1", "--branch", "HEAD"]) == 0
    shown = capsys.readouterr().out
    # 48_213.57 and 6,729,102.50 have five or more significant digits; 250000 has two, 0.25 two.
    assert "'seeded_refused': 2" in shown and "seeded_missed" not in shown and "'false_alarms': 0" in shown
    assert "'file_versions': 2" in shown
    assert not any(figure in shown for figure in ("48", "729", "cash.py"))


def test_numbers_split_by_plain_commas_are_separate_numbers(repository):
    repo, base, _head = repository
    _change(repo, "ROW = [1,2,734561]\nTOTAL = 1,234,567.89\n")
    found = seeded.added_numbers(repo, base, command(repo, "rev-parse", "HEAD"))
    assert set(found) == {"734561", "1,234,567.89"}


def test_a_miss_or_a_false_alarm_fails_the_run(repository, monkeypatch, capsys):
    repo, _base, _head = repository
    _change(repo, "OPENING = 48_213.57\n")
    monkeypatch.setattr(seeded, "outcome", lambda text, path, snapshot: None)  # A screen that refuses nothing.
    assert seeded.main([str(repo), "--changes", "1", "--branch", "HEAD"]) == 1
    assert "'seeded_missed': 1" in capsys.readouterr().out
