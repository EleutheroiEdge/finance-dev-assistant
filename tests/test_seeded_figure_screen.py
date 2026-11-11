"""The seeded figure-screen script on a synthetic repository. Every figure here is made up."""

import importlib.util
from pathlib import Path

import pytest

from conftest import command

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("seeded_figure_screen", ROOT / "scripts/seeded_figure_screen.py")
seeded = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seeded)


def _change(repo: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
        command(repo, "add", "-f", name)
    command(repo, "commit", "-q", "-m", "Synthetic change with numbers")


def _run(capsys, repo, *options):
    code = seeded.main([str(repo), "--changes", "1", "--branch", "HEAD", *options])
    return code, capsys.readouterr().out


def test_added_numbers_are_listed_one_at_a_time_and_only_counts_are_printed(repository, capsys):
    repo, _base, _head = repository
    _change(repo, {"src/cash.py": "OPENING = 48_213.57  # was (6,729,102.50 before)\nLIMITS = [3, 12, 250000]\nRATE = 0.25\n"})
    code, shown = _run(capsys, repo)
    # 48_213.57 and 6,729,102.50 have five or more significant digits; 250000 and 0.25 have two.
    assert code == 0 and "'seeded_refused': 2" in shown and "seeded_missed" not in shown
    assert "'file_versions': 2" in shown and "'changes': 1" in shown and "false_alarms" not in shown
    assert "repository 1" in shown and str(repo) not in shown
    assert not any(part in shown for part in ("48", "729", "cash.py"))


def test_a_number_added_to_two_files_is_counted_in_each(repository, capsys, monkeypatch):
    repo, _base, _head = repository
    _change(repo, {"src/cash.py": "OPENING = 48_213.57\n", "src/fees.py": "FEE = 48213.57\n"})
    code, shown = _run(capsys, repo)
    assert code == 0 and "'seeded_refused': 2" in shown
    # A screen that misses one of the two files fails the run, though the other file is refused.
    real = seeded.outcome
    monkeypatch.setattr(seeded, "outcome", lambda text, path, snapshot: None if path == "src/fees.py" else real(text, path, snapshot))
    code, shown = _run(capsys, repo)
    assert code == 1 and "'seeded_missed': 1" in shown and "'seeded_refused': 1" in shown


def test_a_private_path_is_never_read(repository, capsys, monkeypatch):
    repo, _base, _head = repository
    _change(repo, {"src/.env.py": "SYNTHETIC_TOTAL = 48213.57\n", "credentials/settings.json": '{"total": 6729102.50}\n',
                   "data/positions.csv": "value\n1234567.89\n", "src/cash.py": "OPENING = 905.125\n"})
    read, real = [], seeded.git

    def spy(repository, *args):
        read.append(args)
        return real(repository, *args)

    monkeypatch.setattr(seeded, "git", spy)
    code, shown = _run(capsys, repo)
    assert code == 0 and "'paths_private': 2" in shown and "'paths_not_text': 1" in shown
    assert "'seeded_refused': 1" in shown and "'file_versions': 2" in shown
    contents = [args for args in read if args[0] in {"cat-file", "ls-tree"} or (args[0] == "diff" and "--name-only" not in args)]
    assert contents and all("src/cash.py" in args[-1] for args in contents)


def test_numbers_split_by_plain_commas_are_separate_numbers(repository):
    repo, base, _head = repository
    _change(repo, {"src/cash.py": "ROW = [1,2,734561]\nTOTAL = 1,234,567.89\n"})
    assert seeded.added_numbers(repo, base, command(repo, "rev-parse", "HEAD"), "src/cash.py") == {"734561", "1,234,567.89"}


def test_a_control_figure_that_is_in_a_file_is_a_collision_not_a_false_alarm(repository, capsys):
    figure = seeded.control_figures(7)[0]
    repo, _base, _head = repository
    _change(repo, {"src/cash.py": f"CONTROL = {figure}\n"})
    code, shown = _run(capsys, repo, "--seed", "7")
    assert code == 2 and "'control_collisions': 1" in shown and "false_alarms" not in shown
    code, shown = _run(capsys, repo)  # Another seed: the same file holds no control figure.
    assert code == 0 and "control_collisions" not in shown


def test_a_false_alarm_fails_the_run(repository, capsys, monkeypatch):
    repo, _base, _head = repository
    _change(repo, {"src/cash.py": "OPENING = 1\n"})
    monkeypatch.setattr(seeded, "outcome", lambda text, path, snapshot: "forbidden_token_present")
    code, shown = _run(capsys, repo)
    assert code == 1 and "'false_alarms': 2" in shown


@pytest.mark.parametrize("options", [("--branch", "no-such-branch"), ("--changes", "0")])
def test_an_incomplete_run_never_exits_zero(repository, capsys, options):
    repo, _base, _head = repository
    try:
        code = seeded.main([str(repo), *options])
    except SystemExit as stopped:
        code = stopped.code
    assert code == 2
    assert str(repo) not in capsys.readouterr().out


def test_a_missing_repository_is_reported_without_its_path(tmp_path, capsys):
    missing = tmp_path / "private-name"
    assert seeded.main([str(missing)]) == 2
    shown = capsys.readouterr().out
    assert "repository 1: INCOMPLETE" in shown and "private-name" not in shown


def test_no_control_figure_ends_in_a_zero():
    figures = seeded.control_figures(20261110)
    assert len(figures) == 1000 and len(set(figures)) > 990
    assert all(len(figure.split(".")[1]) == 2 and figure[-1] != "0" and figure[0] != "0" for figure in figures)


def _grouped(figure: str, separator: str) -> str:
    whole, fraction = figure.split(".")
    head = len(whole) % 3 or 3
    return separator.join([whole[:head], *(whole[start:start + 3] for start in range(head, len(whole), 3))]) + "." + fraction


ESCAPED_SPACE = chr(92) + "u00a0"  # A no-break space as source text writes it.


@pytest.mark.parametrize("respell", [
    lambda figure: _grouped(figure, ","),
    lambda figure: _grouped(figure, ESCAPED_SPACE),
    lambda figure: _grouped(figure, "&nbsp;"),
    lambda figure: figure.replace(".", "") + "e-2",
    lambda figure: figure + "000",
    lambda figure: "".join(chr(0xFF10 + int(c)) if c.isdigit() else c for c in figure),   # fullwidth digits
    lambda figure: "".join(chr(0x0660 + int(c)) if c.isdigit() else c for c in figure),   # Arabic-Indic digits
])
def test_a_control_figure_in_any_spelling_is_a_collision(repository, capsys, monkeypatch, respell):
    repo, _base, _head = repository
    _change(repo, {"src/control.py": "CONTROL = '" + respell(seeded.control_figures(7)[0]) + "'\n"})
    # Whatever the screen makes of the spelling, a refusal here is explained by the file, not a false alarm.
    monkeypatch.setattr(seeded, "outcome", lambda text, path, snapshot: "forbidden_token_present")
    code, shown = _run(capsys, repo, "--seed", "7")
    assert code == 2 and "'control_collisions': 1" in shown and "false_alarms" not in shown


def test_an_added_line_that_starts_with_two_plus_signs_is_read(repository, capsys, monkeypatch):
    repo, base, _head = repository
    _change(repo, {"src/counter.ts": "let counter = 0;\n++counter; // 48213.57\n"})
    assert seeded.added_numbers(repo, base, command(repo, "rev-parse", "HEAD"), "src/counter.ts") == {"48213.57"}
    code, shown = _run(capsys, repo)
    assert code == 0 and "'seeded_refused': 1" in shown
    monkeypatch.setattr(seeded, "outcome", lambda text, path, snapshot: None)  # A screen that misses it fails the run.
    code, shown = _run(capsys, repo)
    assert code == 1 and "'seeded_missed': 1" in shown


def test_a_history_shorter_than_asked_for_is_incomplete(repository, capsys):
    repo, _base, _head = repository
    assert seeded.main([str(repo), "--changes", "25", "--branch", "HEAD"]) == 2
    shown = capsys.readouterr().out
    assert "INCOMPLETE (history holds 1 of the 25 changes asked for)" in shown and str(repo) not in shown
