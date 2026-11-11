"""The first-run scenario script on a synthetic repository: counts and codes only, nothing written into it."""

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

from conftest import command, synthetic_symlink

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


def _main(*arguments) -> int:
    try:
        return scenarios.main([*arguments, "--python", sys.executable])
    except SystemExit as stopped:
        return stopped.code


def test_the_script_reports_counts_and_leaves_the_repository_alone(repository, tmp_path, capsys):
    repo, _base, _head = repository
    _history(repo)
    before = command(repo, "status", "--porcelain")
    output = tmp_path / "private-output"
    assert _main(str(repo), "--changes", "3", "--branch", "main", "--output", str(output)) == 0
    shown = capsys.readouterr().out
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))["repository-1"]
    assert summary["changes"] == 3 and set(summary["variants"]) == set(scenarios.VARIANTS)
    gate, skipping = summary["variants"]["gate"], summary["variants"]["gate+skip"]
    assert gate["ready"] == 2 and skipping["ready"] == 3
    assert summary["variants"]["config"]["ready_but_for_authorization"] == 2
    assert summary["variants"]["config+skip"]["ready_but_for_authorization"] == 3
    assert summary["variants"]["gate+leave"]["ready"] == 3
    assert summary["variants"]["config+leave"]["ready_but_for_authorization"] == 3
    assert summary["variants"]["gate+tests"]["ready"] == 3
    assert summary["variants"]["config+tests"]["ready_but_for_authorization"] == 3
    assert "ALL gate" in shown and "repositories measured: 1 | incomplete: 0" in shown
    # Only an anonymous label is printed; which repository it is stays in the private folder.
    assert "repository-1" in shown and str(repo) not in shown and "positions" not in shown and "cash.py" not in shown
    assert json.loads((output / "repositories.json").read_text(encoding="utf-8")) == {"repository-1": str(repo.resolve())}
    assert command(repo, "status", "--porcelain") == before


def test_two_repositories_with_one_name_are_both_measured(repository, tmp_path, capsys):
    repo, _base, _head = repository
    _history(repo)
    twin = tmp_path / "elsewhere" / repo.name
    twin.parent.mkdir()
    command(tmp_path, "clone", "-q", str(repo), str(twin))
    output = tmp_path / "private-output"
    assert _main(str(repo), str(twin), "--changes", "2", "--branch", "main", "--output", str(output)) == 0
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert set(summary) == {"repository-1", "repository-2"} and all(item["changes"] == 2 for item in summary.values())


def test_the_output_folder_must_be_new_and_outside_every_repository(repository, tmp_path):
    repo, _base, _head = repository
    assert _main(str(repo), "--output", str(repo / "results")) == 2 and not (repo / "results").exists()
    existing = tmp_path / "existing"
    existing.mkdir()
    # A folder that already exists could hold a link that redirects a write into a repository.
    synthetic_symlink(existing / "repository-1-config.json", repo / "src/cash.py")
    kept = (repo / "src/cash.py").read_bytes()
    assert _main(str(repo), "--output", str(existing)) == 2
    assert (repo / "src/cash.py").read_bytes() == kept
    assert _main(str(repo), str(repo), "--output", str(tmp_path / "twice")) == 2
    assert _main(str(repo), "--changes", "0", "--output", str(tmp_path / "none")) == 2


@pytest.mark.parametrize("branch", ["no-such-branch"])
def test_an_incomplete_measurement_never_exits_zero(repository, tmp_path, capsys, branch):
    repo, _base, _head = repository
    output = tmp_path / "private-output"
    assert _main(str(repo), str(tmp_path / "private-name"), "--branch", branch, "--output", str(output)) == 2
    shown = capsys.readouterr().out
    assert shown.count("INCOMPLETE") == 2 and "repositories measured: 0 | incomplete: 2" in shown
    assert "private-name" not in shown and str(repo) not in shown
    assert set(json.loads((output / "summary.json").read_text(encoding="utf-8"))) == {"repository-1", "repository-2"}


def _doctor_answers(monkeypatch, answer, at: int):
    """Replace the `at`-th doctor run's result with `answer`; every other run is the real one."""
    real, calls = scenarios.finassist, []

    def wrapped(command, arguments, cwd, environment):
        if "doctor" in arguments:
            calls.append(arguments)
            if len(calls) == at:
                return subprocess.CompletedProcess(arguments, *answer), 0.0
        return real(command, arguments, cwd, environment)

    monkeypatch.setattr(scenarios, "finassist", wrapped)


def test_a_doctor_run_with_no_report_makes_the_measurement_incomplete(repository, tmp_path, capsys, monkeypatch):
    repo, _base, _head = repository
    _history(repo)
    # One crashed run among ranges that would otherwise all count.
    _doctor_answers(monkeypatch, (1, "Traceback (most recent call last):\n", "synthetic crash\n"), at=2)
    assert _main(str(repo), "--changes", "3", "--branch", "main", "--output", str(tmp_path / "out")) == 2
    shown = capsys.readouterr().out
    assert "INCOMPLETE (doctor gave no report)" in shown and "repositories measured: 0 | incomplete: 1" in shown
    assert "ALL " not in shown


def test_a_refusal_the_product_states_is_a_measurement(repository, tmp_path, capsys, monkeypatch):
    repo, _base, _head = repository
    _history(repo)
    _doctor_answers(monkeypatch, (2, "", '{"code": "synthetic_refusal"}\n'), at=1)
    output = tmp_path / "out"
    assert _main(str(repo), "--changes", "3", "--branch", "main", "--output", str(output)) == 0
    config = json.loads((output / "summary.json").read_text(encoding="utf-8"))["repository-1"]["variants"]["config"]
    assert config["blockers"]["synthetic_refusal"] == 1 and config["ready_but_for_authorization"] == 1


def test_a_history_shorter_than_asked_for_is_incomplete(repository, tmp_path, capsys):
    repo, _base, _head = repository
    _history(repo)  # Five commits: four changes with a parent.
    assert _main(str(repo), "--changes", "25", "--branch", "main", "--output", str(tmp_path / "out")) == 2
    shown = capsys.readouterr().out
    assert "INCOMPLETE (history holds 4 of the 25 changes asked for)" in shown
    assert "repositories measured: 0 | incomplete: 1" in shown


def test_a_folder_inside_a_repository_is_not_taken_for_its_root(repository, tmp_path):
    repo, _base, _head = repository
    # Git would read the repository from src/, and results/ is outside src/ yet inside the repository.
    assert _main(str(repo / "src"), "--output", str(repo / "results")) == 2 and not (repo / "results").exists()
    assert _main(str(repo / "src"), "--output", str(tmp_path / "out")) == 2 and not (tmp_path / "out").exists()


def test_a_content_refusal_is_counted_by_its_rule_and_suffix_and_never_by_name():
    refused = {"status": "refused", "code": "sensitive_content", "rule": "credential_label", "lines": [3]}
    assert scenarios.outcome({**refused, "path": "src/app/Settings.TS"}) == "refused:sensitive_content:credential_label:.ts"
    assert scenarios.outcome({**refused, "path": "[redacted]"}) == "refused:sensitive_content:credential_label:"
    # A suffix that could itself say something is not kept.
    assert scenarios.outcome({**refused, "path": "notes.client-name-2026"}) == "refused:sensitive_content:credential_label:"
    assert scenarios.outcome({"path": "src/cash.py", "status": "included"}) == "included:"
    assert scenarios.outcome({"path": "data/x.csv", "status": "withheld", "reason": "private"}) == "withheld:private"


# --- The same changes on a later day ----------------------------------------

def _fingerprint(shown: str) -> str:
    return re.search(r"^reference set: ([0-9a-f]{16}) \(1 repositories, \d+ changes each\)$", shown, re.M).group(1)


def _counts(folder: Path) -> dict:
    variants = json.loads((folder / "summary.json").read_text(encoding="utf-8"))["repository-1"]["variants"]
    return {name: {key: item[key] for key in ("ready", "blockers", "paths")} for name, item in variants.items()}


def test_a_later_run_reads_the_same_changes_from_the_tips_of_an_earlier_one(repository, tmp_path, capsys):
    repo, _base, _head = repository
    _history(repo)
    first, moved, again = tmp_path / "first", tmp_path / "moved", tmp_path / "again"
    assert _main(str(repo), "--changes", "2", "--branch", "main", "--output", str(first)) == 0
    earlier = capsys.readouterr().out
    tip = command(repo, "rev-parse", "main")
    # The commit is written to the private folder and never printed.
    assert (first / "tips.txt").read_text(encoding="utf-8") == tip + "\n" and tip not in earlier and tip[:7] not in earlier
    # The repository moves on. Its last two changes are now other changes: the newest is a private file alone.
    (repo / "data/prices.csv").write_text("symbol,price\nSYNTHETIC,2\n", encoding="utf-8", newline="\n")
    command(repo, "add", "-f", "data/prices.csv")
    command(repo, "commit", "-q", "-m", "Synthetic change after the measurement")
    assert _main(str(repo), "--changes", "2", "--branch", "main", "--output", str(moved)) == 0
    later = capsys.readouterr().out
    assert _main(str(repo), "--changes", "2", "--branch", "main", "--tips", str(first / "tips.txt"),
                 "--output", str(again)) == 0
    repeated = capsys.readouterr().out
    assert _fingerprint(repeated) == _fingerprint(earlier) != _fingerprint(later)
    assert _counts(again) == _counts(first) != _counts(moved)
    assert (again / "tips.txt").read_text(encoding="utf-8") == tip + "\n"
    # The count of changes is part of what is named.
    assert _main(str(repo), "--changes", "3", "--tips", str(first / "tips.txt"), "--output", str(tmp_path / "three")) == 0
    assert _fingerprint(capsys.readouterr().out) != _fingerprint(earlier)


@pytest.mark.parametrize("content", ["", "main\n", "0" * 39 + "\n", "0" * 40 + "\n" + "1" * 40 + "\n", "A" * 40 + "\n"])
def test_tips_must_hold_one_full_commit_for_each_repository(repository, tmp_path, content):
    repo, _base, _head = repository
    tips = tmp_path / "tips.txt"
    tips.write_text(content, encoding="utf-8")
    output = tmp_path / "out"
    assert _main(str(repo), "--tips", str(tips), "--output", str(output)) == 2 and not output.exists()
    assert _main(str(repo), "--tips", str(tmp_path / "missing.txt"), "--output", str(output)) == 2 and not output.exists()


def test_a_tip_a_repository_does_not_hold_is_incomplete_and_pins_nothing(repository, tmp_path, capsys):
    repo, _base, _head = repository
    tips = tmp_path / "tips.txt"
    tips.write_text("0" * 40 + "\n", encoding="utf-8")
    output = tmp_path / "out"
    assert _main(str(repo), "--tips", str(tips), "--output", str(output)) == 2
    shown = capsys.readouterr().out
    assert "INCOMPLETE" in shown and "reference set:" not in shown and not (output / "tips.txt").exists()


def test_no_git_command_of_a_measurement_may_take_the_optional_lock(repository, tmp_path, monkeypatch):
    repo, _base, _head = repository
    _history(repo)
    real_run, real_finassist, seen = subprocess.run, scenarios.finassist, []

    def settings(environment):
        return tuple(sorted((name, value) for name, value in environment.items() if name.startswith("GIT_")))

    def run(command, **options):
        if command[0] == "git":
            seen.append(("git", settings(options.get("env", {"GIT_": "inherited"}))))
        return real_run(command, **options)

    def finassist(command, arguments, cwd, environment):
        seen.append(("finassist", settings(environment)))
        return real_finassist(command, arguments, cwd, environment)

    monkeypatch.setattr(scenarios.subprocess, "run", run)
    monkeypatch.setattr(scenarios, "finassist", finassist)
    # The caller's own Git settings: one that would point every command at another repository, and
    # two that would undo what a measurement sets.
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "1")
    monkeypatch.setenv("GIT_NO_REPLACE_OBJECTS", "0")
    assert _main(str(repo), "--changes", "2", "--branch", "main", "--output", str(tmp_path / "out")) == 0
    kinds = {kind for kind, _value in seen}
    # The script's own Git reads, and every run of the product, which reads the repository with Git too.
    assert kinds == {"git", "finassist"}
    assert {value for _kind, value in seen} == {(("GIT_NO_REPLACE_OBJECTS", "1"), ("GIT_OPTIONAL_LOCKS", "0"))}


def _sibling_with_another_private_file(repo, tip):
    """A commit with the tip's parent and the tip's change plus one more private file. Not on any branch."""
    (repo / "data/prices.csv").write_text("symbol,price\nSYNTHETIC,2\n", encoding="utf-8", newline="\n")
    command(repo, "add", "-f", "data/prices.csv")
    tree = command(repo, "write-tree")
    command(repo, "reset", "-q", "--hard", tip)
    return command(repo, "commit-tree", tree, "-p", tip + "^", "-m", "Synthetic sibling")


def test_a_replacement_ref_cannot_put_other_changes_in_the_place_of_the_pinned_ones(repository, tmp_path, capsys):
    """Codex P114-1: with a replacement for the saved commit, a run read other changes under the same fingerprint."""
    repo, _base, _head = repository
    _history(repo)
    first, again = tmp_path / "first", tmp_path / "again"
    assert _main(str(repo), "--changes", "2", "--branch", "main", "--output", str(first)) == 0
    earlier = capsys.readouterr().out
    tip = command(repo, "rev-parse", "main")
    sibling = _sibling_with_another_private_file(repo, tip)
    command(repo, "replace", tip, sibling)
    # Git itself now shows the sibling's tree for the saved commit, unless it is told to read objects as they are.
    # It is told so by the variable being set at all, so this control reads without it.
    plain = {name: value for name, value in scenarios.git_environment().items() if name != "GIT_NO_REPLACE_OBJECTS"}
    shown = subprocess.run(["git", "-C", str(repo), "rev-parse", tip + "^{tree}"], capture_output=True, text=True,
                           check=True, env=plain).stdout.strip()
    assert shown == command(repo, "rev-parse", sibling + "^{tree}") != scenarios.git(repo, "rev-parse", tip + "^{tree}")
    assert _main(str(repo), "--changes", "2", "--branch", "main", "--tips", str(first / "tips.txt"),
                 "--output", str(again)) == 0
    assert _fingerprint(capsys.readouterr().out) == _fingerprint(earlier)
    assert _counts(again) == _counts(first)


def test_a_repository_with_a_grafts_file_is_not_measured(repository, tmp_path, capsys):
    """Codex P114-2: a graft gave the pinned commit another parent, under the same tips and fingerprint."""
    repo, _base, _head = repository
    _history(repo)
    first = tmp_path / "first"
    assert _main(str(repo), "--changes", "2", "--branch", "main", "--output", str(first)) == 0
    capsys.readouterr()
    tip = command(repo, "rev-parse", "main")
    grafts = repo / ".git/info/grafts"
    grafts.parent.mkdir(exist_ok=True)
    # The pinned commit is given its grandparent for a parent. Its own object still names its parent.
    parent, grandparent = command(repo, "rev-parse", tip + "~1"), command(repo, "rev-parse", tip + "~2")
    grafts.write_text("%s %s\n" % (tip, grandparent), encoding="utf-8")
    assert scenarios.git(repo, "rev-list", "--parents", "-n", "1", tip).split()[1] == grandparent
    assert ("parent " + parent) in scenarios.git(repo, "cat-file", "commit", tip)
    grafted = tmp_path / "grafted"
    assert _main(str(repo), "--changes", "2", "--tips", str(first / "tips.txt"), "--output", str(grafted)) == 2
    shown = capsys.readouterr().out
    assert "INCOMPLETE (the repository holds a grafts file)" in shown and "reference set:" not in shown
    assert not (grafted / "tips.txt").exists()
    # A grafts file that says nothing changes nothing.
    grafts.write_text("# no grafts\n\n", encoding="utf-8")
    again = tmp_path / "again"
    assert _main(str(repo), "--changes", "2", "--tips", str(first / "tips.txt"), "--output", str(again)) == 0
    assert _counts(again) == _counts(first)
