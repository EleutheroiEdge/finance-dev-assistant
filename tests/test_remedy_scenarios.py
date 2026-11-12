"""The remedy scenario script on a synthetic repository: each change ends where it should, nothing is written
into the repository, and only codes, setting names and counts are printed."""

import importlib.util
import json
from pathlib import Path
import sys

import pytest

from conftest import command

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("remedy_scenarios", ROOT / "scripts/remedy_scenarios.py")
remedies = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remedies)

# The label and the value are joined when the test runs, so this file holds no line that looks like a credential.
SECRET_LINE = "pass" + "word = " + '"' + "synthetic-" + "do-not-use-0123456789" + '"\n'
CHANGES = [
    # Nothing in the way.
    {"src/cash.py": "def balance(opening, deposits):\n    return opening + deposits\n"},
    # A private data file beside an ordinary change: a program can choose to withhold it.
    {"data/positions.csv": "symbol,quantity\nSYNTHETIC,1\n", "src/fees.py": "def fee(amount):\n    return amount // 50\n"},
    # A file over the size limit beside an ordinary change: a program can choose to leave it out.
    {"src/table.py": "ROWS = [\n" + "    (1, 2, 3, 4, 5, 6, 7, 8, 9, 10),\n" * 20000 + "]\n",
     "src/fees.py": "def fee(amount):\n    return amount // 25\n"},
    # A credential in the change: nobody but a person can decide that.
    {"src/login.py": SECRET_LINE},
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
        return remedies.main([*arguments, "--python", sys.executable])
    except SystemExit as stopped:
        return stopped.code


def test_each_change_ends_where_it_should_and_the_repository_is_left_alone(repository, tmp_path, capsys):
    repo, _base, _head = repository
    _history(repo)
    before = command(repo, "status", "--porcelain")
    output = tmp_path / "private-output"
    assert _main(str(repo), "--changes", "4", "--branch", "main", "--output", str(output)) == 0
    shown = capsys.readouterr().out
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))["repository-1"]
    assert summary["changes"] == 4 and set(summary["routes"]) == set(remedies.ROUTES)
    for route, counts in summary["routes"].items():
        outcomes = counts["outcomes"]
        assert outcomes == {"ready": 1, "remedied": 2, "needs_decision": 1, "failed": 0, "looped": 0}, route
        assert counts["set_up"] == 3 and counts["defects"] == {}
        assert counts["decisions"] == {"sensitive_content": 1}
        # The careful path: both remedies taken leave a file out, and neither sends or spends more.
        assert counts["effects"] == {"leaves_files_out": 2}
        assert counts["settings"] == {"private_paths": 1, "unreviewable_paths": 1}
        assert counts["runs_to_set_up"] == [2, 2] and counts["left_out_when_set_up"] == 2
    rows = json.loads((output / "repository-1-rows.json").read_text(encoding="utf-8"))
    assert [row["outcome"] for row in rows["gate policy"]] == ["ready", "remedied", "remedied", "needs_decision"]
    # Every document tried is kept, privately: two for a remedied change, one for the others.
    kept = sorted(path.relative_to(output / "repository-1").as_posix() for path in (output / "repository-1").rglob("*.json"))
    assert kept == sorted(f"{field}/{change}/{run}.json" for field in ("config", "gate_policy_draft")
                          for change, runs in ((1, 1), (2, 2), (3, 2), (4, 1)) for run in range(1, runs + 1))
    assert "ALL configuration" in shown and "ALL gate policy" in shown
    assert "repositories measured: 1 | incomplete: 0" in shown and "reference set: " in shown
    # Only an anonymous label, codes and setting names are printed.
    for private in (str(repo), "positions", "table.py", "login.py", "synthetic-do-not-use"):
        assert private not in shown
    assert command(repo, "status", "--porcelain") == before


def test_a_change_is_made_where_its_pointer_says_and_an_option_a_program_cannot_apply_is_not_applied():
    document = {"max_file_bytes": 10, "model_review": {"max_request_bytes": 10}}
    for route in remedies.ROUTES:
        needs = {"document": route, "effect": "spends_more",
                 "changes": [{"setting": "max_run_usd", "needs_value": True, "pointer": "/max_run_usd"}]}
        other = {"document": "another document", "effect": "none",
                 "changes": [{"setting": "x", "value": 1, "pointer": "/x"}]}
        assert remedies.apply(route, document, needs) is None and remedies.apply(route, document, other) is None
    changed = remedies.apply("gate policy", document, {"document": "gate policy", "effect": "sends_more", "changes": [
        {"setting": "max_request_bytes", "at_least": 20, "pointer": "/model_review/max_request_bytes"},
        {"setting": "allow_paths", "add": ["src/a.py"], "pointer": "/model_review/allow_paths"}]})
    assert changed == {"max_file_bytes": 10, "model_review": {"max_request_bytes": 20, "allow_paths": ["src/a.py"]}}
    top = remedies.apply("configuration", document, {"document": "configuration", "effect": "leaves_files_out",
                                                    "changes": [{"setting": "allow_partial_review", "value": True,
                                                                 "pointer": "/allow_partial_review"}]})
    assert top == {**document, "allow_partial_review": True}
    assert document == {"max_file_bytes": 10, "model_review": {"max_request_bytes": 10}}
    for pointer in (None, "/missing_section/max_file_bytes"):
        change = {"setting": "max_file_bytes", "value": 1, **({} if pointer is None else {"pointer": pointer})}
        with pytest.raises(remedies.Incomplete):
            remedies.apply("configuration", document, {"document": "configuration", "changes": [change]})


def test_a_remedy_that_comes_back_is_reported_as_failed_and_one_that_never_ends_as_looped(tmp_path, monkeypatch):
    option = {"document": "configuration", "effect": "leaves_files_out",
              "changes": [{"setting": "unreviewable_paths", "value": "skip-and-report", "pointer": "/unreviewable_paths"}]}
    blocked = {"status": "blocked", "blockers": ["file_limit_exceeded"], "left_out": 1, "seconds": 0.1,
               "remedies": [{"code": "file_limit_exceeded", "options": [option]}]}
    monkeypatch.setattr(remedies, "preflight", lambda *_arguments: dict(blocked))
    row = remedies.follow(["finassist"], "configuration", {}, tmp_path, "base", "head", tmp_path / "failed", {})
    assert (row["outcome"], row["rounds"], row["codes"]) == ("failed", 2, ["file_limit_exceeded"])
    assert row["applied"] == [{"code": "file_limit_exceeded", "effect": "leaves_files_out", "settings": ["unreviewable_paths"]}]

    counter = iter(range(1, 100))

    def moving(*_arguments):
        bound = {"setting": "max_file_bytes", "at_least": next(counter), "pointer": "/max_file_bytes"}
        return {**blocked, "remedies": [{"code": "file_limit_exceeded", "options": [
            {"document": "configuration", "effect": "sends_more", "changes": [bound]}]}]}

    monkeypatch.setattr(remedies, "preflight", moving)
    row = remedies.follow(["finassist"], "configuration", {}, tmp_path, "base", "head", tmp_path / "looped", {})
    assert (row["outcome"], row["rounds"]) == ("looped", remedies.MAX_ROUNDS)
    assert len(row["applied"]) == remedies.MAX_ROUNDS
