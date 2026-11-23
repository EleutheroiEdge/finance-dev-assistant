"""Gate A11's script on a synthetic repository: identical doctor output is counted byte for byte, a difference is
named only by stream, and nothing is written into the repository."""

import importlib.util
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from conftest import command

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("doctor_stability", ROOT / "scripts/doctor_stability.py")
stability = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stability)

CHANGES = [
    {"src/cash.py": "def balance(opening, deposits):\n    return opening + deposits\n"},
    {"src/fees.py": "def fee(amount):\n    return amount // 100\n"},
]

# An interpreter that runs the real one and, on every second `doctor` run, changes only the line endings of one
# stream: two raw outputs that decoded text would call the same.
UNSTEADY = """#!{python}
import os, pathlib, subprocess, sys
done = subprocess.run([sys.executable, *sys.argv[1:]], capture_output=True)
out, err = done.stdout, done.stderr
if "doctor" in sys.argv:
    counter = pathlib.Path(os.environ["A11_TEST_COUNTER"])
    calls = int(counter.read_text()) if counter.exists() else 0
    counter.write_text(str(calls + 1))
    crlf = calls % 2 == 1
    if os.environ["A11_TEST_STREAM"] == "output" and crlf:
        out = out.replace(b"\\n", b"\\r\\n")
    if os.environ["A11_TEST_STREAM"] == "error output":
        err += b"note\\r\\n" if crlf else b"note\\n"
sys.stdout.buffer.write(out)
sys.stderr.buffer.write(err)
sys.exit(done.returncode)
"""


def _history(repo: Path) -> None:
    command(repo, "switch", "-q", "main")
    command(repo, "merge", "-q", "--ff-only", "test/candidate")
    for index, files in enumerate(CHANGES):
        for name, text in files.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(text, encoding="utf-8", newline="\n")
            command(repo, "add", "-f", name)
        command(repo, "commit", "-q", "-m", f"Synthetic change {index}")


def _main(*arguments, python: str = sys.executable) -> int:
    try:
        return stability.main([*arguments, "--python", python])
    except SystemExit as stopped:
        return stopped.code


def test_identical_reruns_are_counted_and_the_repository_is_left_alone(repository, tmp_path, capsys):
    repo, _base, _head = repository
    _history(repo)
    before = command(repo, "status", "--porcelain")
    output = tmp_path / "private-output"
    assert _main(str(repo), "--runs", "2", "--changes", "2", "--branch", "main", "--output", str(output)) == 0
    shown = capsys.readouterr().out
    assert "A11: 4 of 4 checks gave byte-identical doctor output over 2 runs" in shown
    assert "repositories measured: 1 | incomplete: 0" in shown and str(repo) not in shown
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))["repository-1"]
    assert summary == {"changes": 2, "checked": 4, "identical": 4, "different": 0, "streams": {}}
    assert command(repo, "status", "--porcelain") == before


@pytest.mark.skipif(os.name == "nt", reason="the stand-in interpreter is a script run by its first line")
@pytest.mark.parametrize("stream", ["output", "error output"])
def test_line_endings_alone_make_a_difference(repository, tmp_path, capsys, monkeypatch, stream):
    repo, _base, _head = repository
    _history(repo)
    interpreter = tmp_path / "unsteady-python"
    interpreter.write_text(UNSTEADY.format(python=sys.executable), encoding="utf-8")
    interpreter.chmod(0o755)
    monkeypatch.setenv("A11_TEST_COUNTER", str(tmp_path / "doctor-calls"))
    monkeypatch.setenv("A11_TEST_STREAM", stream)
    output = tmp_path / "private-output"
    assert _main(str(repo), "--runs", "2", "--changes", "2", "--branch", "main", "--output", str(output),
                 python=str(interpreter)) == 1
    shown = capsys.readouterr().out
    assert "A11: 0 of 4 checks" in shown and f"checks whose {stream} differed: 4" in shown
    other = {"output": "error output", "error output": "output"}[stream]
    assert f"checks whose {other} differed" not in shown
    kept = sorted(path.name for path in output.iterdir() if path.suffix in (".out", ".err"))
    assert len(kept) == 4 * 2 * 2  # every run of every differing check, both streams, kept privately


def test_a_difference_is_named_by_stream_never_by_field_value_or_path(repository, tmp_path, capsys, monkeypatch):
    repo, _base, _head = repository
    _history(repo)
    original, calls = stability.run_raw, itertools.count()

    def unsteady(command_line, arguments, cwd, environment):
        done = original(command_line, arguments, cwd, environment)
        if next(calls) % 2:
            report = json.loads(done.stdout.splitlines()[-1])
            report["synthetic_private_positions"] = "SYNTHETIC-VALUE"
            report["/private/positions.csv"] = "SYNTHETIC-LATER"
            done = subprocess.CompletedProcess(done.args, done.returncode, json.dumps(report).encode() + b"\n",
                                               done.stderr)
        return done

    monkeypatch.setattr(stability, "run_raw", unsteady)
    output = tmp_path / "private-output"
    assert _main(str(repo), "--runs", "2", "--changes", "2", "--branch", "main", "--output", str(output)) == 1
    shown = capsys.readouterr().out
    assert "A11: 0 of 4 checks" in shown and "checks whose output differed: 4" in shown
    assert "SYNTHETIC" not in shown and "positions" not in shown and str(repo) not in shown


@pytest.mark.parametrize("runs", ["1", "0"])
def test_fewer_than_two_runs_is_refused_before_anything_is_created(repository, tmp_path, runs):
    repo, _base, _head = repository
    output = tmp_path / "private-output"
    assert _main(str(repo), "--runs", runs, "--output", str(output)) == 2
    assert not output.exists()


def test_a_run_with_no_report_makes_the_measurement_incomplete(repository, tmp_path, capsys, monkeypatch):
    repo, _base, _head = repository
    _history(repo)

    def silent(command_line, arguments, cwd, environment):
        return subprocess.CompletedProcess([*command_line, *arguments], 1, b"", b"")

    monkeypatch.setattr(stability, "run_raw", silent)
    output = tmp_path / "private-output"
    assert _main(str(repo), "--runs", "2", "--changes", "2", "--branch", "main", "--output", str(output)) == 2
    assert "INCOMPLETE" in capsys.readouterr().out
    assert not (output / "tips.txt").exists()
