"""One local command runs what CI runs, and the workflow lints once before the test matrix starts."""

from pathlib import Path
import subprocess
import sys
import sysconfig

import pytest
import yaml

from scripts import ci

ROOT = Path(__file__).resolve().parent.parent


def _workflow() -> dict:
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))


def _commands(job: dict) -> list[str]:
    return [step["run"] for step in job["steps"] if "run" in step]


def test_every_stage_is_the_command_the_workflow_runs():
    jobs = _workflow()["jobs"]
    # The lint job goes through the entry script, so the linter's arguments are written once.
    assert _commands(jobs["lint"]) == ["python scripts/ci_install.py dependencies", "python scripts/ci.py lint"]
    assert ci.command_line("lint") == "ruff check src tests scripts actions"
    # The test job's own steps, after installation, are the remaining stages in the same order.
    after_install = [command for command in _commands(jobs["test"]) if "ci_install.py" not in command]
    assert after_install == [ci.command_line(stage) for stage in ci.STAGES if stage != "lint"]
    assert ci.expand([ci.ALL]) == ["lint", "test", "demo", "scan", "wheel"]


def test_the_linter_runs_once_and_the_test_matrix_waits_for_it():
    jobs = _workflow()["jobs"]
    assert jobs["test"]["needs"] == "lint"
    assert jobs["lint"]["runs-on"] == "ubuntu-24.04" and jobs["lint"]["timeout-minutes"] == 5
    assert "strategy" not in jobs["lint"] and "needs" not in jobs["lint"]
    others = [command for name, job in jobs.items() if name != "lint" for command in _commands(job)]
    assert not any("ruff" in command or "ci.py" in command for command in others)
    # The checks that branch protection requires keep their names; isolation still starts at once.
    assert "needs" not in jobs["isolation"] and "name" not in jobs["isolation"]
    assert jobs["test"]["name"] == "${{ matrix.check_name }}"


def test_python_installs_are_cached_by_the_hash_of_the_lock_they_install():
    for name, job in _workflow()["jobs"].items():
        setups = [step for step in job["steps"] if step.get("uses", "").startswith("actions/setup-python@")]
        assert len(setups) == 1, name
        assert setups[0]["with"]["cache"] == "pip"
        assert setups[0]["with"]["cache-dependency-path"] == "requirements-dev.lock"
        assert "python scripts/ci_install.py dependencies" in _commands(job)  # Still hash-verified on every run.


def test_stages_run_in_the_order_given_from_the_repository_root_and_stop_at_the_first_failure(
        tmp_path, monkeypatch, capsys):
    calls = []

    def execute(command, **options):
        calls.append((command, options))
        return subprocess.CompletedProcess(command, 3 if command[-1] == "scripts/ci_test.py" else 0)

    monkeypatch.setattr(ci, "program", lambda name: "resolved-" + name)
    monkeypatch.setattr(ci.subprocess, "run", execute)
    assert ci.main(["scan", "lint"], tmp_path) == 0
    assert [command for command, _ in calls] == [
        ["resolved-finassist", "scan", "--repo", "."],
        ["resolved-ruff", "check", "src", "tests", "scripts", "actions"],
    ]
    assert all(options == {"cwd": tmp_path, "check": False, "shell": False} for _, options in calls)
    assert "2 stages passed" in capsys.readouterr().out
    calls.clear()
    assert ci.main(["all"], tmp_path) == 3
    assert [command[0] for command, _ in calls] == ["resolved-ruff", "resolved-python"]  # Nothing ran after the failure.
    assert "[test] FAILED (exit 3)" in capsys.readouterr().out


def test_an_unknown_or_missing_stage_is_refused_before_anything_runs(monkeypatch, capsys):
    monkeypatch.setattr(ci.subprocess, "run", lambda *args, **options: pytest.fail("a stage ran"))
    for arguments in ([], ["lint", "deploy"]):
        with pytest.raises(SystemExit) as refusal:
            ci.main(arguments)
        assert refusal.value.code == 2
    capsys.readouterr()


def test_tools_come_only_from_the_running_interpreters_scripts_directory(tmp_path, monkeypatch):
    assert ci.program("python") == sys.executable
    scripts, elsewhere = tmp_path / "scripts", tmp_path / "elsewhere"
    for directory in (scripts, elsewhere):
        directory.mkdir()
        (directory / "other-tool").write_text("", encoding="utf-8")
    (scripts / "ruff").write_text("", encoding="utf-8")
    (elsewhere / "finassist").write_text("", encoding="utf-8")
    monkeypatch.setattr(sysconfig, "get_path", lambda name: str(scripts) if name == "scripts" else None)
    monkeypatch.setenv("PATH", str(elsewhere))
    monkeypatch.chdir(elsewhere)
    assert ci.program("ruff") == str(scripts / "ruff")
    with pytest.raises(SystemExit, match="finassist is not installed beside"):
        ci.program("finassist")  # On PATH and in the current directory, but not installed with this interpreter.
