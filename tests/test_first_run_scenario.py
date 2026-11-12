"""Run the documented offline start in order, with synthetic Git history only."""

import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

import pytest

from conftest import command, synthetic_symlink
from finassist.cli import main
from finassist.initialization_state import local_state_exclude

ROOT = Path(__file__).resolve().parents[1]


def repository_at(path, *, source=False, commit=True):
    path.mkdir()
    command(path, "init", "-b", "main")
    command(path, "config", "user.name", "Synthetic")
    command(path, "config", "user.email", "synthetic@example.invalid")
    if source:
        (path / "calculator.py").write_text("def total():\n    return 1\n")
        command(path, "add", "calculator.py")
    if commit:
        command(path, "commit", "--allow-empty", "-m", "Synthetic baseline")
    return path


def run(args, capsys):
    code = main(args)
    output = capsys.readouterr()
    assert code == 0, output.err
    return json.loads(output.out)


@pytest.mark.parametrize("source", [False, True])
def test_readme_then_first_run_commands_in_order(tmp_path, source):
    repo = repository_at(tmp_path / "repo", source=source)
    readme = (ROOT / "README.md").read_text()
    quick_start = readme.split("## Quick start", 1)[1].split("### From source", 1)[0]
    commands = re.findall(r"^finassist .+$", re.findall(r"```sh\n(.*?)```", quick_start, re.S)[0], re.M)
    assert commands == ["finassist demo", "finassist init", "finassist doctor"]
    guide = (ROOT / "docs/first-run.md").read_text()
    for block in re.findall(r"```sh\n(.*?)```", guide, re.S)[:4]:
        commands.extend(line for line in block.splitlines() if line.startswith("finassist "))
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "FINASSIST_NO_UPDATE_CHECK": "1"}
    reports = []
    for line in commands:
        # Follow the guide's explicit source/base prerequisite after the README.
        if line == "finassist init --detect --purpose quant" and not source:
            (repo / "calculator.py").write_text("def total():\n    return 1\n")
            command(repo, "add", "calculator.py")
            command(repo, "commit", "-m", "Synthetic source for first review")
        # The guide asks for a committed source change on a feature branch.
        if " plan --repo " in line:
            command(repo, "checkout", "-b", "synthetic-review")
            (repo / "calculator.py").write_text("def total():\n    return 2\n")
            command(repo, "add", "calculator.py")
            command(repo, "commit", "-m", "Synthetic change for offline review")
        args = shlex.split(line)[1:]
        result = subprocess.run([sys.executable, "-m", "finassist", *args], cwd=repo, env=env,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, (line, result.stderr)
        reports.extend(json.loads(row) for row in result.stdout.splitlines())
    assert any(report.get("replaced_initial_config") is True for report in reports)
    saved = json.loads((repo / "finassist.json").read_text())
    assert saved["generated_paths"] == [] and saved["profile"] == "quant-review"
    assert saved["allow_paths"] == ["calculator.py"]
    assert command(repo, "status", "--short") == "?? finassist.json"
    assert not (repo / ".gitignore").exists()


def test_unborn_repository_writes_no_source_authority(tmp_path, monkeypatch, capsys):
    repo = repository_at(tmp_path / "repo", commit=False)
    monkeypatch.chdir(repo)
    report = run(["init"], capsys)
    assert report["head"] is None and not report["source_detected"]
    assert report["config"]["allow_paths"] == []
    assert command(repo, "status", "--short") == "?? finassist.json"
    # Once source is committed, the same untouched setup file can be refined.
    (repo / "new.py").write_text("def value():\n    return 2\n")
    command(repo, "add", "new.py")
    command(repo, "commit", "-m", "Synthetic code")
    updated = run(["init", "--detect", "--write"], capsys)
    assert updated["config"]["allow_paths"] == ["new.py"] and updated["replaced_initial_config"]


@pytest.mark.parametrize("change", ["bytes", "copied", "template", "symlink"])
def test_only_the_initial_untouched_output_can_be_refined(tmp_path, monkeypatch, capsys, change):
    repo = repository_at(tmp_path / "repo", source=True)
    monkeypatch.chdir(repo)
    run(["init", "--template"] if change == "template" else ["init"], capsys)
    path = repo / "finassist.json"
    if change == "bytes":
        path.write_bytes(path.read_bytes() + b" ")
    elif change == "copied":
        other = repo / "copy.json"
        other.write_bytes(path.read_bytes())
        path = other
    elif change == "symlink":
        target = repo / "original.json"
        path.rename(target)
        synthetic_symlink(path, target)
    before = path.read_bytes()
    assert main(["init", "--detect", "--write", "--output", str(path)]) == 2
    assert json.loads(capsys.readouterr().err)["code"] in {"output_exists", "linked_path"}
    assert path.read_bytes() == before


def test_refinement_is_reported_backed_up_and_cannot_repeat(tmp_path, monkeypatch, capsys):
    repo = repository_at(tmp_path / "repo", source=True)
    monkeypatch.chdir(repo)
    run(["init"], capsys)
    before = (repo / "finassist.json").read_bytes()
    report = run(["init", "--detect", "--purpose", "quant", "--write"], capsys)
    assert report["replaced_initial_config"] is True
    backups = list((repo / ".finassist/setup").glob("*.before.json"))
    assert len(backups) == 1 and backups[0].read_bytes() == before
    assert main(["init", "--detect", "--write"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "output_exists"


def test_proposal_is_read_only_and_template_stays_explicit(tmp_path, monkeypatch, capsys):
    repo = repository_at(tmp_path / "repo", source=True)
    monkeypatch.chdir(repo)
    before = command(repo, "status", "--short")
    run(["init", "--detect"], capsys)
    assert command(repo, "status", "--short") == before
    assert not (repo / ".finassist").exists()
    run(["init", "--template"], capsys)
    assert json.loads((repo / "finassist.json").read_text())["profile"] == "finance-saas"


def test_ignore_rules_are_preserved_idempotent_and_local(tmp_path):
    repo = repository_at(tmp_path / "repo")
    exclude = repo / ".git/info/exclude"
    exclude.write_bytes(b"# retained\r\n*.local")
    assert local_state_exclude(repo)["status"] == "added"
    expected = b"# retained\r\n*.local\n.finassist/\n"
    assert exclude.read_bytes() == expected
    assert local_state_exclude(repo)["status"] == "already_present"
    assert exclude.read_bytes() == expected and not (repo / ".gitignore").exists()


def test_exclude_failure_reports_manual_line_without_losing_configuration(tmp_path, monkeypatch, capsys):
    from finassist import initialization_state
    repo = repository_at(tmp_path / "repo", source=True)
    monkeypatch.chdir(repo)
    real = initialization_state.git
    def refused(path, *args, **kwargs):
        if args == ("rev-parse", "--git-path", "info/exclude"):
            raise OSError("synthetic unavailable metadata path")
        return real(path, *args, **kwargs)
    monkeypatch.setattr(initialization_state, "git", refused)
    report = run(["init"], capsys)
    assert (repo / "finassist.json").exists() and report["local_ignore"]["status"] == "manual"
    assert ".finassist/" in report["local_ignore"]["instruction"]


def test_help_and_guide_index_offer_an_offline_start(capsys):
    with pytest.raises(SystemExit) as done:
        main(["--help"])
    assert done.value.code == 0
    assert "demo -> init -> doctor -> plan -> review" in capsys.readouterr().out
    assert main(["guide"]) == 0
    text = capsys.readouterr().out
    assert "first-run" in text and "configuration" in text and not text.startswith("{")
    assert main(["guide", "--json"]) == 0
    assert "topics" in json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("failure", ["missing_receipt", "bad_receipt", "readonly", "linked_receipt"])
def test_refinement_refuses_unproven_or_unwritable_output(tmp_path, monkeypatch, capsys, failure):
    repo = repository_at(tmp_path / "repo", source=True)
    monkeypatch.chdir(repo)
    run(["init"], capsys)
    output = repo / "finassist.json"
    before = output.read_bytes()
    proof = next((repo / ".finassist/setup").glob("*.json"))
    if failure == "missing_receipt":
        proof.unlink()
    elif failure == "bad_receipt":
        proof.write_text("{}")
    elif failure == "readonly":
        output.chmod(0o400)
    else:
        target = repo / "synthetic-proof.json"
        proof.rename(target)
        synthetic_symlink(proof, target)
    try:
        assert main(["init", "--detect", "--write"]) == 2
        assert json.loads(capsys.readouterr().err)["code"] in {"output_exists", "linked_path"}
        assert output.read_bytes() == before
    finally:
        output.chmod(0o600)


def test_linked_exclude_is_not_written(tmp_path):
    repo = repository_at(tmp_path / "repo")
    target = tmp_path / "synthetic-exclude"
    target.write_bytes(b"# preserve\n")
    exclude = repo / ".git/info/exclude"
    exclude.unlink()
    synthetic_symlink(exclude, target)
    assert local_state_exclude(repo)["status"] == "manual"
    assert target.read_bytes() == b"# preserve\n"


def test_linked_worktree_uses_its_git_exclude_location(tmp_path):
    repo = repository_at(tmp_path / "repo")
    worktree = tmp_path / "linked"
    command(repo, "worktree", "add", "-b", "synthetic-linked", str(worktree))
    assert local_state_exclude(worktree)["status"] == "added"
    (worktree / ".finassist").mkdir()
    (worktree / ".finassist/synthetic.json").write_text("{}")
    assert command(worktree, "status", "--short") == ""
    assert not (worktree / ".gitignore").exists()


def test_corrupt_head_is_not_treated_as_unborn(tmp_path, monkeypatch, capsys):
    repo = repository_at(tmp_path / "repo", commit=False)
    monkeypatch.chdir(repo)
    # This ref exists but names an absent object; it is not a new branch.
    (repo / ".git/refs/heads/main").write_text("1" * 40 + "\n")
    assert main(["init"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] in {"git_commit_unavailable", "git_read_failed"}
    assert not (repo / "finassist.json").exists()


def test_invalid_explicit_revision_is_not_empty_setup(tmp_path, monkeypatch, capsys):
    repo = repository_at(tmp_path / "repo")
    monkeypatch.chdir(repo)
    assert main(["init", "--revision", "missing-synthetic-ref"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "git_commit_unavailable"
    assert not (repo / "finassist.json").exists()
