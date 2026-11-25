"""Which program a local recipe runs: `recipe_python` for a leading `python`, PATH for the rest."""

from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from conftest import command
from test_workflow import workflow_case as workflow_case
from test_workflow_execution import execution_case as execution_case, new_run, run
from finassist import runner
from finassist.cli import main
from finassist.config import Config, load_config
from finassist.errors import AssistantError
from finassist.runner import run_recipe


def _program(directory: Path, name: str) -> Path:
    """A file the platform's PATH search treats as a program (it is never started here)."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + ".EXE" if os.name == "nt" else name)
    path.write_text("synthetic\n", encoding="utf-8")
    path.chmod(0o755)
    return path

# The repository checks still need Git when a test narrows PATH to its own directories.
_GIT_DIRECTORY = Path(shutil.which("git") or "git").parent


@pytest.fixture
def captured(monkeypatch):
    """Record each argv the runner would start, and report a passing run without starting it."""
    calls = []

    def fake(argv, *, cwd, env, timeout, max_bytes=1_000_000):
        calls.append(list(argv))
        return {"exit_code": 0, "timed_out": False, "output_limit_exceeded": False, "passed": True,
                "output": "", "elapsed_seconds": 0.0}

    monkeypatch.setattr(runner, "run_bounded", fake)
    return calls


def _run(config, tmp_path, recipe, repo=None, head=None):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir(exist_ok=True)
    config = replace(config, recipes={"unit": recipe})
    return run_recipe(config, "unit", snapshot, backend="local", approve_local=True, repo=repo, head=head)


def _commit(repo: Path) -> str:
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
                    "commit", "-qm", "synthetic", "--allow-empty"], check=True, env=environment)
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
                          env=environment).stdout.strip()


def _repository(path: Path) -> Path:
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(path), "init", "-q"], check=True, env=environment)
    (path / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    return path


def _track(repo: Path, *names: str) -> None:
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", str(repo), "add", "--", *names], check=True, env=environment)


def _path(monkeypatch, *entries):
    separator = ";" if os.name == "nt" else os.pathsep
    monkeypatch.setenv("PATH", separator.join(str(entry) for entry in entries))


def test_default_takes_python_from_an_absolute_path_entry_never_the_snapshot_or_cwd(
        tmp_path, monkeypatch, captured):
    snapshot = tmp_path / "snapshot"
    _program(snapshot, "python")
    _program(tmp_path / "cwd", "python")
    monkeypatch.chdir(tmp_path / "cwd")
    expected = _program(tmp_path / "env" / "bin", "python")
    _path(monkeypatch, "", ".", "relative", tmp_path / "env" / "bin")
    assert _run(Config(), tmp_path, ["python", "-c", "print(1)"])["receipt"]["passed"]
    assert captured == [[str(expected), "-c", "print(1)"]]


def test_default_falls_back_to_python3(tmp_path, monkeypatch, captured):
    expected = _program(tmp_path / "bin", "python3")
    _path(monkeypatch, tmp_path / "bin")
    _run(Config(), tmp_path, ["python", "-c", "print(1)"])
    assert captured == [[str(expected), "-c", "print(1)"]]


def test_no_interpreter_on_path_is_a_named_refusal(tmp_path, monkeypatch, captured):
    (tmp_path / "empty").mkdir()
    _path(monkeypatch, tmp_path / "empty")
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, ["python", "-c", "print(1)"])
    assert caught.value.code == "recipe_python_not_found"
    assert caught.value.public_details == {"setting": "path"}
    assert captured == []


def test_finassist_setting_keeps_its_own_interpreter(tmp_path, monkeypatch, captured):
    (tmp_path / "empty").mkdir()
    _path(monkeypatch, tmp_path / "empty")
    _run(replace(Config(), recipe_python="finassist"), tmp_path, ["python", "-c", "print(1)"])
    assert captured == [[sys.executable, "-c", "print(1)"]]


def test_absolute_setting_names_the_interpreter_and_must_exist(tmp_path, monkeypatch, captured):
    pinned = _program(tmp_path / "project" / "venv", "python")
    _program(tmp_path / "bin", "python")
    _path(monkeypatch, tmp_path / "bin")
    _run(replace(Config(), recipe_python=str(pinned)), tmp_path, ["python", "-c", "print(1)"])
    assert captured == [[str(pinned), "-c", "print(1)"]]
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(tmp_path / "missing" / "python")), tmp_path, ["python", "-V"])
    assert caught.value.code == "recipe_python_not_found"


@pytest.mark.parametrize("value", ["python", ".venv/bin/python", "venv\\Scripts\\python.exe", "a\0b"])
def test_relative_or_bare_setting_is_refused_when_the_configuration_loads(value):
    with pytest.raises(AssistantError) as caught:
        replace(Config(), recipe_python=value).validate()
    assert caught.value.code == "invalid_recipe_python"


def test_setting_loads_from_json_and_its_default_leaves_the_hash_unset():
    from finassist.config import config_identity

    assert "recipe_python" not in config_identity(Config())
    assert load_config(content=b'{"recipe_python": "finassist"}').recipe_python == "finassist"
    assert "recipe_python" in config_identity(replace(Config(), recipe_python="finassist"))


def test_batch_shim_interpreter_is_refused(tmp_path, captured):
    shim = tmp_path / "python.bat"
    shim.write_text("@echo synthetic\n", encoding="utf-8")
    shim.chmod(0o755)
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(shim)), tmp_path, ["python", "-V"])
    assert caught.value.code == "batch_tool_not_supported"
    # Named as a batch file, it is refused as one even when it does not exist.
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(tmp_path / "missing" / "python.cmd")), tmp_path, ["python", "-V"])
    assert caught.value.code == "batch_tool_not_supported"
    assert captured == []


def test_missing_module_is_refused_before_the_recipe_runs(tmp_path):
    config = replace(Config(), recipe_python="finassist")
    with pytest.raises(AssistantError) as caught:
        _run(config, tmp_path, ["python", "-m", "finassist_synthetic_absent_module", "-q"])
    assert caught.value.code == "recipe_python_module_missing"
    assert caught.value.public_details == {"module": "finassist_synthetic_absent_module"}


def test_present_module_runs_with_the_chosen_interpreter(tmp_path):
    result = _run(replace(Config(), recipe_python="finassist"), tmp_path, ["python", "-m", "platform"])
    assert result["receipt"]["passed"], result["output"]
    assert result["output"].strip()


def test_interpreter_that_fails_the_module_check_is_unusable(tmp_path, monkeypatch):
    calls = []

    def failing(argv, **_kwargs):
        calls.append(argv)
        return {"exit_code": 1, "timed_out": False, "output_limit_exceeded": False, "passed": False,
                "output": "", "elapsed_seconds": 0.0}

    monkeypatch.setattr(runner, "run_bounded", failing)
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python="finassist"), tmp_path, ["python", "-m", "pytest"])
    assert caught.value.code == "recipe_python_unusable"
    # The lookup, then the interpreter alone (isolated); the recipe itself never starts.
    assert len(calls) == 2 and calls[0][1:5] == ["-I", "-c", runner._PROBE, "pytest"]
    assert calls[1][1:] == ["-I", "-c", ""]


def test_only_python_dash_m_is_probed(tmp_path, captured):
    config = replace(Config(), recipe_python="finassist")
    _run(config, tmp_path, ["python", "-m", "pytest", "-q"])
    _run(config, tmp_path, ["python", "check_cash.py"])
    _run(config, tmp_path, ["python", "-m", "not a module"])
    assert captured[0][1:5] == ["-I", "-c", runner._PROBE, "pytest"]
    assert [call[1:] for call in captured[1:]] == [["-m", "pytest", "-q"], ["check_cash.py"], ["-m", "not a module"]]


def test_other_programs_come_from_absolute_path_entries_only(tmp_path, monkeypatch, captured):
    _program(tmp_path / "snapshot", "synthetic-tool")
    monkeypatch.chdir(tmp_path / "snapshot")
    (tmp_path / "empty").mkdir()
    _path(monkeypatch, ".", "", tmp_path / "empty")
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, ["synthetic-tool", "--check"])
    assert caught.value.code == "recipe_program_not_found"
    assert caught.value.public_details == {"program": "synthetic-tool"}
    tool = _program(tmp_path / "bin", "synthetic-tool")
    _path(monkeypatch, ".", tmp_path / "bin")
    _run(Config(), tmp_path, ["synthetic-tool", "--check"])
    assert captured == [[str(tool), "--check"]]


def test_a_program_written_as_a_path_is_left_as_written(tmp_path, monkeypatch, captured):
    (tmp_path / "empty").mkdir()
    _path(monkeypatch, tmp_path / "empty")
    explicit = str(tmp_path / "tools" / "check")
    relative = os.path.join("scripts", "check")
    script = "." + os.sep + "run-tests.sh"
    _run(Config(), tmp_path, [explicit, "-q"])
    _run(Config(), tmp_path, [relative])
    # A relative path names the change's own script in the snapshot, exactly as before.
    _run(Config(), tmp_path, [script, "-x"])
    assert captured == [[explicit, "-q"], [relative], [script, "-x"]]


def test_container_backend_leaves_python_to_the_image(tmp_path, monkeypatch):
    seen = []

    def fake(argv, **_kwargs):
        seen.append(argv)
        return {"exit_code": 0, "timed_out": False, "output_limit_exceeded": False, "passed": True,
                "output": "", "elapsed_seconds": 0.0}

    monkeypatch.setattr(runner, "run_bounded", fake)
    monkeypatch.setattr(runner, "find_tool", lambda name: "/synthetic/" + name)
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: type(
        "Done", (), {"returncode": 1 if a[0][1] == "container" else 0, "stderr": b""})())
    config = replace(Config(), runner_image="sha256:" + "a" * 64, recipe_python="finassist",
                     recipes={"unit": ["python", "-m", "pytest"]})
    (tmp_path / "snapshot").mkdir()
    run_recipe(config, "unit", tmp_path / "snapshot", backend="docker")
    assert len(seen) == 1 and seen[0][-3:] == ["python", "-m", "pytest"]


@pytest.mark.skipif(os.name != "nt", reason="PATHEXT shims are a Windows search rule")
def test_a_batch_shim_found_on_path_is_refused(tmp_path, monkeypatch, captured):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "synthetic-tool.cmd").write_text("@echo synthetic\n", encoding="utf-8")
    _path(monkeypatch, tmp_path / "bin")
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, ["synthetic-tool"])
    assert caught.value.code == "batch_tool_not_supported"
    assert captured == []


def test_an_interpreter_inside_the_snapshot_is_refused(tmp_path, monkeypatch, captured):
    planted = _program(tmp_path / "snapshot" / "bin", "python")
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(planted)), tmp_path, ["python", "-V"])
    assert caught.value.code == "recipe_program_inside_change"
    # The same file reached through an absolute PATH entry into the snapshot is refused too.
    _path(monkeypatch, tmp_path / "snapshot" / "bin")
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, ["python", "-V"])
    assert caught.value.code == "recipe_program_inside_change"
    assert captured == []


def test_a_program_git_tracks_in_the_repository_is_refused(tmp_path, monkeypatch, captured):
    repo = _repository(tmp_path / "project")
    committed = _program(repo / "tools", "python")
    _track(repo, committed.relative_to(repo).as_posix())
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(committed)), tmp_path, ["python", "-V"], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"
    _path(monkeypatch, repo / "tools", _GIT_DIRECTORY)
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, ["python", "-V"], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"
    assert captured == []


def test_an_ignored_environment_inside_the_repository_is_allowed(tmp_path, monkeypatch, captured):
    repo = _repository(tmp_path / "project")
    environment = _program(repo / ".venv" / ("Scripts" if os.name == "nt" else "bin"), "python")
    _path(monkeypatch, environment.parent, _GIT_DIRECTORY)
    _run(Config(), tmp_path, ["python", "-V"], repo=repo)
    _run(replace(Config(), recipe_python=str(environment)), tmp_path, ["python", "-V"], repo=repo)
    assert captured == [[str(environment), "-V"], [str(environment), "-V"]]


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_a_link_to_a_tracked_file_is_refused(tmp_path, captured):
    repo = _repository(tmp_path / "project")
    committed = _program(repo / "tools", "python")
    _track(repo, "tools/python")
    link = repo / ".venv" / "bin" / "python"
    link.parent.mkdir(parents=True)
    link.symlink_to(committed)
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(link)), tmp_path, ["python", "-V"], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"


@pytest.mark.skipif(os.name != "nt", reason="PATHEXT suffixes are a Windows search rule")
def test_windows_finds_the_exe_and_skips_the_current_directory(tmp_path, monkeypatch, captured):
    (tmp_path / "cwd").mkdir()
    (tmp_path / "cwd" / "synthetic-tool.exe").write_text("synthetic", encoding="utf-8")
    monkeypatch.chdir(tmp_path / "cwd")
    tool = _program(tmp_path / "bin", "synthetic-tool")
    _path(monkeypatch, tmp_path / "bin")
    _run(Config(), tmp_path, ["synthetic-tool"])
    assert captured == [[str(tool)]]
    assert tool.suffix.lower() == ".exe"


def test_a_case_variant_of_a_tracked_folder_is_refused(tmp_path, monkeypatch, captured):
    # On a case-insensitive disk .venv and .VENV are one folder; the index can still say .VENV.
    repo = _repository(tmp_path / "project")
    tool = _program(repo / ".VENV" / "bin", "tool")
    # Forced: where Git ignores case (macOS, Windows), .gitignore's .venv/ also matches .VENV.
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", str(repo), "add", "-f", "--", ".VENV/bin/" + tool.name], check=True,
                   env=environment)
    on_disk = _program(repo / ".venv" / "bin", "python")
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(on_disk)), tmp_path, ["python", "-V"], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"
    assert captured == []


def test_a_folder_tracked_only_at_the_reviewed_commit_is_refused(tmp_path, captured):
    repo = _repository(tmp_path / "project")
    tool = _program(repo / "tools", "python")
    _track(repo, "tools/" + tool.name)
    head = _commit(repo)
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", str(repo), "rm", "-q", "--cached", "tools/" + tool.name], check=True,
                   env=environment)
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(tool)), tmp_path, ["python", "-V"], repo=repo, head=head)
    assert caught.value.code == "recipe_program_inside_change"
    # Without the reviewed commit, the untracked file is not one a change supplied.
    _run(replace(Config(), recipe_python=str(tool)), tmp_path, ["python", "-V"], repo=repo)
    assert captured == [[str(tool), "-V"]]


def test_dot_dot_segments_are_normalized_before_the_check(tmp_path, captured):
    repo = _repository(tmp_path / "project")
    tool = _program(repo / "tools", "python")
    _track(repo, "tools/" + tool.name)
    (repo / "sub").mkdir()
    winding = str(repo / "sub") + os.sep + ".." + os.sep + "tools" + os.sep + tool.name
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=winding), tmp_path, ["python", "-V"], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_a_tracked_link_reached_through_a_linked_parent_is_refused(tmp_path, captured):
    outside = _program(tmp_path / "outside", "python")
    real = _repository(tmp_path / "real-project")
    (real / "tools").mkdir()
    (real / "tools" / "python").symlink_to(outside)
    _track(real, "tools/python")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(alias / "tools" / "python")), tmp_path, ["python", "-V"], repo=real)
    assert caught.value.code == "recipe_program_inside_change"


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_a_tracked_folder_link_is_refused(tmp_path, captured):
    outside = tmp_path / "outside-bin"
    tool = _program(outside, "python")
    repo = _repository(tmp_path / "project")
    (repo / "bin").symlink_to(outside, target_is_directory=True)
    _track(repo, "bin")
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(repo / "bin" / tool.name)), tmp_path, ["python", "-V"], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"


def test_bare_and_explicit_programs_get_the_same_checks(tmp_path, monkeypatch, captured):
    repo = _repository(tmp_path / "project")
    tool = _program(repo / "tools", "synthetic-tool")
    _track(repo, "tools/" + tool.name)
    _path(monkeypatch, repo / "tools", _GIT_DIRECTORY)
    for recipe in (["synthetic-tool", "--check"], [str(tool), "--check"]):
        with pytest.raises(AssistantError) as caught:
            _run(Config(), tmp_path, recipe, repo=repo)
        assert caught.value.code == "recipe_program_inside_change"
    assert captured == []


def test_an_explicit_batch_file_is_refused_however_it_is_named(tmp_path, captured):
    for name in ("npm.cmd", "build.BAT"):
        with pytest.raises(AssistantError) as caught:
            _run(Config(), tmp_path, [str(tmp_path / "tools" / name), "install"])
        assert caught.value.code == "batch_tool_not_supported"
    assert captured == []


def test_a_bare_repository_checks_only_the_snapshot(tmp_path, captured):
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True, env=environment)
    tool = _program(tmp_path / "bin", "python")
    _run(replace(Config(), recipe_python=str(tool)), tmp_path, ["python", "-V"], repo=bare)
    assert captured == [[str(tool), "-V"]]


def test_a_lookup_broken_by_the_snapshot_lets_the_recipe_record_it(tmp_path, monkeypatch):
    # The lookup fails some other way and the interpreter works on its own, so the recipe runs and its
    # saved record holds the failure, instead of a refusal with no record.
    calls = []

    def sequence(argv, **_kwargs):
        calls.append(argv)
        failed = len(calls) in {1, 3}
        return {"exit_code": 1 if failed else 0, "timed_out": False, "output_limit_exceeded": False,
                "passed": not failed, "output": "synthetic traceback" if failed else "", "elapsed_seconds": 0.0}

    monkeypatch.setattr(runner, "run_bounded", sequence)
    result = _run(replace(Config(), recipe_python="finassist"), tmp_path, ["python", "-m", "pytest", "-q"])
    assert [call[1:3] for call in calls] == [["-I", "-c"], ["-I", "-c"], ["-m", "pytest"]]
    assert result["receipt"]["passed"] is False and result["output"] == "synthetic traceback"


def test_only_the_top_level_package_is_looked_up(tmp_path):
    # A missing submodule is the recipe's own failure, held in its saved record; no project code runs first.
    result = _run(replace(Config(), recipe_python="finassist"), tmp_path, ["python", "-m", "json.no_such_submodule"])
    assert result["receipt"]["passed"] is False


@pytest.mark.skipif(os.name != "nt", reason="drive-relative paths exist only on Windows")
def test_a_drive_relative_program_is_refused(tmp_path, captured):
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, ["C:python", "-V"])
    assert caught.value.code == "recipe_program_not_found"
    assert captured == []


@pytest.mark.skipif(os.name != "nt", reason="root-relative paths are a Windows form")
def test_a_root_relative_program_is_refused(tmp_path, captured):
    # Its drive is the current directory's, which need not be the drive it was checked on.
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, ["\\tools\\check.exe"])
    assert caught.value.code == "recipe_program_not_found"
    assert captured == []


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_a_link_before_dot_dot_is_followed_as_the_system_follows_it(tmp_path, captured):
    # The system reads link/.. as the link target's parent; a lexical tidy-up would read it as link's.
    repo = _repository(tmp_path / "project")
    _program(repo / "tools", "python")
    _track(repo, "tools/python")
    (repo / "sub").mkdir()
    planted = _program(tmp_path / "snapshot" / "bin", "python")
    (tmp_path / "snapshot" / "sub").mkdir()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "into-repo").symlink_to(repo / "sub", target_is_directory=True)
    (tmp_path / "elsewhere" / "into-snapshot").symlink_to(tmp_path / "snapshot" / "sub", target_is_directory=True)
    for link, rest in (("into-repo", ("tools", "python")), ("into-snapshot", ("bin", planted.name))):
        winding = os.sep.join([str(tmp_path / "elsewhere" / link), "..", *rest])
        with pytest.raises(AssistantError) as caught:
            _run(replace(Config(), recipe_python=winding), tmp_path, ["python", "-V"], repo=repo)
        assert caught.value.code == "recipe_program_inside_change"
    assert captured == []


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_a_tracked_folder_link_reached_through_a_linked_parent_is_refused(tmp_path, captured):
    outside = tmp_path / "outside-bin"
    tool = _program(outside, "python")
    real = _repository(tmp_path / "real-project")
    (real / "bin").symlink_to(outside, target_is_directory=True)
    _track(real, "bin")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(alias / "bin" / tool.name)), tmp_path, ["python", "-V"], repo=real)
    assert caught.value.code == "recipe_program_inside_change"
    assert captured == []


def test_a_repository_named_by_a_subfolder_is_checked_from_its_top(tmp_path, captured):
    repo = _repository(tmp_path / "project")
    tool = _program(repo / "tools", "python")
    _track(repo, "tools/" + tool.name)
    (repo / "sub").mkdir()
    config = replace(Config(), recipe_python=str(tool))
    with pytest.raises(AssistantError) as caught:
        _run(config, tmp_path, ["python", "-V"], repo=repo / "sub")
    assert caught.value.code == "recipe_program_inside_change"
    head = _commit(repo)
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", str(repo), "rm", "-q", "--cached", "tools/" + tool.name], check=True, env=environment)
    with pytest.raises(AssistantError) as caught:
        _run(config, tmp_path, ["python", "-V"], repo=repo / "sub", head=head)
    assert caught.value.code == "recipe_program_inside_change"
    # A Git folder has no work tree to check against, so nothing runs.
    with pytest.raises(AssistantError) as caught:
        _run(config, tmp_path, ["python", "-V"], repo=repo / ".git")
    assert caught.value.code == "git_read_failed"
    assert captured == []


def test_a_windows_name_that_carries_its_suffix_is_found_as_written(tmp_path):
    from finassist.platform_support import locate_tool

    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "pwsh.exe").write_text("synthetic", encoding="utf-8")
    environment = {"PATH": str(tmp_path / "bin"), "PATHEXT": ".COM;.EXE;.BAT;.CMD"}
    # Before, "pwsh.exe" was searched as "pwsh.exe.EXE" and so on, and never found.
    assert locate_tool("pwsh.exe", environment, windows=True) == str(tmp_path / "bin" / "pwsh.exe")


@pytest.mark.parametrize("name, batch", [
    ("C:\\tools\\build.bat.", True), ("C:\\tools\\build.cmd ", True), ("npm.CMD", True),
    ("C:\\tools\\pwsh.exe", False), ("C:\\tools\\build.cmd.exe", False)])
def test_windows_drops_trailing_dots_and_spaces_before_the_batch_check(name, batch):
    assert runner._batch(name, windows=True) is batch


def test_a_bare_batch_name_is_refused_even_when_path_lacks_it(tmp_path, monkeypatch, captured):
    (tmp_path / "empty").mkdir()
    _path(monkeypatch, tmp_path / "empty")
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, ["npm.cmd", "install"])
    assert caught.value.code == "batch_tool_not_supported"
    assert captured == []


def test_the_module_lookup_runs_none_of_the_snapshot(tmp_path):
    marker = tmp_path / "ran"
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "sitecustomize.py").write_text(f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python="finassist"), tmp_path, ["python", "-m", "finassist_synthetic_absent"])
    assert caught.value.code == "recipe_python_module_missing"
    assert not marker.exists()


def test_the_module_lookup_still_sees_the_snapshot_folders(tmp_path):
    package = tmp_path / "snapshot" / "src" / "synthetic_pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("raise SystemExit(3)\n", encoding="utf-8")
    # Found without being run; the recipe then runs it and its saved record holds the exit.
    result = _run(replace(Config(), recipe_python="finassist"), tmp_path, ["python", "-m", "synthetic_pkg"])
    assert result["receipt"]["passed"] is False and result["receipt"]["exit_code"] == 3


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_dot_dot_after_a_tracked_link_is_still_seen_at_the_link(tmp_path, captured):
    # repo/tools is a tracked link to outside/sub; repo/tools/../.venv/bin/python runs outside/.venv/bin/python.
    (tmp_path / "outside" / "sub").mkdir(parents=True)
    _program(tmp_path / "outside" / ".venv" / "bin", "python")
    repo = _repository(tmp_path / "project")
    (repo / "tools").symlink_to(tmp_path / "outside" / "sub", target_is_directory=True)
    _track(repo, "tools")
    _program(repo / ".venv" / "bin", "python")
    winding = os.sep.join([str(repo), "tools", "..", ".venv", "bin", "python"])
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=winding), tmp_path, ["python", "-V"], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"
    # The ignored environment itself, written plainly, is still allowed.
    _run(replace(Config(), recipe_python=str(repo / ".venv" / "bin" / "python")), tmp_path, ["python", "-V"], repo=repo)
    assert captured == [[str(repo / ".venv" / "bin" / "python"), "-V"]]


def _refused(tmp_path, program, repo):
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(program)), tmp_path, ["python", "-V"], repo=repo)
    return caught.value.code


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_a_chain_of_links_is_followed_one_hop_at_a_time(tmp_path, captured):
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "sub").mkdir(parents=True)
    _program(elsewhere / ".venv" / "bin", "python")
    real_bin = elsewhere / "real-bin"
    _program(real_bin, "python")
    repo = _repository(tmp_path / "project")
    venv = _program(repo / ".venv" / "bin", "evil")
    (repo / "tools").mkdir()
    (repo / "tools" / "python").symlink_to(venv)  # a tracked file link into the ignored folder
    (repo / "bin").symlink_to(real_bin, target_is_directory=True)  # a tracked folder link
    (repo / "linked").symlink_to(elsewhere / "sub", target_is_directory=True)  # a tracked folder link
    _track(repo, "tools/python", "bin", "linked")
    outside = tmp_path / "outside"
    outside.mkdir()
    # A file link to a tracked file link; a folder link to a tracked folder link; `..` inside a target.
    (outside / "python").symlink_to(repo / "tools" / "python")
    (outside / "alias-bin").symlink_to(repo / "bin", target_is_directory=True)
    (outside / "runner").symlink_to(str(repo) + "/linked/../.venv/bin/python")
    for program in (outside / "python", outside / "alias-bin" / "python", outside / "runner"):
        assert _refused(tmp_path, program, repo) == "recipe_program_inside_change", program
    assert captured == []


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_a_link_loop_is_refused(tmp_path, captured):
    (tmp_path / "a").symlink_to(tmp_path / "b")
    (tmp_path / "b").symlink_to(tmp_path / "a")
    assert _refused(tmp_path, tmp_path / "a", None) in {"recipe_python_not_found", "recipe_program_not_found"}
    assert runner._entries(str(tmp_path / "bin" / "x")) >= {tmp_path / "bin" / "x"}
    with pytest.raises(AssistantError) as caught:
        runner._entries(str(tmp_path / "a" / "python"))
    assert caught.value.code == "recipe_program_not_found"
    assert captured == []


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_every_entry_read_on_the_way_is_listed_once_per_hop(tmp_path):
    # outside/hop -> first/sub/../next, and first/next -> ../second: each link, and where each `..` really leads.
    (tmp_path / "first" / "sub").mkdir(parents=True)
    (tmp_path / "second").mkdir()
    (tmp_path / "second" / "tool").write_text("synthetic\n", encoding="utf-8")
    (tmp_path / "first" / "next").symlink_to("../second", target_is_directory=True)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "hop").symlink_to(str(tmp_path / "first" / "sub") + "/../next")
    entries = runner._entries(str(tmp_path / "outside" / "hop" / "tool"))
    assert {tmp_path / "outside" / "hop", tmp_path / "first" / "sub", tmp_path / "first" / "next",
            tmp_path / "second", tmp_path / "second" / "tool"} <= entries
    # Nothing is invented: the lexical reading outside/tool was never an entry the system read.
    assert tmp_path / "outside" / "tool" not in entries


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_a_link_from_outside_to_an_ignored_environment_is_allowed(tmp_path, captured):
    repo = _repository(tmp_path / "project")
    environment = _program(repo / ".venv" / "bin", "python")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "python").symlink_to(environment)
    _run(replace(Config(), recipe_python=str(tmp_path / "bin" / "python")), tmp_path, ["python", "-V"], repo=repo)
    assert captured == [[str(tmp_path / "bin" / "python"), "-V"]]


@pytest.mark.skipif(os.name == "nt", reason="a leading // is a POSIX form")
def test_a_root_written_with_two_slashes_is_the_same_root(tmp_path, captured):
    repo = _repository(tmp_path / "project")
    tool = _program(repo / "tools", "python")
    _track(repo, "tools/" + tool.name)
    planted = _program(tmp_path / "snapshot" / "bin", "python")
    for program in ("/" + str(tool), "/" + str(planted)):
        assert _refused(tmp_path, program, repo) == "recipe_program_inside_change", program
    assert captured == []


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_a_link_to_the_root_is_the_root(tmp_path, captured):
    repo = _repository(tmp_path / "project")
    tool = _program(repo / "tools", "python")
    _track(repo, "tools/" + tool.name)
    (tmp_path / "alias").symlink_to(repo, target_is_directory=True)
    # Found by which folder it is on disk, even if a path were written through the alias.
    assert runner._below(tmp_path / "alias" / "tools" / "python", repo) == tmp_path / "alias" / "tools"
    assert runner._below(tmp_path / "elsewhere" / "python", repo) is None
    assert runner._below(repo, repo) is None
    assert _refused(tmp_path, tmp_path / "alias" / "tools" / "python", repo) == "recipe_program_inside_change"
    assert captured == []


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need extra rights on Windows")
def test_the_path_is_also_read_as_the_system_resolves_it(tmp_path, monkeypatch, captured):
    # A link the part-by-part reading does not recognise as one (an older junction, say) is still followed
    # by the system: the resolved path is read too.
    repo = _repository(tmp_path / "project")
    _program(repo / "tools", "python")
    _track(repo, "tools/python")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "unknown-link").symlink_to(repo / "tools", target_is_directory=True)
    monkeypatch.setattr(runner, "_is_link", lambda item: False)
    assert _refused(tmp_path, tmp_path / "outside" / "unknown-link" / "python", repo) == "recipe_program_inside_change"
    assert captured == []


@pytest.mark.skipif(os.name == "nt", reason="hard links to a file under a second name are set up on POSIX here")
def test_a_second_name_of_a_tracked_entry_is_that_entry(tmp_path, captured):
    # One file, two names at the top of the repository: Git tracks one, the recipe names the other.
    repo = _repository(tmp_path / "project")
    tracked = _program(repo, "run-checks")
    _track(repo, tracked.name)
    second = repo / "untracked-name"
    os.link(tracked, second)
    assert runner._names(repo, second) == {"untracked-name", tracked.name}
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, [str(second)], repo=repo)
    assert caught.value.code == "recipe_program_inside_change"
    # An untracked file with a name of its own is not one the change supplied.
    alone = _program(repo, "local-tool")
    _run(Config(), tmp_path, [str(alone)], repo=repo)
    assert captured == [[str(alone)]]


def test_windows_extended_and_unc_link_targets_are_read_as_plain_paths():
    assert runner._plain_windows("\\\\?\\C:\\repo\\tools") == "C:\\repo\\tools"
    assert runner._plain_windows("\\\\?\\UNC\\server\\share\\x") == "\\\\server\\share\\x"
    assert runner._plain_windows("\\\\?\\unc\\server\\share") == "\\\\server\\share"
    assert runner._plain_windows("\\??\\D:\\x") == "D:\\x"
    assert runner._plain_windows("relative\\x") == "relative\\x"
    from pathlib import PureWindowsPath as W

    unc = W(runner._plain_windows("\\\\?\\UNC\\server\\share\\x"))
    assert unc.anchor == "\\\\server\\share\\"


def test_a_windows_target_with_a_root_and_no_drive_keeps_the_current_drive():
    from pathlib import PureWindowsPath as W

    assert runner._start(W("\\repo\\tools\\python.exe"), W("D:\\links")) == W("D:\\")
    assert runner._start(W("C:\\repo"), W("D:\\links")) == W("C:\\")
    assert runner._start(W("\\\\server\\share\\x"), W("D:\\links")) == W("\\\\server\\share\\")


@pytest.mark.skipif(os.name != "nt", reason="the implied .exe is a Windows rule")
def test_windows_checks_the_exe_a_suffixless_path_runs(tmp_path, monkeypatch, captured):
    seen = []
    original = runner._entries
    monkeypatch.setattr(runner, "_entries", lambda program: seen.append(program) or original(program))
    program = str(tmp_path / "tools" / "check")
    _run(Config(), tmp_path, [program])
    assert {program, program + ".exe"} <= set(seen) and all(item.lower().endswith("check.exe") or item in {
        program, os.path.realpath(program)} for item in seen)
    del seen[:]
    _run(Config(), tmp_path, [program + ".com"])
    assert program + ".com" in seen and not any(item.lower().endswith(".exe") for item in seen)


@pytest.mark.skipif(os.name != "nt", reason="PATHEXT suffixes are a Windows search rule")
def test_windows_finds_a_bare_name_written_with_its_suffix(tmp_path, monkeypatch, captured):
    tool = _program(tmp_path / "bin", "synthetic-tool")
    _path(monkeypatch, tmp_path / "bin")
    _run(Config(), tmp_path, [tool.name, "--check"])
    assert captured == [[str(tool), "--check"]]


@pytest.mark.skipif(os.name != "nt", reason="trailing dots and spaces are dropped only by Windows")
@pytest.mark.parametrize("name", ["build.cmd.", "build.bat ", "build.CMD . ."])
def test_windows_refuses_a_batch_file_named_with_trailing_dots_or_spaces(tmp_path, captured, name):
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / name.rstrip(" .")).write_text("@echo synthetic\n", encoding="utf-8")
    with pytest.raises(AssistantError) as caught:
        _run(Config(), tmp_path, [str(tmp_path / "tools") + os.sep + name])
    assert caught.value.code == "batch_tool_not_supported"
    with pytest.raises(AssistantError) as caught:
        _run(replace(Config(), recipe_python=str(tmp_path / "tools") + os.sep + name), tmp_path, ["python", "-V"])
    assert caught.value.code == "batch_tool_not_supported"
    assert captured == []


@pytest.mark.skipif(os.name != "nt", reason="drive and root forms are Windows path rules")
def test_windows_rooted_forms_do_not_depend_on_the_current_drive(tmp_path, monkeypatch, captured):
    # Refused as written, wherever the command runs: nothing is completed from the current drive or folder.
    for folder in (tmp_path, Path(os.environ.get("SystemRoot", "C:\\Windows"))):
        monkeypatch.chdir(folder)
        for program in ("\\tools\\check.exe", "/tools/check.exe", "C:check.exe", "C:tools\\check.exe"):
            with pytest.raises(AssistantError) as caught:
                _run(Config(), tmp_path, [program])
            assert caught.value.code == "recipe_program_not_found", program
        with pytest.raises(AssistantError) as caught:
            replace(Config(), recipe_python="\\tools\\python.exe").validate()
        assert caught.value.code == "invalid_recipe_python"
    assert captured == []


def test_a_name_with_another_suffix_still_gets_the_search_suffixes(tmp_path):
    from finassist.platform_support import locate_tool

    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "tool.v2.EXE").write_text("synthetic", encoding="utf-8")
    (tmp_path / "bin" / "npm.cmd").write_text("synthetic", encoding="utf-8")
    environment = {"PATH": str(tmp_path / "bin"), "PATHEXT": ".COM;.EXE;.BAT;.CMD"}
    assert locate_tool("tool.v2", environment, windows=True) == str(tmp_path / "bin" / "tool.v2.EXE")
    assert locate_tool("npm.cmd", environment, windows=True) == str(tmp_path / "bin" / "npm.cmd")
    assert locate_tool("npm.exe", environment, windows=True) is None


def test_check_gives_the_repository_and_the_reviewed_commit_to_the_program_check(repository, tmp_path, capsys):
    repo, _base, _head = repository
    tool = _program(repo / "tools", "python")
    command(repo, "add", "tools/" + tool.name)
    command(repo, "commit", "-m", "Synthetic tracked program")
    # Tracked at the commit being checked only: the index no longer lists it.
    command(repo, "rm", "-q", "--cached", "tools/" + tool.name)
    cfg, output = tmp_path / "config.json", tmp_path / "check.json"
    config = replace(Config(), recipe_python=str(tool), recipes={"unit": ["python", "-V"]})
    cfg.write_text(json.dumps(asdict(config)), encoding="utf-8", newline="\n")
    assert main(["--config", str(cfg), "check", "--repo", str(repo), "--recipe", "unit", "--backend", "local",
                 "--approve-local", "--output", str(output)]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "recipe_program_inside_change"
    assert not output.exists()


def test_a_workflow_step_gives_the_repository_and_the_reviewed_commit_to_the_program_check(
        request, tmp_path, monkeypatch):
    import finassist.workflow_execution as executor
    from finassist.workflow_state import WorkflowStore

    case = request.getfixturevalue("execution_case")
    repo, _config, _packet, plan = case
    original, seen = executor.run_recipe, []

    def tracked(config, name, snapshot, **kwargs):
        seen.append((kwargs.get("repo"), kwargs.get("head")))
        return original(config, name, snapshot, **kwargs)

    monkeypatch.setattr(executor, "run_recipe", tracked)
    with WorkflowStore(tmp_path / "state", create=True) as store:
        identifier = new_run(store, case)
        assert run(store, identifier, case, max_steps=1)["status"] == "paused"
    assert seen == [(repo, plan["head"])]
