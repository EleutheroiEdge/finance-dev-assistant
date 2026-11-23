"""First-run outcomes are named: an empty range, a missing input file and a folder outside Git."""

import json
import os
from pathlib import Path
import subprocess

import pytest

from finassist.cli import main
from finassist.errors import AssistantError
from finassist.scope import git, resolve


def _git(repo: Path, *args: str) -> str:
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          env=environment).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "project"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    (path / "cash.py").write_text("BALANCE = 100\n", encoding="utf-8", newline="\n")
    _git(path, "add", "cash.py")
    _git(path, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-qm", "one")
    return path


def _error(capsys) -> dict:
    return json.loads(capsys.readouterr().err.strip().splitlines()[-1])


def test_plan_on_its_own_branch_warns_that_the_range_is_empty(repo, tmp_path, capsys):
    output = tmp_path / "packet.json"
    assert main(["--audit-dir", str(tmp_path / "state"), "plan", "--repo", str(repo), "--base", "main",
                 "--head", "HEAD", "--output", str(output)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["triage"]["changes_present"] is False
    (warning,) = summary["warnings"]
    assert set(warning) == {"code", "hint"} and warning["code"] == "empty_review_scope"
    assert "HEAD~1" in warning["hint"]
    assert json.loads(output.read_text(encoding="utf-8"))["changed_paths"] == []


def test_plan_with_changes_has_no_empty_range_warning(repo, tmp_path, capsys):
    (repo / "cash.py").write_text("BALANCE = 120\n", encoding="utf-8", newline="\n")
    _git(repo, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-qam", "two")
    assert main(["--audit-dir", str(tmp_path / "state"), "plan", "--repo", str(repo), "--base", "HEAD~1",
                 "--head", "HEAD", "--output", str(tmp_path / "packet.json")]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["triage"]["changes_present"] is True
    assert "warnings" not in summary


def test_review_of_a_packet_that_was_never_written_names_the_missing_file(tmp_path, capsys):
    missing = tmp_path / "missing-sentinel-packet.json"
    assert main(["--audit-dir", str(tmp_path / "state"), "review", "--packet", str(missing),
                 "--output", str(tmp_path / "review.json")]) == 2
    error = _error(capsys)
    assert error["code"] == "input_file_not_found"
    assert "plan" in error["hint"]
    assert missing.name not in json.dumps(error)


def test_a_directory_given_as_an_input_file_is_not_found_either(tmp_path, capsys):
    assert main(["--audit-dir", str(tmp_path / "state"), "review", "--packet", str(tmp_path),
                 "--output", str(tmp_path / "review.json")]) == 2
    assert _error(capsys)["code"] == "input_file_not_found"


def test_a_folder_outside_git_is_named(tmp_path, capsys):
    outside = tmp_path / "not-a-checkout"
    outside.mkdir()
    with pytest.raises(AssistantError) as caught:
        resolve(outside, "HEAD")
    assert caught.value.code == "not_a_git_repository"
    with pytest.raises(AssistantError) as caught:
        git(outside, "ls-files")
    assert caught.value.code == "not_a_git_repository"
    assert main(["--audit-dir", str(tmp_path / "state"), "plan", "--repo", str(outside), "--base", "main",
                 "--head", "HEAD", "--output", str(tmp_path / "packet.json")]) == 2
    assert _error(capsys)["code"] == "not_a_git_repository"
    # init names the same case with its own code, whose hint offers init --template.
    assert main(["init", "--detect", "--repo", str(outside), "--purpose", "quant"]) == 2
    error = _error(capsys)
    assert error["code"] == "init_repository_required" and "init --template" in error["hint"]


def test_a_folder_that_does_not_exist_is_named(tmp_path, capsys):
    missing = tmp_path / "missing"
    for read in (lambda: resolve(missing, "HEAD"), lambda: git(missing, "ls-files")):
        with pytest.raises(AssistantError) as caught:
            read()
        assert caught.value.code == "not_a_git_repository"
    assert main(["--audit-dir", str(tmp_path / "state"), "plan", "--repo", str(missing), "--base", "main",
                 "--head", "HEAD", "--output", str(tmp_path / "packet.json")]) == 2
    assert _error(capsys)["code"] == "not_a_git_repository"


def test_every_json_input_goes_through_the_named_check(tmp_path):
    from finassist import cli

    for target in (tmp_path / "absent.json", tmp_path):
        with pytest.raises(AssistantError) as caught:
            cli._read_json(str(target))
        assert caught.value.code == "input_file_not_found"


def test_a_damaged_checkout_keeps_git_read_failed(repo):
    # A .git folder whose HEAD is unreadable makes Git say "not a git repository"; it is still a checkout.
    (repo / ".git" / "HEAD").write_text("synthetic damage\n", encoding="utf-8")
    with pytest.raises(AssistantError) as caught:
        resolve(repo, "HEAD")
    assert caught.value.code == "git_read_failed"


def test_the_phrase_inside_another_message_is_not_the_outside_git_case(repo):
    from finassist.scope import _git_failure

    assert _git_failure(b"fatal: path 'not a git repository' does not exist in 'HEAD'\n", repo).code == \
        "git_read_failed"
    assert _git_failure(b"fatal: Not a git repository (or any parent up to mount point /)\n", repo).code == \
        "git_read_failed"  # a .git entry exists here, so it is a damaged checkout


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and an account they apply to")
def test_a_checkout_that_cannot_be_entered_keeps_git_read_failed(repo):
    repo.chmod(0)
    try:
        with pytest.raises(AssistantError) as caught:
            resolve(repo, "HEAD")
        assert caught.value.code == "git_read_failed"
    finally:
        repo.chmod(0o755)


def test_a_range_changing_only_withheld_private_files_is_not_called_empty(repo, tmp_path, capsys):
    from dataclasses import replace

    from finassist.config import Config, save_config

    (repo / "src" / "data").mkdir(parents=True)
    (repo / "src" / "data" / "accounts.py").write_text("SYNTHETIC = 1\n", encoding="utf-8", newline="\n")
    _git(repo, "add", "src/data/accounts.py")
    _git(repo, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-qm", "two")
    config = tmp_path / "config.json"
    save_config(config, replace(Config(), private_paths="skip-and-report"))
    assert main(["--config", str(config), "--audit-dir", str(tmp_path / "state"), "plan", "--repo", str(repo),
                 "--base", "HEAD~1", "--head", "HEAD", "--output", str(tmp_path / "packet.json")]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["withheld_paths"]
    assert "warnings" not in summary


def test_other_git_failures_keep_their_code(repo):
    with pytest.raises(AssistantError) as caught:
        git(repo, "cat-file", "-p", "0" * 40)
    assert caught.value.code == "git_read_failed"


def test_a_dotted_path_out_of_a_checkout_is_named(repo, tmp_path, monkeypatch):
    # Git enters ../not-a-checkout; the folders above it, not the checkout it was written from, decide.
    (tmp_path / "not-a-checkout").mkdir()
    monkeypatch.chdir(repo)
    for written in (Path("..") / "not-a-checkout", Path(str(repo) + os.sep + ".." + os.sep + "not-a-checkout")):
        with pytest.raises(AssistantError) as caught:
            resolve(written, "HEAD")
        assert caught.value.code == "not_a_git_repository"


def test_an_unreadable_git_entry_keeps_git_read_failed(tmp_path, monkeypatch):
    import errno

    from finassist.scope import _git_failure

    outside = tmp_path / "not-a-checkout"
    outside.mkdir()
    original = Path.lstat

    def failing(self, *args, **kwargs):
        if self.name == ".git":
            raise OSError(errno.EIO, "synthetic I/O error")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", failing)
    assert _git_failure(b"fatal: not a git repository (or any of the parent directories): .git\n", outside).code \
        == "git_read_failed"


def test_the_search_for_a_git_entry_stops_at_a_mount_point(repo, monkeypatch):
    from finassist import scope

    (repo / "mounted").mkdir()
    mounted = Path(os.path.realpath(repo / "mounted"))  # as the search sees it, macOS /var included
    # As Git does without GIT_DISCOVERY_ACROSS_FILESYSTEM: the checkout above another file system is not searched.
    monkeypatch.setattr(scope, "_device", lambda item: 2 if Path(item) in {mounted, mounted / "inner"} else 1)
    message = b"fatal: not a git repository (or any parent up to mount point /synthetic)\n"
    assert scope._git_failure(message, mounted).code == "not_a_git_repository"


def test_init_names_a_folder_that_does_not_exist_by_its_own_code(tmp_path, capsys):
    missing = tmp_path / "missing"
    assert main(["init", "--detect", "--repo", str(missing), "--purpose", "quant"]) == 2
    error = _error(capsys)
    # Its hint says to check the folder; init_repository_required's would offer init --template.
    assert error["code"] == "not_a_git_repository" and "--repo" in error["hint"]


def _json_inputs(repo: Path, absent: Path, output: Path) -> list[list[str]]:
    packet = output.parent / "synthetic-packet.json"
    packet.write_text('{"synthetic": true}', encoding="utf-8")
    head = _git(repo, "rev-parse", "HEAD")
    hash_value = "0" * 64
    return [
        ["review", "--packet", str(absent), "--output", str(output)],
        ["propose", "--packet", str(absent), "--output", str(output)],
        ["workflow", "preflight", "--repo", str(repo), "--packet", str(absent), "--plan", str(absent)],
        ["workflow", "run", "--repo", str(repo), "--plan", str(absent), "--packet", str(packet),
         "--approve-plan", hash_value],
        ["apply", "--repo", str(repo), "--proposal", str(absent), "--approve-hash", hash_value],
        ["finance-check", "--kind", "cash", "--input", str(absent)],
        ["render", "--input", str(absent), "--output", str(output)],
        ["verify-gate", "--repo", str(repo), "--expected-head", head, "--packet", str(packet),
         "--review", str(absent)],
    ]


@pytest.mark.parametrize("index", range(8))
@pytest.mark.parametrize("kind", ["missing", "folder"])
def test_each_json_input_option_names_a_missing_file(repo, tmp_path, capsys, index, kind):
    work = tmp_path / "work"
    work.mkdir()
    absent = work / "absent.json" if kind == "missing" else work
    argv = _json_inputs(repo, absent, work / "out.json")[index]
    assert main(["--audit-dir", str(tmp_path / "state"), *argv]) == 2
    assert _error(capsys)["code"] == "input_file_not_found"


def test_triage_inputs_keep_their_own_named_code(tmp_path, capsys):
    # triage reads its documents itself, offline and without configuration, and names a missing one.
    absent = tmp_path / "absent.json"
    assert main(["triage", "validate", "--request", str(absent), "--result", str(absent),
                 "--model-manifest", str(absent), "--output", str(tmp_path / "report.json")]) == 2
    assert _error(capsys)["code"] == "triage_input_file_required"
