"""One state folder for every command, and no silent second spending ledger."""

from argparse import Namespace
import json
from pathlib import Path

from finassist.cli import main
from finassist.config import Config, save_config
from finassist.state_location import state_location


def _listing(path: Path) -> list[str]:
    return sorted(str(item.relative_to(path)) for item in path.rglob("*"))


def _texts(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _texts(item)]
    if isinstance(value, list):
        return [text for item in value for text in _texts(item)]
    return []


def test_explicit_audit_dir_wins_and_is_not_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    old = tmp_path / ".finassist"
    old.mkdir()
    (old / "audit.sqlite").write_bytes(b"synthetic")
    chosen = tmp_path / "kept"
    folder, origin = state_location(Namespace(
        audit_dir=chosen, state_dir=tmp_path / "state", config=tmp_path / "finassist.json",
        repo=tmp_path, command="audit"))
    assert (folder, origin) == (chosen, "audit_dir")
    assert not chosen.exists()


def test_explicit_state_dir_wins_over_config_and_repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    config = root / "finassist.json"
    chosen = tmp_path / "state"
    folder, origin = state_location(Namespace(
        audit_dir=None, state_dir=chosen, config=config, repo=root / "src", command="plan"))
    assert (folder, origin) == (chosen, "state_dir")


def test_config_directory_wins_over_the_repository(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    config = project / "finassist.json"
    config.write_text("{}\n", encoding="utf-8", newline="\n")
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / ".git").mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    folder, origin = state_location(Namespace(
        audit_dir=None, state_dir=None, config=config, repo=repo / "src", command="audit"))
    assert (folder, origin) == (project / ".finassist", "config")


def test_a_configuration_inside_a_repository_uses_the_repository_root(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / ".github").mkdir(parents=True)
    (root / ".git").mkdir()
    config = root / ".github" / "finassist.json"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    with_config = state_location(Namespace(audit_dir=None, state_dir=None, config=config, command="audit"))
    without = state_location(Namespace(audit_dir=None, state_dir=None, config=None, repo=root, command="plan"))
    # The same folder whether or not the configuration is named: one ledger.
    assert with_config == (root / ".finassist", "config")
    assert without == (root / ".finassist", "repository")


def test_repository_root_is_the_nearest_ancestor_with_git(tmp_path):
    root = tmp_path / "repo"
    nested = root / "a" / "b"
    nested.mkdir(parents=True)
    (root / ".git").write_text("gitdir: /synthetic\n", encoding="utf-8", newline="\n")
    (tmp_path / ".git").mkdir()  # A farther ancestor must not win.
    folder, origin = state_location(Namespace(
        audit_dir=None, state_dir=None, config=None, repo=nested, command="plan"))
    assert (folder, origin) == (root / ".finassist", "repository")


def test_working_directory_is_used_when_no_git_ancestor_exists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    folder, origin = state_location(Namespace(audit_dir=None, state_dir=None, config=None, command="audit"))
    assert (folder, origin) == (tmp_path / ".finassist", "working_directory")
    folder, origin = state_location(Namespace(
        audit_dir=None, state_dir=None, config=None, repo=other, command="plan"))
    assert (folder, origin) == (tmp_path / ".finassist", "working_directory")


def test_one_configuration_keeps_one_ledger_from_two_directories(tmp_path, monkeypatch, capsys):
    project = tmp_path / "project"
    project.mkdir()
    config = project / "finassist.json"
    save_config(config, Config())
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    before = {work: _listing(work) for work in (first, second)}
    for work in (first, second):
        monkeypatch.chdir(work)
        code = main(["--config", str(config), "audit"])
        captured = capsys.readouterr()
        assert code == 0, captured.err
    for work in (first, second):
        assert _listing(work) == before[work]
    ledger = project / ".finassist" / "audit.sqlite"
    assert list(tmp_path.rglob("audit.sqlite")) == [ledger]


def test_audit_from_a_subdirectory_uses_the_repository_root(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repo"
    nested = root / "src"
    nested.mkdir(parents=True)
    (root / ".git").mkdir()
    before = _listing(nested)
    monkeypatch.chdir(nested)
    code = main(["audit"])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert (root / ".finassist" / "audit.sqlite").is_file()
    assert _listing(nested) == before
    assert not (nested / ".finassist").exists()


def test_an_old_working_directory_ledger_is_not_replaced(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repo"
    nested = root / "src"
    nested.mkdir(parents=True)
    (root / ".git").mkdir()
    old = nested / ".finassist"
    old.mkdir()
    (old / "audit.sqlite").write_bytes(b"synthetic")
    before = _listing(root)
    monkeypatch.chdir(nested)
    code = main(["audit"])
    captured = capsys.readouterr()
    assert code == 2
    record = json.loads(captured.err)
    assert record["code"] == "state_location_moved"
    assert "--state-dir" in record["hint"] and "state status" in record["hint"]
    # The rules are named in public; the paths are not.
    assert (record["previous"], record["selected"]) == ("working_directory", "repository")
    assert all(str(tmp_path) not in text for text in _texts(record))
    assert _listing(root) == before
    assert not (root / ".finassist").exists()
    assert (old / "audit.sqlite").read_bytes() == b"synthetic"


def test_an_explicit_state_dir_is_not_refused(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repo"
    nested = root / "src"
    nested.mkdir(parents=True)
    (root / ".git").mkdir()
    old = nested / ".finassist"
    old.mkdir()
    (old / "audit.sqlite").write_bytes(b"synthetic")
    monkeypatch.chdir(nested)
    chosen = root / ".finassist"
    code = main(["audit", "--state-dir", str(chosen)])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert (chosen / "audit.sqlite").is_file()
    assert (old / "audit.sqlite").read_bytes() == b"synthetic"


def test_state_status_reports_the_folder_the_rule_chose(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repo"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / ".git").mkdir()
    monkeypatch.chdir(nested)
    code = main(["state", "status", "--no-user"])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    report = json.loads(captured.out)
    assert report["state_dir"] == str(root / ".finassist")
    assert report["state_dir_source"] == "repository" and "moved_from" not in report
    assert report["exists"] is False
    assert not (root / ".finassist").exists()


def test_doctor_reports_the_repository_state_folder(tmp_path, monkeypatch, capsys):
    root = tmp_path / "repo"
    nested = root / "src"
    nested.mkdir(parents=True)
    (root / ".git").mkdir()
    monkeypatch.chdir(nested)
    code = main(["doctor"])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    report = json.loads(captured.out)
    assert report["environment"]["paths"]["state"]["path"] == str(root / ".finassist")
    assert not (root / ".finassist").exists()


def _moved_ledger(tmp_path):
    root = tmp_path / "repo"
    nested = root / "src"
    nested.mkdir(parents=True)
    (root / ".git").mkdir()
    old = nested / ".finassist"
    old.mkdir()
    (old / "audit.sqlite").write_bytes(b"synthetic")
    return root, nested


def test_two_ledgers_are_refused_until_one_is_chosen(tmp_path, monkeypatch, capsys):
    root, nested = _moved_ledger(tmp_path)
    (root / ".finassist").mkdir()
    (root / ".finassist" / "audit.sqlite").write_bytes(b"synthetic")
    monkeypatch.chdir(nested)
    # Both ledgers already exist and each would enforce the budget alone, so neither is chosen silently.
    assert main(["audit"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "state_location_moved"
    for folder in (nested, root):
        assert (folder / ".finassist" / "audit.sqlite").read_bytes() == b"synthetic"


def test_state_status_reports_a_moved_ledger_and_does_not_refuse(tmp_path, monkeypatch, capsys):
    root, nested = _moved_ledger(tmp_path)
    monkeypatch.chdir(nested)
    before = _listing(root)
    assert main(["state", "status", "--no-user"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert (report["state_dir"], report["state_dir_source"]) == (str(root / ".finassist"), "repository")
    assert report["moved_from"] == str(nested / ".finassist")
    assert _listing(root) == before


def test_doctor_warns_about_a_moved_ledger(tmp_path, monkeypatch, capsys):
    from finassist.doctor_environment import _shown_path

    root, nested = _moved_ledger(tmp_path)
    monkeypatch.chdir(nested)
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert "state_location_moved" in [warning["code"] for warning in report["environment"]["warnings"]]
    assert report["environment"]["paths"]["previous_state"]["path"] == _shown_path(str(nested / ".finassist"))
    assert not (root / ".finassist").exists()
