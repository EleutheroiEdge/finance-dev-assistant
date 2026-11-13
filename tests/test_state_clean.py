"""`finassist state clean`: dry-run first, then remove only old backups and temporary leftovers."""

import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
import time
from types import SimpleNamespace

import pytest

from conftest import synthetic_symlink
from finassist.cli import main, parser
from finassist.ledger import Ledger
from finassist.security import canonical
import finassist.state_clean as state_clean

PREFIXES = (
    "finassist-check-", "finassist-ci-", "finassist-ci-refused-", "finassist-eval-",
    "finassist-home-", "finassist-ignore-", "finassist-model-gate-",
    "finassist-patch-screen-", "finassist-state-", "finassist-workflow-",
)
OLD = 1_000_000_000
BACKUP = 1_700_000_000
REASONS = {
    "patches": "rollback needs patches",
    "workflow-runs": "completed run is readiness evidence",
    "workflow-locks": "a lock file keeps one workflow to one process",
    "history": "journals reconcile the budget",
    "setup": "setup state",
    "evidence.sqlite": "evidence store",
    "notes.txt": "unknown name",
}


def _isolate(monkeypatch, tmp_path) -> Path:
    folder = tmp_path / "temp"
    folder.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(folder))
    return folder


def _stamp(path: Path, when: int, *, follow: bool = True) -> None:
    os.utime(path, (when, when), follow_symlinks=follow)


def _run(capsys, tmp_path, argv: list[str]) -> tuple[int, dict]:
    assert tempfile.tempdir is not None and Path(tempfile.tempdir).is_relative_to(tmp_path)
    code = main(argv)
    captured = capsys.readouterr()
    assert captured.err == "", captured.err
    text = captured.out
    assert text.endswith("\n") and text.count("\n") == 1
    report = json.loads(text)
    assert text.encode() == canonical(report) + b"\n"
    return code, report


def _fingerprint(root: Path) -> list[tuple]:
    rows = []
    info = root.lstat()
    rows.append((".", stat.S_IFMT(info.st_mode), info.st_size, info.st_mtime_ns))
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        for name in dirnames + filenames:
            path = current / name
            item = path.lstat()
            rows.append((str(path.relative_to(root)), stat.S_IFMT(item.st_mode), item.st_size, item.st_mtime_ns))
    return sorted(rows)


def _snapshot(root: Path) -> dict[str, tuple | None]:
    """Files keep mode, size and time. Real directories are recorded without their time, which changes
    when a child is removed."""
    found: dict[str, tuple | None] = {}
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        for name in dirnames:
            path = current / name
            info = path.lstat()
            relative = str(path.relative_to(root))
            if stat.S_ISLNK(info.st_mode):
                found[relative] = (stat.S_IFMT(info.st_mode), info.st_size, info.st_mtime_ns)
            else:
                found[relative] = None
        for name in filenames:
            path = current / name
            info = path.lstat()
            found[str(path.relative_to(root))] = (stat.S_IFMT(info.st_mode), info.st_size, info.st_mtime_ns)
    return found


def _covered(relative: str, removed: set[str]) -> bool:
    return any(relative == item or relative.startswith(item + os.sep) for item in removed)


def _assert_only_removed(root: Path, before: dict[str, tuple | None], removed_paths: list[str]) -> None:
    removed = {str(Path(path).relative_to(root)) for path in removed_paths}
    after = _snapshot(root)
    for relative, row in before.items():
        if _covered(relative, removed):
            assert relative not in after
        else:
            assert relative in after
            if row is not None:
                assert after[relative] == row
    assert [relative for relative in after if relative not in before] == []


def _hex(index: int) -> str:
    """A name the dashboard gives a backup: the SHA-256 of its content."""
    return f"{index:064x}.json"


def _stamped(index: int) -> str:
    """A name a configuration migration gives a backup: the UTC time it was taken."""
    return f"finassist.json.backup-20261101T0000{index:02d}.000000Z"


def _series(directory: Path, name_for, count: int = 12) -> list[Path]:
    paths = []
    for index in range(count):
        path = directory / name_for(index)
        path.write_bytes(b"b" * (index + 1))
        _stamp(path, BACKUP + index)
        paths.append(path)
    return paths


def _build(monkeypatch, tmp_path) -> dict:
    assert PREFIXES == state_clean._TEMP_PREFIXES
    state = tmp_path / "state"
    backups = state / "config-backups"
    backups.mkdir(parents=True)
    nested = backups / "nested"
    nested.mkdir()
    (nested / "keep.bin").write_bytes(b"nested-keep")
    state_backups = _series(backups, _hex)
    (state / "patches").mkdir()
    (state / "patches" / "one.json").write_bytes(b"patch-bytes")
    (state / "workflow-runs" / "run1").mkdir(parents=True)
    (state / "workflow-runs" / "run1" / "run.json").write_bytes(b"{}")
    (state / "workflow-locks").mkdir()
    (state / "workflow-locks" / "a.lock").write_bytes(b"\0")
    (state / "history").mkdir()
    (state / "history" / "journal.json").write_bytes(b"journal-bytes")
    (state / "setup").mkdir()
    (state / "setup" / "done").write_bytes(b"ok")
    (state / "evidence.sqlite").write_bytes(b"evidence-bytes")
    (state / "notes.txt").write_bytes(b"unknown-bytes")
    project = tmp_path / "project"
    project.mkdir()
    config = project / "finassist.json"
    config.write_bytes(b"{}\n")
    (project / "README").write_bytes(b"readme")
    other = project / "other.json.backup-9"
    other.write_bytes(b"other")
    config_backups = _series(project, _stamped)
    temp = _isolate(monkeypatch, tmp_path)
    old = {}
    for prefix in PREFIXES:
        if prefix == "finassist-state-":
            directory = temp / (prefix + "old")
            directory.mkdir()
            (directory / "inner").write_bytes(b"tree-file")
            _stamp(directory, OLD)
            old[prefix] = directory
            continue
        path = temp / (prefix + "old")
        path.write_bytes(b"t")
        _stamp(path, OLD)
        old[prefix] = path
    young = temp / "finassist-eval-young"
    young.write_bytes(b"young")
    unrelated = temp / "unrelated.tmp"
    unrelated.write_bytes(b"unrelated")
    return {
        "state": state, "config": config, "backups": backups, "project": project, "temp": temp,
        "state_backups": state_backups, "config_backups": config_backups, "old": old,
        "young": young, "unrelated": unrelated, "other": other,
    }


def _argv(world, *extra: str) -> list[str]:
    return ["--config", str(world["config"]), "state", "clean", "--state-dir", str(world["state"]), *extra]


def _expected_removable(world) -> list[Path]:
    return [
        world["state_backups"][0], world["state_backups"][1],
        world["config_backups"][0], world["config_backups"][1],
        *world["old"].values(),
    ]


def test_dry_run_lists_old_backups_and_temp_files_and_writes_nothing(tmp_path, monkeypatch, capsys):
    world = _build(monkeypatch, tmp_path)
    before = _fingerprint(tmp_path)
    code, report = _run(capsys, tmp_path, _argv(world))
    assert code == 0
    assert _fingerprint(tmp_path) == before
    assert set(report) == {
        "schema_version", "mode", "applied", "state_dir", "state_dir_source",
        "removable", "removed", "kept", "removable_bytes", "removed_bytes",
    }
    assert report["schema_version"] == 1 and report["mode"] == "state-clean"
    assert report["applied"] is False and report["removed"] == [] and report["removed_bytes"] == 0
    assert report["state_dir"] == str(world["state"]) and report["state_dir_source"] == "state_dir"
    removable = {item["path"]: item for item in report["removable"]}
    expected = _expected_removable(world)
    assert set(removable) == {str(path) for path in expected}
    for item in report["removable"]:
        assert set(item) == {"kind", "path", "bytes", "reason"}
    assert removable[str(world["state_backups"][0])]["reason"] == "beyond the newest backups"
    assert removable[str(world["state_backups"][0])]["kind"] == "config-backup"
    assert removable[str(world["state_backups"][0])]["bytes"] == 1
    assert removable[str(world["config_backups"][1])]["kind"] == "config-file-backup"
    assert removable[str(world["config_backups"][1])]["bytes"] == 2
    tree = world["old"]["finassist-state-"]
    assert removable[str(tree)] == {
        "kind": "temporary", "path": str(tree), "bytes": len(b"tree-file"), "reason": "temporary leftover",
    }
    assert report["removable_bytes"] == sum(path.stat().st_size for path in expected if path.is_file()) + len(b"tree-file")
    kept = {item["path"]: item for item in report["kept"]}
    for item in report["kept"]:
        assert set(item) == {"kind", "path", "reason"}
    for index in range(2, 12):
        assert kept[str(world["state_backups"][index])]["reason"] == "newest backup"
        assert kept[str(world["config_backups"][index])]["reason"] == "newest backup"
    assert kept[str(world["backups"])]["reason"] == "config backup directory"
    assert kept[str(world["backups"] / "nested")]["reason"] == "unknown name"
    for name, reason in REASONS.items():
        assert kept[str(world["state"] / name)]["reason"] == reason
    assert kept[str(world["young"])]["reason"] == "newer than the age threshold"
    assert str(world["state"] / "patches" / "one.json") not in kept
    listed = set(removable) | set(kept)
    assert str(world["unrelated"]) not in listed
    assert str(world["other"]) not in listed
    assert str(world["config"]) not in listed
    assert str(world["project"] / "README") not in listed


def test_apply_removes_exactly_the_dry_run_and_keeps_the_ten_newest(tmp_path, monkeypatch, capsys):
    world = _build(monkeypatch, tmp_path)
    before = _snapshot(tmp_path)
    code, dry = _run(capsys, tmp_path, _argv(world))
    assert code == 0 and dry["removed"] == []
    code, applied = _run(capsys, tmp_path, _argv(world, "--apply"))
    assert code == 0 and applied["applied"] is True
    assert applied["removed"] == dry["removable"]
    assert applied["removed_bytes"] == dry["removable_bytes"] == applied["removable_bytes"]
    assert applied["audit"] == "no ledger"
    _assert_only_removed(tmp_path, before, [item["path"] for item in dry["removable"]])
    assert sorted(path.name for path in world["backups"].iterdir()) == [
        *[_hex(index) for index in range(2, 12)], "nested"]
    sibling_names = sorted(path.name for path in world["project"].iterdir())
    assert [name for name in sibling_names if name.startswith("finassist.json.backup-")] == [
        _stamped(index) for index in range(2, 12)]
    assert "finassist.json" in sibling_names and "README" in sibling_names
    assert "other.json.backup-9" in sibling_names
    for path in world["old"].values():
        assert not path.exists() and not path.is_symlink()
    assert world["young"].read_bytes() == b"young"
    assert world["unrelated"].read_bytes() == b"unrelated"
    assert (world["backups"] / "nested" / "keep.bin").read_bytes() == b"nested-keep"
    assert (world["state"] / "patches" / "one.json").read_bytes() == b"patch-bytes"
    assert (world["state"] / "history" / "journal.json").read_bytes() == b"journal-bytes"
    assert (world["state"] / "workflow-locks" / "a.lock").read_bytes() == b"\0"
    assert (world["state"] / "workflow-runs" / "run1" / "run.json").read_bytes() == b"{}"
    assert (world["state"] / "evidence.sqlite").read_bytes() == b"evidence-bytes"
    assert not (world["state"] / "audit.sqlite").exists()


def test_the_name_breaks_a_tie_and_a_later_time_wins(tmp_path, monkeypatch, capsys):
    _isolate(monkeypatch, tmp_path)
    state = tmp_path / "state"
    backups = state / "config-backups"
    backups.mkdir(parents=True)
    older = backups / ("b" * 64 + ".json")
    same_time = backups / ("c" * 64 + ".json")
    newer = backups / ("a" * 64 + ".json")
    for path in (older, same_time, newer):
        path.write_bytes(path.name.encode())
    _stamp(older, 1_500_000_000)
    _stamp(same_time, 1_500_000_000)
    _stamp(newer, 1_600_000_000)
    code, report = _run(capsys, tmp_path, [
        "state", "clean", "--state-dir", str(state), "--keep-backups", "2", "--no-temp", "--apply"])
    assert code == 0
    removed = {item["path"] for item in report["removed"]}
    assert removed == {str(older)}
    assert not older.exists()
    assert same_time.read_bytes() == same_time.name.encode()
    assert newer.read_bytes() == newer.name.encode()


def test_no_temp_leaves_temporary_leftovers(tmp_path, monkeypatch, capsys):
    temp = _isolate(monkeypatch, tmp_path)
    leftover = temp / "finassist-check-old"
    leftover.write_bytes(b"stay")
    _stamp(leftover, OLD)
    state = tmp_path / "state"
    backups = state / "config-backups"
    backups.mkdir(parents=True)
    paths = _series(backups, _hex)
    code, report = _run(capsys, tmp_path, [
        "state", "clean", "--state-dir", str(state), "--no-temp", "--apply"])
    assert code == 0
    assert leftover.read_bytes() == b"stay"
    assert {item["path"] for item in report["removed"]} == {str(paths[0]), str(paths[1])}
    assert str(leftover) not in {item["path"] for item in report["kept"] + report["removable"]}


@pytest.mark.skipif(os.name != "posix", reason="ownership is checked only on POSIX")
def test_a_temp_entry_owned_by_someone_else_stays(tmp_path, monkeypatch, capsys):
    uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: uid + 1)
    temp = _isolate(monkeypatch, tmp_path)
    leftover = temp / "finassist-home-old"
    leftover.write_bytes(b"owned")
    _stamp(leftover, OLD)
    state = tmp_path / "state"
    state.mkdir()
    before = _fingerprint(tmp_path)
    code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state)])
    assert code == 0 and report["removable"] == []
    assert _fingerprint(tmp_path) == before
    assert report["kept"] == [{
        "kind": "temporary", "path": str(leftover), "reason": "not owned by the current user",
    }]


def test_a_symlink_inside_a_leftover_is_removed_without_its_target(tmp_path, monkeypatch, capsys):
    _isolate(monkeypatch, tmp_path)
    target = tmp_path / "target"
    target.write_bytes(b"keep-the-target")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_bytes(b"outside-bytes" * 50)
    before_target = target.lstat()
    before_outside = (outside / "keep").read_bytes()
    temp = Path(tempfile.tempdir)
    leftover = temp / "finassist-patch-screen-old"
    leftover.mkdir()
    (leftover / "note").write_bytes(b"abc")
    synthetic_symlink(leftover / "file-link", target)
    synthetic_symlink(leftover / "dir-link", outside, target_is_directory=True)
    _stamp(leftover, OLD)
    top = temp / "finassist-home-link"
    synthetic_symlink(top, target)
    if os.utime in os.supports_follow_symlinks:
        _stamp(top, OLD, follow=False)
    else:
        # Windows cannot set a link's own time, so the clock moves forward instead: the new link is then old.
        later = time.time() + 30 * 24 * 3600
        monkeypatch.setattr(state_clean, "time", SimpleNamespace(time=lambda: later))
    state = tmp_path / "state"
    state.mkdir()
    code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply"])
    assert code == 0
    listed = {item["path"]: item for item in report["removed"]}
    assert set(listed) == {str(leftover), str(top)}
    assert listed[str(leftover)]["bytes"] == len(b"abc")
    assert listed[str(top)]["bytes"] == 0
    assert not leftover.exists() and not top.exists()
    assert target.read_bytes() == b"keep-the-target"
    assert target.lstat().st_mtime_ns == before_target.st_mtime_ns
    assert target.lstat().st_size == before_target.st_size
    assert (outside / "keep").read_bytes() == before_outside


def test_a_linked_backup_directory_is_not_followed(tmp_path, monkeypatch, capsys):
    _isolate(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    for index in range(12):
        (outside / f"{index:02d}.json").write_bytes(b"x" * (index + 1))
    state = tmp_path / "state"
    state.mkdir()
    synthetic_symlink(state / "config-backups", outside, target_is_directory=True)
    before = _fingerprint(tmp_path)
    code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply"])
    assert code == 0 and report["removable"] == [] and report["removed"] == []
    assert _fingerprint(tmp_path) == before
    assert {"kind": "config-backup", "path": str(state / "config-backups"), "reason": "symbolic link"} in report["kept"]
    assert (outside / "00.json").read_bytes() == b"x"


def test_a_read_only_leftover_tree_is_removed(tmp_path, monkeypatch, capsys):
    temp = _isolate(monkeypatch, tmp_path)
    leftover = temp / "finassist-workflow-old"
    nested = leftover / "snap" / "dir"
    nested.mkdir(parents=True)
    data = nested / "data"
    data.write_bytes(b"frozen")
    top = leftover / "top.txt"
    top.write_bytes(b"also")
    data.chmod(0o400)
    top.chmod(0o400)
    nested.chmod(0o500)
    (leftover / "snap").chmod(0o500)
    leftover.chmod(0o500)
    _stamp(leftover, OLD)
    state = tmp_path / "missing-state"
    try:
        code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply"])
        assert code == 0
        assert report["audit"] == "no ledger"
        assert [item["path"] for item in report["removed"]] == [str(leftover)]
        assert not leftover.exists()
        assert not state.exists()
    finally:
        _unlock(leftover)


def _unlock(path: Path) -> None:
    if path.is_symlink() or not path.exists():
        return
    os.chmod(path, 0o700 if path.is_dir() else 0o600)
    if path.is_dir():
        for child in list(path.iterdir()):
            _unlock(child)


def test_protected_stores_are_kept_with_reasons_and_their_bytes_stay(tmp_path, monkeypatch, capsys):
    _isolate(monkeypatch, tmp_path)
    state = tmp_path / "state"
    (state / "patches").mkdir(parents=True)
    (state / "patches" / "one.json").write_bytes(b"patch-bytes")
    (state / "workflow-runs" / "run1").mkdir(parents=True)
    (state / "workflow-runs" / "run1" / "run.json").write_bytes(b"{}")
    (state / "workflow-locks").mkdir()
    (state / "workflow-locks" / "a.lock").write_bytes(b"\0")
    (state / "history").mkdir()
    (state / "history" / "journal.json").write_bytes(b"journal-bytes")
    (state / "setup").mkdir()
    (state / "setup" / "done").write_bytes(b"ok")
    (state / "audit.sqlite").write_bytes(b"audit-bytes")
    (state / "audit.sqlite-wal").write_bytes(b"wal-bytes")
    (state / "evidence.sqlite").write_bytes(b"evidence-bytes")
    (state / "evidence.v2.sqlite").write_bytes(b"v2-bytes")
    (state / "evidence.v2.sqlite-wal").write_bytes(b"v2-wal")
    (state / "notes.txt").write_bytes(b"unknown-bytes")
    (state / "config-backups").mkdir()
    (state / "config-backups" / _hex(1)).write_bytes(b"one-backup")
    before = _fingerprint(tmp_path)
    code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply"])
    assert code == 0 and report["removable"] == [] and report["removed"] == []
    assert "audit" not in report
    assert _fingerprint(tmp_path) == before
    kept = {item["path"]: item for item in report["kept"]}
    for name, reason in REASONS.items():
        assert kept[str(state / name)] == {"kind": _kind(name), "path": str(state / name), "reason": reason}
    assert kept[str(state / "audit.sqlite")] == {
        "kind": "audit", "path": str(state / "audit.sqlite"), "reason": "audit chain is evidence"}
    assert kept[str(state / "audit.sqlite-wal")]["reason"] == "audit chain is evidence"
    assert kept[str(state / "evidence.v2.sqlite")]["reason"] == "evidence store"
    assert kept[str(state / "evidence.v2.sqlite-wal")]["reason"] == "evidence store"
    assert kept[str(state / "config-backups" / _hex(1))]["reason"] == "newest backup"
    assert (state / "audit.sqlite").read_bytes() == b"audit-bytes"
    assert (state / "patches" / "one.json").read_bytes() == b"patch-bytes"
    assert (state / "history" / "journal.json").read_bytes() == b"journal-bytes"
    assert (state / "workflow-locks" / "a.lock").read_bytes() == b"\0"


def _kind(name: str) -> str:
    if name.startswith("audit."):
        return "audit"
    if name.startswith("evidence."):
        return "evidence"
    if name == "notes.txt":
        return "unknown"
    return name


def test_apply_records_one_audit_event_with_counts_and_leaves_stores(tmp_path, monkeypatch, capsys):
    _isolate(monkeypatch, tmp_path)
    state = tmp_path / "state"
    (state / "patches").mkdir(parents=True)
    (state / "patches" / "one.json").write_bytes(b"patch-bytes")
    (state / "workflow-runs" / "run1").mkdir(parents=True)
    (state / "workflow-runs" / "run1" / "run.json").write_bytes(b"{}")
    (state / "workflow-locks").mkdir()
    (state / "workflow-locks" / "a.lock").write_bytes(b"\0")
    (state / "history").mkdir()
    (state / "history" / "journal.json").write_bytes(b"journal-bytes")
    with Ledger(state / "audit.sqlite") as ledger:
        ledger.append({"event": "note"})
    backups = state / "config-backups"
    backups.mkdir()
    paths = _series(backups, _hex)
    code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply"])
    assert code == 0 and report["audit"] == "recorded"
    assert [item["path"] for item in report["removed"]] == [str(paths[0]), str(paths[1])]
    assert report["removed_bytes"] == 3
    assert (state / "patches" / "one.json").read_bytes() == b"patch-bytes"
    assert (state / "history" / "journal.json").read_bytes() == b"journal-bytes"
    assert (state / "workflow-locks" / "a.lock").read_bytes() == b"\0"
    assert (state / "workflow-runs" / "run1" / "run.json").read_bytes() == b"{}"
    kept = {item["path"]: item["reason"] for item in report["kept"]}
    assert kept[str(state / "audit.sqlite")] == "audit chain is evidence"
    assert kept[str(state / "patches")] == "rollback needs patches"
    assert kept[str(state / "workflow-runs")] == "completed run is readiness evidence"
    assert kept[str(state / "workflow-locks")] == "a lock file keeps one workflow to one process"
    assert kept[str(state / "history")] == "journals reconcile the budget"
    with Ledger(state / "audit.sqlite", read_only=True) as ledger:
        payloads = [row["payload"] for row in ledger.events()]
    assert [item["event"] for item in payloads] == [
        "note", "command_started", "state_cleaned", "command_completed"]
    cleaned = [item for item in payloads if item["event"] == "state_cleaned"]
    assert len(cleaned) == 1
    assert cleaned[0]["removed_count"] == 2
    assert cleaned[0]["removed_bytes"] == 3
    assert cleaned[0]["failed_count"] == 0
    assert payloads[1]["command"] == "state-clean"
    assert payloads[3]["exit_code"] == 0
    encoded = json.dumps(payloads)
    assert str(tmp_path) not in encoded and paths[0].name not in encoded and "config-backups" not in encoded


def test_apply_creates_no_audit_chain_when_none_exists(tmp_path, monkeypatch, capsys):
    _isolate(monkeypatch, tmp_path)
    state = tmp_path / "state"
    backups = state / "config-backups"
    backups.mkdir(parents=True)
    path = backups / _hex(1)
    path.write_bytes(b"old-backup")
    _stamp(path, BACKUP)
    newer = backups / _hex(2)
    newer.write_bytes(b"new-backup")
    _stamp(newer, BACKUP + 10)
    code, report = _run(capsys, tmp_path, [
        "state", "clean", "--state-dir", str(state), "--keep-backups", "1", "--apply"])
    assert code == 0 and report["audit"] == "no ledger"
    assert not path.exists() and newer.read_bytes() == b"new-backup"
    assert list(state.rglob("audit.sqlite*")) == []


def test_a_failed_removal_is_reported_and_the_rest_proceeds(tmp_path, monkeypatch, capsys):
    _isolate(monkeypatch, tmp_path)
    state = tmp_path / "state"
    backups = state / "config-backups"
    backups.mkdir(parents=True)
    paths = _series(backups, _hex)
    original = state_clean._unlink

    def unlink(path: Path) -> None:
        if path.name == paths[0].name:
            raise PermissionError(path.name)
        original(path)

    monkeypatch.setattr(state_clean, "_unlink", unlink)
    code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply"])
    assert code == 1
    assert report["audit"] == "no ledger"
    failed = [item for item in report["removable"] if "error" in item]
    assert len(failed) == 1 and failed[0]["path"] == str(paths[0]) and failed[0]["error"] == "PermissionError"
    assert [item["path"] for item in report["removed"]] == [str(paths[1])]
    assert paths[0].read_bytes() == b"b"
    assert not paths[1].exists()
    assert paths[2].read_bytes() == b"bbb"
    assert list(state.rglob("audit.sqlite*")) == []


def test_clean_defaults_and_rejects_values_below_one():
    args = parser().parse_args(["state", "clean"])
    assert args.command == "state" and args.state_action == "clean"
    assert args.apply is False and args.no_temp is False and args.state_dir is None
    assert args.keep_backups == 10 and args.older_than == 24
    with pytest.raises(SystemExit) as keep:
        parser().parse_args(["state", "clean", "--keep-backups", "0"])
    assert keep.value.code == 2
    with pytest.raises(SystemExit) as age:
        parser().parse_args(["state", "clean", "--older-than", "0"])
    assert age.value.code == 2


def _old_backups(state, count=12):
    folder = state / "config-backups"
    folder.mkdir(parents=True)
    for n in range(count):
        path = folder / f"{n:064x}.json"
        path.write_text("{}", encoding="utf-8")
        os.utime(path, (1_000_000 + n, 1_000_000 + n))
    return folder


@pytest.mark.parametrize("damage", ["garbage", "link"])
def test_apply_stops_before_removing_when_the_chain_does_not_verify(tmp_path, monkeypatch, capsys, damage):
    # The removal must be recordable, so a chain that cannot be verified stops it before anything is removed.
    from finassist.cli import main

    if damage == "link" and os.name == "nt":
        pytest.skip("symbolic links need privileges on Windows")
    state = tmp_path / "state"
    backups = _old_backups(state)
    ledger = state / "audit.sqlite"
    if damage == "garbage":
        ledger.write_bytes(b"not a database")
    else:
        target = tmp_path / "elsewhere.sqlite"
        target.write_bytes(b"not a database")
        ledger.symlink_to(target)
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir()
    before = sorted(path.name for path in backups.iterdir())
    code = main(["state", "clean", "--state-dir", str(state), "--apply", "--no-temp"])
    err = capsys.readouterr().err
    expected = {"garbage": {"audit_unavailable", "audit_integrity_failed"}, "link": {"linked_path"}}[damage]
    assert code == 2 and json.loads(err.strip().splitlines()[-1])["code"] in expected, err
    assert sorted(path.name for path in backups.iterdir()) == before


@pytest.mark.parametrize("count", [10, 12])
def test_only_the_names_the_writers_give_count_as_backups(tmp_path, monkeypatch, capsys, count):
    _isolate(monkeypatch, tmp_path)
    state = tmp_path / "state"
    backups = state / "config-backups"
    backups.mkdir(parents=True)
    valid = _series(backups, _hex, count)
    lookalikes = [backups / name for name in (
        "README.txt", "f" * 63 + ".json", "F" * 64 + ".json", "f" * 64 + ".json.tmp", "f" * 64 + ".JSON",
        "f" * 65 + ".json")]
    project = tmp_path / "project"
    project.mkdir()
    config = project / "finassist.json"
    config.write_bytes(b"{}\n")
    siblings = _series(project, _stamped, count)
    odd = [project / ("finassist.json.backup-" + suffix) for suffix in (
        "not-a-backup", "20261301T000000.000000Z", "20261101T000000Z", "20261101T000000.000000Z.bak",
        "20261101T000000.000000z")]
    for path in (*lookalikes, *odd):
        path.write_bytes(b"not-a-backup")
        _stamp(path, OLD)  # older than every backup: counted by age, they would go first
    folder = backups / ("e" * 64 + ".json")
    folder.mkdir()
    code, report = _run(capsys, tmp_path, [
        "--config", str(config), "state", "clean", "--state-dir", str(state), "--no-temp", "--apply"])
    assert code == 0
    assert {item["path"] for item in report["removed"]} == {
        str(path) for path in (*valid[: count - 10], *siblings[: count - 10])}
    kept = {item["path"]: item["reason"] for item in report["kept"]}
    for path in (*lookalikes, *odd):
        assert kept[str(path)] == "unknown name" and path.read_bytes() == b"not-a-backup"
    assert kept[str(folder)] == "not a regular file" and folder.is_dir()


def _junction(link: Path, target: Path) -> None:
    winapi = pytest.importorskip("_winapi")
    if not hasattr(winapi, "CreateJunction"):
        pytest.skip("this Python cannot create a junction")
    winapi.CreateJunction(str(target), str(link))


def _clock_forward(monkeypatch) -> None:
    later = time.time() + 30 * 24 * 3600
    monkeypatch.setattr(state_clean, "time", SimpleNamespace(time=lambda: later))


@pytest.mark.skipif(os.name != "nt", reason="junctions exist only on Windows")
def test_a_junction_is_removed_itself_and_never_entered(tmp_path, monkeypatch, capsys):
    temp = _isolate(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    (outside / "keep").write_bytes(b"outside-bytes")
    (outside / "deep" / "keep").write_bytes(b"deep-bytes")
    leftover = temp / "finassist-state-old"
    (leftover / "inner").mkdir(parents=True)
    (leftover / "note").write_bytes(b"abc")
    _junction(leftover / "inner" / "nested-junction", outside)
    _junction(leftover / "junction", outside)
    top = temp / "finassist-home-junction"
    _junction(top, outside)
    _clock_forward(monkeypatch)
    state = tmp_path / "state"
    state.mkdir()
    code, dry = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state)])
    listed = {item["path"]: item["bytes"] for item in dry["removable"]}
    assert code == 0 and listed == {str(leftover): len(b"abc"), str(top): 0}
    code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply"])
    assert code == 0 and {item["path"] for item in report["removed"]} == set(listed)
    assert not os.path.lexists(leftover) and not os.path.lexists(top)
    assert (outside / "keep").read_bytes() == b"outside-bytes"
    assert (outside / "deep" / "keep").read_bytes() == b"deep-bytes"


@pytest.mark.skipif(os.name != "nt", reason="junctions exist only on Windows")
def test_a_junction_for_the_backup_folder_or_a_backup_is_not_followed(tmp_path, monkeypatch, capsys):
    _isolate(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    for index in range(12):
        (outside / _hex(index)).write_bytes(b"x" * (index + 1))
    state = tmp_path / "state"
    state.mkdir()
    _junction(state / "config-backups", outside)
    code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply", "--no-temp"])
    assert code == 0 and report["removable"] == [] and report["removed"] == []
    folder = {"kind": "config-backup", "path": str(state / "config-backups"), "reason": "reparse point"}
    assert folder in report["kept"]
    assert sorted(path.name for path in outside.iterdir()) == [_hex(index) for index in range(12)]


@pytest.mark.skipif(not shutil.rmtree.avoids_symlink_attacks, reason="needs removal through descriptors")
def test_a_leftover_replaced_by_a_link_after_it_was_listed_is_not_removed(tmp_path, monkeypatch, capsys):
    temp = _isolate(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_bytes(b"outside-bytes")
    leftover = temp / "finassist-state-old"
    leftover.mkdir()
    (leftover / "note").write_bytes(b"abc")
    _stamp(leftover, OLD)
    plan = state_clean._plan

    def replaced_after_listing(*args):
        listed = plan(*args)
        shutil.rmtree(leftover)
        synthetic_symlink(leftover, outside, target_is_directory=True)
        return listed

    monkeypatch.setattr(state_clean, "_plan", replaced_after_listing)
    state = tmp_path / "state"
    state.mkdir()
    code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply"])
    assert code == 1 and report["removed"] == []
    assert [item.get("error") for item in report["removable"]] == ["EntryChanged"]
    assert leftover.is_symlink() and (outside / "keep").read_bytes() == b"outside-bytes"


@pytest.mark.skipif(not shutil.rmtree.avoids_symlink_attacks, reason="needs removal through descriptors")
def test_a_folder_inside_replaced_by_a_link_is_neither_entered_nor_changed(tmp_path, monkeypatch, capsys):
    temp = _isolate(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_bytes(b"outside-bytes")
    outside.chmod(0o550)  # a grant through the link would add the owner's write
    leftover = temp / "finassist-workflow-old"
    (leftover / "sub").mkdir(parents=True)
    (leftover / "sub" / "file").write_bytes(b"abc")
    leftover.chmod(0o500)
    _stamp(leftover, OLD)
    grant = state_clean._grant_tree

    def replaced_before_the_grant(path, identity):
        os.chmod(path, 0o700)
        shutil.rmtree(path / "sub")
        synthetic_symlink(path / "sub", outside, target_is_directory=True)
        os.chmod(path, 0o500)
        grant(path, identity)

    monkeypatch.setattr(state_clean, "_grant_tree", replaced_before_the_grant)
    state = tmp_path / "state"
    state.mkdir()
    try:
        code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply"])
        assert code == 0 and [item["path"] for item in report["removed"]] == [str(leftover)]
        assert not os.path.lexists(leftover)
        assert (outside / "keep").read_bytes() == b"outside-bytes"
        assert stat.S_IMODE(outside.stat().st_mode) == 0o550
    finally:
        _unlock(leftover)
        outside.chmod(0o750)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs POSIX permissions, not root")
def test_apply_removes_nothing_when_the_audit_cannot_record_its_start(tmp_path, monkeypatch, capsys):
    state = tmp_path / "state"
    backups = _old_backups(state)
    with Ledger(state / "audit.sqlite") as ledger:
        ledger.append({"event": "note"})
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir()
    before = sorted(path.name for path in backups.iterdir())
    state.chmod(0o500)  # the chain reads and verifies, but cannot be written
    try:
        code = main(["state", "clean", "--state-dir", str(state), "--apply", "--no-temp"])
    finally:
        state.chmod(0o700)
    captured = capsys.readouterr()
    assert code == 2 and json.loads(captured.err.strip().splitlines()[-1])["code"] == "audit_unavailable"
    assert captured.out == ""
    assert sorted(path.name for path in backups.iterdir()) == before


def test_a_record_that_fails_once_removal_began_is_reported_as_failed(tmp_path, monkeypatch, capsys):
    _isolate(monkeypatch, tmp_path)
    state = tmp_path / "state"
    backups = _old_backups(state)
    with Ledger(state / "audit.sqlite") as ledger:
        ledger.append({"event": "note"})
    original = Ledger.append

    def append(self, payload, *args, **kwargs):
        if payload.get("event") == "state_cleaned":
            raise sqlite3.OperationalError("disk I/O error")
        return original(self, payload, *args, **kwargs)

    monkeypatch.setattr(Ledger, "append", append)
    code, report = _run(capsys, tmp_path, ["state", "clean", "--state-dir", str(state), "--apply", "--no-temp"])
    assert code == 1 and report["audit"] == "failed"
    assert len(report["removed"]) == 2 and len(list(backups.iterdir())) == 10
    monkeypatch.setattr(Ledger, "append", original)
    with Ledger(state / "audit.sqlite", read_only=True) as ledger:
        events = [row["payload"]["event"] for row in ledger.events()]
    assert events == ["note", "command_started", "command_failed"]
