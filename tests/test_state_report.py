"""Read-only state-folder inventory. Fixtures are synthetic files in tmp_path."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat

from conftest import synthetic_symlink
from finassist.security import regular_path
from finassist.state_report import state_report

MARKER = "MARKER_ROW_SECRET_7f3a9c"


def _iso(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime_ns / 1_000_000_000, timezone.utc).isoformat()


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


def _tree_bytes(root: Path) -> int:
    total = 0
    for directory, _dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        for name in filenames:
            path = current / name
            if path.is_symlink() or not path.is_file():
                continue
            total += path.stat().st_size
    return total


def _assert_frozen(root: Path, before: list[tuple]) -> None:
    assert _fingerprint(root) == before


def _assert_no_sidecars(root: Path) -> None:
    names = [name for name, _mode, _size, _mtime in _fingerprint(root)]
    assert not any(name.endswith("-wal") or name.endswith("-shm") for name in names)


def _close(connection: sqlite3.Connection) -> None:
    connection.close()


def test_populated_folder_is_inventoried_store_by_store(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    audit = state / "audit.sqlite"
    connection = sqlite3.connect(audit)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            "CREATE TABLE events (seq INTEGER PRIMARY KEY, previous TEXT NOT NULL, "
            "payload TEXT NOT NULL, hash TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE reservations (id TEXT PRIMARY KEY, day TEXT NOT NULL, "
            "reserved TEXT NOT NULL, actual TEXT, state TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO events (previous, payload, hash) VALUES (?, ?, ?)",
            ("ROOT", '{"note":"' + MARKER + '","recorded_at":"2010-01-01T00:00:00+00:00"}', "h1"),
        )
        connection.execute(
            "INSERT INTO reservations (id, day, reserved, state) VALUES ('r1', '2024-05-01', ?, 'open')",
            (MARKER,),
        )
        connection.execute(
            "INSERT INTO reservations (id, day, reserved, state) VALUES ('r2', '2024-06-15', '2', 'closed')"
        )
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        _close(connection)

    evidence = state / "evidence.sqlite"
    connection = sqlite3.connect(evidence)
    try:
        connection.execute(
            "CREATE TABLE entries (id INTEGER PRIMARY KEY, entity TEXT NOT NULL, metric TEXT NOT NULL, "
            "payload TEXT NOT NULL, hash TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE decisions (id INTEGER PRIMARY KEY, entry INTEGER NOT NULL, "
            "status TEXT NOT NULL, hash TEXT NOT NULL, decided_at TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TRIGGER immutable_evidence BEFORE UPDATE ON entries BEGIN SELECT RAISE(ABORT, 'no'); END"
        )
        connection.execute(
            "INSERT INTO entries (entity, metric, payload, hash, status, created_at) "
            "VALUES ('Example', 'revenue', ?, 'h', 'approved', '2023-01-02 03:04:05')",
            (MARKER,),
        )
        connection.execute(
            "INSERT INTO decisions (entry, status, hash, decided_at) VALUES (1, 'approved', ?, ?)",
            (MARKER, "2023-02-03T04:05:06+00:00"),
        )
        connection.commit()
    finally:
        _close(connection)

    migrated = state / "evidence.v2.sqlite"
    connection = sqlite3.connect(migrated)
    try:
        connection.execute("CREATE TABLE entries (id INTEGER PRIMARY KEY, payload TEXT, created_at TEXT)")
        connection.execute(
            "INSERT INTO entries (payload, created_at) VALUES (?, '2024-07-08T09:10:11Z')",
            (MARKER,),
        )
        connection.commit()
    finally:
        _close(connection)

    patches = state / "patches"
    patches.mkdir()
    older = patches / "a.json"
    newer = patches / "b.json"
    older.write_bytes(MARKER.encode())
    newer.write_bytes(b"xyz")
    os.utime(older, (1_700_000_000, 1_700_000_000))
    os.utime(newer, (1_700_100_000, 1_700_100_000))

    run = state / "workflow-runs" / "run1"
    run.mkdir(parents=True)
    (run / "run.json").write_bytes(b"{}")
    (state / "workflow-locks").mkdir()
    history = state / "history"
    history.mkdir()
    (history / "journal-SECRETNAME.json").write_bytes(b"journal")
    (state / "config-backups").mkdir()
    (state / "config-backups" / "hash.json").write_bytes(b"backup")
    (state / "setup").mkdir()
    (state / "setup" / "done").write_bytes(b"ok")
    (state / "notes.txt").write_bytes(b"hello")
    (state / "misc").mkdir()
    (state / "misc" / "blob.bin").write_bytes(b"abcd")
    (state / "other.sqlite").write_bytes(MARKER.encode())

    _assert_no_sidecars(state)
    before = _fingerprint(state)
    report = state_report(state, user_directories=False)
    _assert_frozen(state, before)
    _assert_no_sidecars(state)

    encoded = json.dumps(report)
    # Nothing of an entry reaches the report but the time the ledger stamped on it.
    assert MARKER not in encoded
    assert "SECRETNAME" not in encoded
    assert report["schema_version"] == 1
    assert report["mode"] == "state-report"
    assert report["state_dir"] == str(state)
    assert report["exists"] is True
    assert "user" not in report
    assert report["unknown_more"] == 0
    assert report["total_bytes"] == _tree_bytes(state)
    stores = {item["name"]: item for item in report["stores"]}
    assert list(stores) == [
        "audit.sqlite", "evidence.sqlite", "evidence.v2.sqlite", "patches", "workflow-runs",
        "workflow-locks", "history", "config-backups", "setup",
    ]
    assert stores["audit.sqlite"]["kind"] == "database"
    assert stores["audit.sqlite"]["bytes"] == audit.stat().st_size
    assert stores["audit.sqlite"]["tables"] == [
        {"name": "events", "rows": 1},
        {"name": "reservations", "rows": 2},
    ]
    # The chain's first entry (2010) is older than any reservation day.
    assert stores["audit.sqlite"]["oldest"] == "2010-01-01T00:00:00+00:00"
    assert stores["audit.sqlite"]["newest"] == "2024-06-15T00:00:00+00:00"
    assert stores["evidence.sqlite"]["tables"] == [
        {"name": "decisions", "rows": 1},
        {"name": "entries", "rows": 1},
    ]
    assert stores["evidence.sqlite"]["oldest"] == "2023-01-02T03:04:05+00:00"
    assert stores["evidence.sqlite"]["newest"] == "2023-02-03T04:05:06+00:00"
    assert stores["evidence.v2.sqlite"]["kind"] == "database"
    assert stores["evidence.v2.sqlite"]["tables"] == [{"name": "entries", "rows": 1}]
    assert stores["evidence.v2.sqlite"]["oldest"] == "2024-07-08T09:10:11+00:00"
    assert stores["evidence.v2.sqlite"]["newest"] == "2024-07-08T09:10:11+00:00"
    assert stores["patches"] == {
        "name": "patches", "kind": "folder", "bytes": older.stat().st_size + newer.stat().st_size,
        "files": 2, "oldest": _iso(older), "newest": _iso(newer),
    }
    assert stores["workflow-runs"]["files"] == 1
    assert stores["workflow-runs"]["bytes"] == 2
    assert stores["workflow-runs"]["oldest"] == _iso(run / "run.json")
    assert stores["workflow-locks"] == {"name": "workflow-locks", "kind": "folder", "bytes": 0, "files": 0}
    assert stores["history"]["files"] == 1
    assert stores["history"]["bytes"] == len(b"journal")
    assert stores["config-backups"]["bytes"] == len(b"backup")
    assert stores["setup"]["files"] == 1
    assert report["unknown"] == [
        {"name": "misc", "bytes": 4},
        {"name": "notes.txt", "bytes": 5},
        {"name": "other.sqlite", "bytes": len(MARKER.encode())},
    ]


def test_missing_folder_is_empty_and_uncreated(tmp_path):
    missing = tmp_path / "missing" / "state"
    before = _fingerprint(tmp_path)
    report = state_report(missing, user_directories=False)
    assert report == {
        "schema_version": 1,
        "mode": "state-report",
        "state_dir": str(missing),
        "exists": False,
        "stores": [],
        "unknown": [],
        "unknown_more": 0,
        "total_bytes": 0,
    }
    _assert_frozen(tmp_path, before)
    assert not missing.exists()
    assert not missing.parent.exists()


def test_unknown_names_stop_at_fifty(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "patches").mkdir()
    (state / "patches" / "keep.json").write_bytes(b"x")
    for index in range(51):
        (state / f"n{index:02d}").write_bytes(b"ab")
    before = _fingerprint(state)
    report = state_report(state, user_directories=False)
    _assert_frozen(state, before)
    _assert_no_sidecars(state)
    assert [item["name"] for item in report["stores"]] == ["patches"]
    assert report["unknown"] == [{"name": f"n{index:02d}", "bytes": 2} for index in range(50)]
    assert report["unknown_more"] == 1
    assert "n50" not in {item["name"] for item in report["unknown"]}
    assert report["total_bytes"] == 1 + 51 * 2


def test_corrupt_database_does_not_hide_other_stores(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "audit.sqlite").write_bytes(b"this is not a sqlite database")
    evidence = state / "evidence.sqlite"
    connection = sqlite3.connect(evidence)
    try:
        connection.execute("CREATE TABLE entries (id INTEGER PRIMARY KEY, payload TEXT, created_at TEXT)")
        connection.execute(
            "INSERT INTO entries (payload, created_at) VALUES (?, '2024-01-01T00:00:00+00:00')",
            (MARKER,),
        )
        connection.commit()
    finally:
        _close(connection)
    (state / "patches").mkdir()
    (state / "patches" / "a.json").write_bytes(b"abc")
    before = _fingerprint(state)
    report = state_report(state, user_directories=False)
    _assert_frozen(state, before)
    _assert_no_sidecars(state)
    stores = {item["name"]: item for item in report["stores"]}
    assert stores["audit.sqlite"]["kind"] == "database"
    assert stores["audit.sqlite"]["bytes"] == len(b"this is not a sqlite database")
    assert stores["audit.sqlite"]["error"] == "DatabaseError"
    assert "tables" not in stores["audit.sqlite"]
    assert "not a database" not in json.dumps(report)
    assert stores["evidence.sqlite"]["tables"] == [{"name": "entries", "rows": 1}]
    assert "error" not in stores["evidence.sqlite"]
    assert stores["patches"]["files"] == 1
    assert stores["patches"]["bytes"] == 3
    assert MARKER not in json.dumps(report)


def test_linked_store_is_an_error_and_neighbors_remain(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    real = tmp_path / "real-patches"
    real.mkdir()
    (real / "secret.txt").write_bytes(b"MARKER_LINK_TARGET")
    synthetic_symlink(state / "patches", real, target_is_directory=True)
    synthetic_symlink(state / "alias.txt", real / "secret.txt")
    (state / "history").mkdir()
    (state / "history" / "one.json").write_bytes(b"{}")
    before = _fingerprint(state)
    target_before = _fingerprint(real)
    report = state_report(state, user_directories=False)
    _assert_frozen(state, before)
    _assert_frozen(real, target_before)
    stores = {item["name"]: item for item in report["stores"]}
    assert stores["patches"]["error"] == "AssistantError"
    assert stores["patches"]["bytes"] == 0
    assert "files" not in stores["patches"]
    assert stores["history"]["files"] == 1
    assert report["unknown"] == [{"name": "alias.txt", "bytes": 0, "error": "AssistantError"}]
    assert "MARKER_LINK_TARGET" not in json.dumps(report)


def test_sidecars_count_toward_the_database_and_stay_put(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    database = state / "audit.sqlite"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE events (seq INTEGER PRIMARY KEY, payload TEXT)")
        connection.execute("INSERT INTO events (payload) VALUES ('x')")
        connection.commit()
    finally:
        _close(connection)
    wal = Path(str(database) + "-wal")
    shm = Path(str(database) + "-shm")
    journal = Path(str(database) + "-journal")
    wal.write_bytes(b"wal-bytes")
    shm.write_bytes(b"shm")
    journal.write_bytes(b"journal")
    before = _fingerprint(state)
    report = state_report(state, user_directories=False)
    _assert_frozen(state, before)
    stores = {item["name"]: item for item in report["stores"]}
    sidecar_bytes = wal.stat().st_size + shm.stat().st_size + journal.stat().st_size
    assert stores["audit.sqlite"]["bytes"] == database.stat().st_size + sidecar_bytes
    assert stores["audit.sqlite"]["tables"] == [{"name": "events", "rows": 1}]
    # These side files are not SQLite's, so the database is read alone and the store says so.
    assert stores["audit.sqlite"]["side_files"] == "unreadable"
    assert report["unknown"] == []
    assert report["total_bytes"] == _tree_bytes(state)


def test_user_directories_are_separate_from_the_state_total(tmp_path, monkeypatch):
    config = tmp_path / "config"
    cache = tmp_path / "cache"
    config.mkdir()
    (config / "settings.json").write_bytes(b"{}")
    (config / "nested").mkdir()
    (config / "nested" / "extra").write_bytes(b"abcd")

    def fake(kind: str) -> Path:
        if kind == "config":
            return config
        if kind == "cache":
            return cache
        raise AssertionError(kind)

    monkeypatch.setattr("finassist.state_report.user_directory", fake)
    state = tmp_path / "state"
    state.mkdir()
    (state / "notes.txt").write_bytes(b"xyz")
    before = _fingerprint(tmp_path)
    report = state_report(state)
    _assert_frozen(tmp_path, before)
    assert not cache.exists()
    assert report["total_bytes"] == 3
    assert report["unknown"] == [{"name": "notes.txt", "bytes": 3}]
    assert report["user"]["config"] == {
        "path": str(regular_path(config)), "exists": True, "bytes": 6,
    }
    assert report["user"]["cache"] == {
        "path": str(regular_path(cache)), "exists": False, "bytes": 0,
    }
    omitted = state_report(state, user_directories=False)
    assert "user" not in omitted
    assert omitted["total_bytes"] == 3


def test_a_real_audit_chain_reports_its_entries_and_their_dates_and_nothing_else(tmp_path):
    from finassist.ledger import Ledger

    state = tmp_path / ".finassist"
    marker = "synthetic-marker-" + "4c1f"  # Assembled here: it must not reach the report from an entry's payload.
    with Ledger(state / "audit.sqlite") as ledger:
        for index in range(3):
            ledger.append({"event": "review_completed", "note": marker + str(index)})
    with Ledger(state / "audit.sqlite", read_only=True) as ledger:
        stamps = [json.loads(payload)["recorded_at"] for (payload,) in ledger.db.execute(
            "SELECT payload FROM events ORDER BY seq")]
    before = _fingerprint(state)
    report = state_report(state, user_directories=False)
    _assert_frozen(state, before)
    _assert_no_sidecars(state)
    audit = next(store for store in report["stores"] if store["name"] == "audit.sqlite")
    assert {table["name"]: table["rows"] for table in audit["tables"]} == {"events": 3, "reservations": 0}
    assert audit["oldest"] == datetime.fromisoformat(stamps[0]).astimezone(timezone.utc).isoformat()
    assert audit["newest"] == datetime.fromisoformat(stamps[-1]).astimezone(timezone.utc).isoformat()
    assert marker not in json.dumps(report)


def test_rows_waiting_in_a_write_ahead_file_are_counted_and_nothing_is_left_beside_it(tmp_path):
    state = tmp_path / ".finassist"
    state.mkdir()
    database = state / "evidence.sqlite"
    writer = sqlite3.connect(database, isolation_level=None)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("PRAGMA wal_autocheckpoint=0")  # Keep the rows in the write-ahead file.
        writer.execute("CREATE TABLE entries(id INTEGER PRIMARY KEY, created_at TEXT)")
        for day in range(1, 6):
            writer.execute("INSERT INTO entries(created_at) VALUES (?)", ("2026-11-%02dT00:00:00+00:00" % day,))
        assert Path(str(database) + "-wal").stat().st_size > 0
        before = _fingerprint(state)
        report = state_report(state, user_directories=False)
        _assert_frozen(state, before)
    finally:
        writer.close()
    store = next(store for store in report["stores"] if store["name"] == "evidence.sqlite")
    assert store.get("error") is None, store
    assert {table["name"]: table["rows"] for table in store["tables"]} == {"entries": 5}
    assert (store["oldest"][:10], store["newest"][:10]) == ("2026-11-01", "2026-11-05")
