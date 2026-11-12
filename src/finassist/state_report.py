"""Read-only inventory of a finassist state folder. Never creates or modifies files."""

from __future__ import annotations

from contextlib import closing
import json
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sqlite3
import shutil
import stat
import tempfile

from .errors import AssistantError
from .security import regular_path
from .update_settings import user_directory

# setup/ belongs to initialization. Migration leaves evidence.sqlite beside evidence.vN.sqlite.
_FOLDERS = ("patches", "workflow-runs", "workflow-locks", "history", "config-backups", "setup")
_PLAIN_DATABASES = frozenset({"audit.sqlite", "evidence.sqlite"})
_VERSIONED_EVIDENCE = re.compile(r"evidence\.v[1-9][0-9]*\.sqlite\Z")
_SIDECARS = ("-wal", "-shm", "-journal")
_UNKNOWN_LIMIT = 50
_TIME_NAMES = frozenset({"timestamp", "time", "date", "day"})
_TIME_SUFFIXES = ("_at", "_time", "_timestamp")
_TIME_TEXT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
    r"(?:[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})?)?"
)
# RuntimeError: Path.home() raises it when no home folder can be found, as in a minimal container.
_READ_ERRORS = (AssistantError, OSError, sqlite3.Error, ValueError, TypeError, RuntimeError)
_TABLES = (
    "SELECT name FROM sqlite_master WHERE type = 'table' "
    "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name"
)

def run_state(args) -> int:
    """`finassist state status`: print the inventory as one JSON line. Reads only."""
    from .security import canonical

    print(canonical(state_report(args.state_dir, user_directories=not args.no_user)).decode())
    return 0


def state_report(state_dir: Path, *, user_directories: bool = True) -> dict:
    """A read-only inventory of the state folder: what is there, how large, how old. Never writes."""
    report = {
        "schema_version": 1, "mode": "state-report", "state_dir": str(state_dir), "exists": False,
        "stores": [], "unknown": [], "unknown_more": 0, "total_bytes": 0,
    }
    if user_directories:
        report["user"] = {kind: _user_entry(kind) for kind in ("config", "cache")}
    try:
        root = regular_path(Path(state_dir))
    except _READ_ERRORS as exc:
        report["error"] = type(exc).__name__
        return report
    if not root.exists():
        return report
    if not root.is_dir():
        report["exists"], report["error"] = True, "NotADirectoryError"
        return report
    report["exists"] = True
    try:
        names = sorted(path.name for path in root.iterdir())
    except OSError as exc:
        report["error"] = type(exc).__name__
        return report
    present, stores, unknown, total = set(names), [], [], 0
    for name in names:
        if (base := _sidecar_base(name)) is not None and base in present:
            continue
        known = _is_database(name) or name in _FOLDERS
        entry = _store(root, name) if known else _unknown(root, name)
        (stores if known else unknown).append(entry)
        total += entry["bytes"]
    stores.sort(key=_store_key)
    report["stores"] = stores
    report["unknown"] = unknown[:_UNKNOWN_LIMIT]
    report["unknown_more"] = max(0, len(unknown) - _UNKNOWN_LIMIT)
    report["total_bytes"] = total
    return report

def _is_database(name: str) -> bool:
    return name in _PLAIN_DATABASES or _VERSIONED_EVIDENCE.fullmatch(name) is not None

def _sidecar_base(name: str) -> str | None:
    for suffix in _SIDECARS:
        if name.endswith(suffix) and _is_database(name[: -len(suffix)]):
            return name[: -len(suffix)]
    return None

def _store_key(entry: dict) -> tuple:
    name = entry["name"]
    if name == "audit.sqlite":
        return (0, 0, name)
    if name == "evidence.sqlite" or _VERSIONED_EVIDENCE.fullmatch(name):
        version = 0 if name == "evidence.sqlite" else int(name[len("evidence.v"): -len(".sqlite")])
        return (1, version, name)
    return (2, _FOLDERS.index(name), name) if name in _FOLDERS else (3, 0, name)

def _store(root: Path, name: str) -> dict:
    kind = "database" if _is_database(name) else "folder"
    entry: dict = {"name": name, "kind": kind, "bytes": 0}
    try:
        path = regular_path(root / name)
        if kind == "database":
            entry["bytes"] = _database_bytes(path)
            entry.update(_database_details(path))
        else:
            if not stat.S_ISDIR(path.lstat().st_mode):
                raise NotADirectoryError(name)
            total, count, oldest, newest = _measure_tree(path)
            entry["bytes"], entry["files"] = total, count
            if oldest is not None and newest is not None:
                entry["oldest"], entry["newest"] = _iso(oldest), _iso(newest)
    except _READ_ERRORS as exc:
        entry["error"] = type(exc).__name__
        for key in ("tables", "files", "oldest", "newest"):
            entry.pop(key, None)
    return entry

def _unknown(root: Path, name: str) -> dict:
    entry = {"name": name, "bytes": 0}
    try:
        path = regular_path(root / name)
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            entry["bytes"] = _measure_tree(path)[0]
        elif stat.S_ISREG(info.st_mode):
            entry["bytes"] = info.st_size
        else:
            raise OSError(name)
    except _READ_ERRORS as exc:
        entry["error"] = type(exc).__name__
    return entry

def _database_bytes(path: Path) -> int:
    total = _file_size(path)
    for suffix in _SIDECARS:
        sidecar = Path(str(path) + suffix)
        try:
            sidecar.lstat()
        except FileNotFoundError:
            continue
        total += _file_size(sidecar)
    return total

def _file_size(path: Path) -> int:
    info = regular_path(path).lstat()
    if stat.S_ISDIR(info.st_mode):
        raise IsADirectoryError(path.name)
    if not stat.S_ISREG(info.st_mode):
        raise OSError(path.name)
    return info.st_size

def _database_details(path: Path) -> dict:
    """Tables, row counts and dates of one database, without writing anything beside it.

    immutable=1 makes SQLite read the file as it is and create nothing, but it also ignores a journal or a
    write-ahead file, whose content then goes uncounted. So a database with a side file is read from a private
    copy of the database and its side files together, and the copy is removed afterwards.
    """
    sides = [Path(str(path) + suffix) for suffix in _SIDECARS if Path(str(path) + suffix).exists()]
    if not sides:
        return _read_database(path.as_uri() + "?mode=ro&immutable=1")
    folder = Path(tempfile.mkdtemp(prefix="finassist-state-"))
    try:
        copy = folder / path.name
        for source in (path, *sides):
            shutil.copyfile(regular_path(source), folder / source.name, follow_symlinks=False)
        try:
            return _read_database(copy.as_uri() + "?mode=ro")
        except sqlite3.Error:
            pass  # A side file SQLite cannot use: count what the database file itself holds, and say so.
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    return {**_read_database(path.as_uri() + "?mode=ro&immutable=1"), "side_files": "unreadable"}


def _read_database(uri: str) -> dict:
    with closing(sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)) as connection:
        connection.execute("PRAGMA query_only=ON")
        tables, oldest, newest = [], None, None
        for (table_name,) in connection.execute(_TABLES):
            quoted = _quote(table_name)
            count = connection.execute("SELECT COUNT(*) FROM " + quoted).fetchone()[0]  # noqa: S608
            tables.append({"name": table_name, "rows": int(count)})
            columns = connection.execute("PRAGMA table_info(" + quoted + ")")  # noqa: S608
            for column in columns:
                if _time_column(column[1], column[2]):
                    oldest, newest = _bounds(connection, quoted, _quote(column[1]), oldest, newest)
        if any(table["name"] == "events" for table in tables):
            oldest, newest = _chain_dates(connection, oldest, newest)
        details: dict = {"tables": tables}
        if oldest is not None and newest is not None:
            details["oldest"], details["newest"] = oldest.isoformat(), newest.isoformat()
        return details

def _chain_dates(connection, oldest, newest):
    """The audit chain stamps every entry with recorded_at, inside its JSON payload. The chain only grows, so its
    first and last entries hold the oldest and newest times. Only that field of the two entries is read."""
    try:
        rows = connection.execute("SELECT payload FROM events WHERE seq IN "
                                  "((SELECT MIN(seq) FROM events), (SELECT MAX(seq) FROM events))").fetchall()
    except sqlite3.Error:
        return oldest, newest  # Not the audit chain's table.
    for (payload,) in rows:
        try:
            parsed = _parse_time(json.loads(payload).get("recorded_at"))
        except (TypeError, ValueError, AttributeError):
            continue
        if parsed is not None:
            oldest = parsed if oldest is None else min(oldest, parsed)
            newest = parsed if newest is None else max(newest, parsed)
    return oldest, newest


def _bounds(connection, table: str, column: str, oldest, newest):
    # Identifiers are quoted from sqlite_master / PRAGMA table_info, then read under query_only.
    sql = "SELECT MIN(" + column + "), MAX(" + column + ") FROM " + table  # noqa: S608
    sql += " WHERE typeof(" + column + ") = 'text'"  # noqa: S608
    for value in connection.execute(sql).fetchone():
        parsed = _parse_time(value)
        if parsed is None:
            continue
        oldest = parsed if oldest is None else min(oldest, parsed)
        newest = parsed if newest is None else max(newest, parsed)
    return oldest, newest

def _time_column(name: object, declared: object) -> bool:
    if not isinstance(name, str):
        return False
    lowered = name.lower()
    obvious = lowered in _TIME_NAMES or lowered.endswith(_TIME_SUFFIXES)
    kind = declared.upper() if isinstance(declared, str) else ""
    return obvious and "INT" not in kind and "BLOB" not in kind and "REAL" not in kind

def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or _TIME_TEXT.fullmatch(value) is None:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    text = text[:10] + "T" + text[11:] if len(text) > 10 and text[10] == " " else text
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

def _quote(name: object) -> str:
    if not isinstance(name, str) or "\x00" in name:
        raise ValueError("invalid identifier")
    return '"' + name.replace('"', '""') + '"'

def _raise(error: OSError) -> None:
    raise error


def _measure_tree(path: Path) -> tuple[int, int, int | None, int | None]:
    # os.walk skips a folder it cannot list unless told otherwise; a partial count must not pass for a full one.
    total, count, oldest, newest = 0, 0, None, None
    for directory, dirnames, filenames in os.walk(path, followlinks=False, onerror=_raise):
        current = regular_path(Path(directory))
        for dirname in dirnames:
            regular_path(current / dirname)
        for filename in filenames:
            info = regular_path(current / filename).lstat()
            if not stat.S_ISREG(info.st_mode):
                raise OSError(filename)
            total += info.st_size
            count += 1
            oldest = info.st_mtime_ns if oldest is None else min(oldest, info.st_mtime_ns)
            newest = info.st_mtime_ns if newest is None else max(newest, info.st_mtime_ns)
    return total, count, oldest, newest

def _iso(stamp_ns: int) -> str:
    return datetime.fromtimestamp(stamp_ns / 1_000_000_000, timezone.utc).isoformat()

def _user_entry(kind: str) -> dict:
    try:
        path = regular_path(user_directory(kind))
    except _READ_ERRORS as exc:
        return {"path": "", "exists": False, "bytes": 0, "error": type(exc).__name__}
    entry = {"path": str(path), "exists": False, "bytes": 0}
    try:
        info = path.lstat()
    except FileNotFoundError:
        return entry
    except OSError as exc:
        entry["error"] = type(exc).__name__
        return entry
    entry["exists"] = True
    try:
        if stat.S_ISDIR(info.st_mode):
            entry["bytes"] = _measure_tree(path)[0]
        elif stat.S_ISREG(info.st_mode):
            entry["bytes"] = info.st_size
        else:
            raise OSError(kind)
    except _READ_ERRORS as exc:
        entry["error"] = type(exc).__name__
    return entry
