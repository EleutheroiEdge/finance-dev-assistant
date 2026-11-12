"""Remove old configuration backups and this tool's temporary leftovers.

A dry run lists them and writes nothing. ``--apply`` removes exactly that list.
Everything else in the state folder is reported and kept.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import tempfile
import time

from .errors import AssistantError
from .security import regular_path

# Prefixes of directories and files this package creates with tempfile. Entries in the
# process temporary directory qualify only when the name starts with one of these.
_TEMP_PREFIXES = (
    "finassist-check-", "finassist-ci-", "finassist-ci-refused-", "finassist-eval-",
    "finassist-home-", "finassist-ignore-", "finassist-model-gate-",
    "finassist-patch-screen-", "finassist-state-", "finassist-workflow-",
)
_SIDECARS = ("-wal", "-shm", "-journal")
_VERSIONED_EVIDENCE = re.compile(r"evidence\.v[1-9][0-9]*\.sqlite\Z")
_FOLDERS = {
    "patches": "rollback needs patches",
    "workflow-runs": "completed run is readiness evidence",
    "workflow-locks": "a lock file keeps one workflow to one process",
    "history": "journals reconcile the budget",
    "setup": "setup state",
}
_AUDIT = "audit chain is evidence"
_EVIDENCE = "evidence store"
_UNKNOWN = "unknown name"
_BACKUP_KEEP = "newest backup"
_BACKUP_DROP = "beyond the newest backups"
_BACKUP_DIR = "config backup directory"
_TEMP_DROP = "temporary leftover"
_TEMP_YOUNG = "newer than the age threshold"
_TEMP_OWNER = "not owned by the current user"
_LINK = "symbolic link"
_NOT_REGULAR = "not a regular file"
_NOT_DIR = "not a directory"
_UNREADABLE = "unreadable"
_KEYS = ("kind", "path", "bytes", "reason")


def run_state_clean(args) -> int:
    """`finassist state clean`: one JSON line. A dry run writes nothing, including no audit entry."""
    from .state_location import state_location

    _check(args)
    folder, origin = state_location(args, refuse=False)
    removable, kept, problem = _plan(folder, args)
    removed = _remove_all(removable) if args.apply else []
    report = _document(
        folder, origin, removable, kept, applied=bool(args.apply), removed=removed, problem=problem)
    failed = bool(args.apply and any("error" in item for item in removable))
    if removed:
        report["audit"] = _audit(folder, removed, sum("error" in item for item in removable))
    _emit(report)
    return 1 if failed else 0


def _check(args) -> None:
    if args.keep_backups < 1 or args.older_than < 1:
        raise ValueError("keep-backups and older-than must be at least 1")


def _plan(state_dir: Path, args) -> tuple[list, list, str | None]:
    removable, kept, problem = _state_plan(state_dir, args.keep_backups)
    _config_plan(getattr(args, "config", None), args.keep_backups, removable, kept)
    if not args.no_temp:
        _temp_plan(args.older_than, removable, kept)
    removable.sort(key=_order)
    kept.sort(key=_order)
    return removable, kept, problem


def _state_plan(state_dir: Path, keep: int) -> tuple[list, list, str | None]:
    removable: list = []
    kept: list = []
    try:
        root = regular_path(state_dir)
    except (OSError, AssistantError) as exc:
        return removable, kept, type(exc).__name__
    if not root.exists():
        return removable, kept, None
    if not stat.S_ISDIR(root.lstat().st_mode):
        return removable, kept, "NotADirectoryError"
    try:
        children = list(root.iterdir())
    except OSError as exc:
        return removable, kept, type(exc).__name__
    for child in children:
        _classify(child, keep, removable, kept)
    return removable, kept, None


def _classify(child: Path, keep: int, removable: list, kept: list) -> None:
    if child.name == "config-backups":
        _scan_backups(child, keep, "config-backup", removable, kept, prefix=None, announce=True)
        return
    store = _store(child.name)
    if store is None:
        kept.append(_note("unknown", child, _UNKNOWN))
        return
    kind, reason = store
    kept.append(_note(kind, child, reason))


def _store(name: str) -> tuple[str, str] | None:
    base = _database_base(name)
    if base == "audit.sqlite":
        return "audit", _AUDIT
    if base == "evidence.sqlite" or _VERSIONED_EVIDENCE.fullmatch(base):
        return "evidence", _EVIDENCE
    if name in _FOLDERS:
        return name, _FOLDERS[name]
    return None


def _database_base(name: str) -> str:
    for suffix in _SIDECARS:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _config_plan(config, keep: int, removable: list, kept: list) -> None:
    if config is None:
        return
    name = Path(config).name
    if not name or name in {".", ".."}:
        return
    parent = Path(config).expanduser().absolute().parent
    try:
        parent = regular_path(parent)
    except (OSError, AssistantError) as exc:
        kept.append(_note("config-file-backup", parent, _UNREADABLE, error=type(exc).__name__))
        return
    _scan_backups(
        parent, keep, "config-file-backup", removable, kept, prefix=name + ".backup-", announce=False)


def _scan_backups(directory: Path, keep: int, kind: str, removable: list, kept: list, *,
                  prefix: str | None, announce: bool) -> None:
    status, failure = _dir_status(directory)
    if status == "absent":
        return
    if status != "ok":
        kept.append(_note(kind, directory, status, error=failure))
        return
    try:
        children = list(directory.iterdir())
    except OSError as exc:
        kept.append(_note(kind, directory, _UNREADABLE, error=type(exc).__name__))
        return
    if announce:
        kept.append(_note(kind, directory, _BACKUP_DIR))
    if prefix is not None:
        children = [child for child in children if child.name.startswith(prefix)]
    regular = []
    for child in children:
        listed = _regular(child, kind, kept)
        if listed is not None:
            regular.append(listed)
    regular.sort(key=lambda row: (row[0], row[1]))  # time, then name: a greater name is newer
    stale, fresh = _split(regular, keep)
    for _mtime, _name, path, size in stale:
        removable.append(_item(kind, path, size, _BACKUP_DROP))
    for _mtime, _name, path, _size in fresh:
        kept.append(_note(kind, path, _BACKUP_KEEP))


def _regular(child: Path, kind: str, kept: list) -> tuple | None:
    try:
        info = child.lstat()
    except OSError as exc:
        kept.append(_note(kind, child, _UNREADABLE, error=type(exc).__name__))
        return None
    if stat.S_ISLNK(info.st_mode):
        kept.append(_note(kind, child, _LINK))
        return None
    if not stat.S_ISREG(info.st_mode):
        kept.append(_note(kind, child, _NOT_REGULAR))
        return None
    return (info.st_mtime_ns, child.name, child, info.st_size)


def _dir_status(directory: Path) -> tuple[str, str | None]:
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return "absent", None
    except OSError as exc:
        return _UNREADABLE, type(exc).__name__
    if stat.S_ISLNK(info.st_mode):
        return _LINK, None
    if not stat.S_ISDIR(info.st_mode):
        return _NOT_DIR, None
    return "ok", None


def _split(rows: list[tuple], keep: int) -> tuple[list, list]:
    """Oldest first. The last `keep` rows are the ones that stay."""
    if len(rows) <= keep:
        return [], rows
    start = len(rows) - keep
    return rows[:start], rows[start:]


def _temp_plan(older_than: int, removable: list, kept: list) -> None:
    root = Path(tempfile.gettempdir())
    status, failure = _dir_status(root)
    if status != "ok":
        if status != "absent":
            kept.append(_note("temporary", root, status, error=failure))
        return
    try:
        children = list(root.iterdir())
    except OSError as exc:
        kept.append(_note("temporary", root, _UNREADABLE, error=type(exc).__name__))
        return
    cutoff = time.time() - older_than * 3600
    for child in children:
        if any(child.name.startswith(prefix) for prefix in _TEMP_PREFIXES):
            _consider_temp(child, cutoff, removable, kept)


def _consider_temp(path: Path, cutoff: float, removable: list, kept: list) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        kept.append(_note("temporary", path, _UNREADABLE, error=type(exc).__name__))
        return
    if os.name == "posix" and info.st_uid != os.getuid():
        kept.append(_note("temporary", path, _TEMP_OWNER))
        return
    if info.st_mtime >= cutoff:
        kept.append(_note("temporary", path, _TEMP_YOUNG))
        return
    try:
        size = _entry_bytes(path)
    except OSError as exc:
        kept.append(_note("temporary", path, _UNREADABLE, error=type(exc).__name__))
        return
    removable.append(_item("temporary", path, size, _TEMP_DROP))


def _entry_bytes(path: Path) -> int:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return 0  # the link itself; never the target
    if stat.S_ISREG(info.st_mode):
        return info.st_size
    if stat.S_ISDIR(info.st_mode):
        return _tree_bytes(path)
    return 0


def _tree_bytes(path: Path) -> int:
    total = 0
    for directory, _dirnames, filenames in os.walk(path, followlinks=False, onerror=_raise):
        current = Path(directory)
        for name in filenames:
            info = (current / name).lstat()
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
    return total


def _raise(error: OSError) -> None:
    raise error


def _remove_all(items: list[dict]) -> list[dict]:
    removed = []
    for item in items:
        try:
            _remove_entry(Path(item["path"]))
        except OSError as exc:
            item["error"] = type(exc).__name__
        else:
            removed.append({key: item[key] for key in _KEYS})
    return removed


def _remove_entry(path: Path) -> None:
    """Remove one leftover. A symbolic link is unlinked; its target is never opened."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _unlink(path)
        return
    _grant(path)
    for child in list(path.iterdir()):
        _remove_entry(child)
    try:
        path.rmdir()
    except OSError:
        _grant(path)
        path.rmdir()


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        if stat.S_ISLNK(path.lstat().st_mode):
            raise
        _grant(path)
        path.unlink()


def _grant(path: Path) -> None:
    """Give the owner write, and on a directory the right to list it. Never follows a link."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return
    needed = stat.S_IRWXU if stat.S_ISDIR(info.st_mode) else stat.S_IWUSR
    if (info.st_mode & needed) == needed:
        return
    os.chmod(path, info.st_mode | needed)


def _audit(state_dir: Path, removed: list[dict], failed_count: int) -> str:
    """Counts and byte totals only. An absent chain is left absent."""
    if not _ledger_exists(state_dir):
        return "no ledger"
    from .auditing import command_audit
    from .config import Config
    from .ledger import Ledger

    # The configuration file is not read: --config only names sibling backups. The hash is the
    # default configuration, the same way `update` records a run that has no project file.
    with command_audit(state_dir / "audit.sqlite", "state-clean", Config()) as outcome:
        with Ledger(state_dir / "audit.sqlite") as ledger:
            ledger.append({
                "event": "state_cleaned",
                "removed_count": len(removed),
                "removed_bytes": sum(item["bytes"] for item in removed),
                "failed_count": failed_count,
            })
        outcome["exit_code"] = 1 if failed_count else 0
    return "recorded"


def _ledger_exists(state_dir: Path) -> bool:
    path = Path(state_dir) / "audit.sqlite"
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def _document(state_dir, origin, removable, kept, *, applied, removed, problem) -> dict:
    report = {
        "schema_version": 1, "mode": "state-clean", "applied": applied, "state_dir": str(state_dir),
        "state_dir_source": origin, "removable": removable, "removed": removed, "kept": kept,
        "removable_bytes": sum(item["bytes"] for item in removable),
        "removed_bytes": sum(item["bytes"] for item in removed),
    }
    if problem is not None:
        report["error"] = problem
    return report


def _emit(report: dict) -> None:
    from .security import canonical

    print(canonical(report).decode())


def _item(kind: str, path: Path, size: int, reason: str) -> dict:
    return {"kind": kind, "path": str(path), "bytes": size, "reason": reason}


def _note(kind: str, path: Path, reason: str, error: str | None = None) -> dict:
    entry = {"kind": kind, "path": str(path), "reason": reason}
    if error is not None:
        entry["error"] = error
    return entry


def _order(entry: dict) -> tuple:
    return (entry["kind"], entry["path"])
