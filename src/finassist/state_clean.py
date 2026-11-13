"""Remove old configuration backups and this tool's temporary leftovers.

A dry run lists them and writes nothing. ``--apply`` removes exactly that list.
Everything else in the state folder is reported and kept.

A link is never followed. On Windows that includes every reparse point, a junction among them.
An entry is removed only if it is still the one that was listed. On POSIX a folder is removed
through descriptors bound to the folder that was listed: an entry replaced while the removal runs,
by a link or by another folder, is neither entered nor removed.
Windows has no such interface: there a process of the same user could redirect a removal that
is under way; the temporary folder there belongs to the user.
"""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import re
import shutil
import stat
import sys
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
# The names the writers give backups: the dashboard names one by its content's SHA-256, a
# configuration migration by the UTC time it was taken. No other name is a backup.
_STATE_BACKUP = re.compile(r"[0-9a-f]{64}\.json\Z")
_FILE_BACKUP_STAMP = re.compile(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z\Z")
_FILE_BACKUP_TIME = "%Y%m%dT%H%M%S.%fZ"
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
_REPARSE = "reparse point"
_NOT_REGULAR = "not a regular file"
_NOT_DIR = "not a directory"
_UNREADABLE = "unreadable"
_KEYS = ("kind", "path", "bytes", "reason")
_DIRECTORY = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
)
# Removal through descriptors needs these; POSIX systems have them, Windows does not.
_DESCRIPTORS = (
    {os.open, os.stat, os.unlink, os.rmdir} <= os.supports_dir_fd and os.scandir in os.supports_fd
    and hasattr(os, "fchmod") and bool(getattr(os, "O_NOFOLLOW", 0)) and bool(getattr(os, "O_DIRECTORY", 0))
)


class EntryChanged(OSError):
    """The entry at a listed path is no longer the one that was listed."""


def run_state_clean(args) -> int:
    """`finassist state clean`: one JSON line. A dry run writes nothing, including no audit entry."""
    from .state_location import state_location

    _check(args)
    folder, origin = state_location(args, refuse=False)
    removable, kept, problem = _plan(folder, args)
    if not (args.apply and removable):
        report = _document(
            folder, origin, removable, kept, applied=bool(args.apply), removed=[], problem=problem)
        _emit(report)
        return 0
    if _ledger_present(folder):
        # The removal must be recordable: a chain that does not verify, or cannot record that the
        # command started, stops it before anything is removed.
        _verify_ledger(folder)
        removed, audit = _remove_recorded(folder, removable)
    else:
        removed, audit = _remove_all(removable), "no ledger"
    report = _document(folder, origin, removable, kept, applied=True, removed=removed, problem=problem)
    report["audit"] = audit
    _emit(report)
    return 1 if audit == "failed" or any("error" in item for item in removable) else 0


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
    # regular_path has refused a link or a reparse point here or in any parent folder.
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


def _backup_name(name: str, prefix: str | None) -> bool:
    """Whether a writer gives backups this name. Anything else is neither removed nor counted."""
    if prefix is None:
        return _STATE_BACKUP.fullmatch(name) is not None
    stamp = name[len(prefix):]
    if not name.startswith(prefix) or _FILE_BACKUP_STAMP.fullmatch(stamp) is None:
        return False
    try:
        datetime.strptime(stamp, _FILE_BACKUP_TIME)
    except ValueError:
        return False
    return True


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
        if not _backup_name(child.name, prefix):
            kept.append(_note(kind, child, _UNKNOWN))
            continue
        listed = _regular(child, kind, kept)
        if listed is not None:
            regular.append(listed)
    regular.sort(key=lambda row: (row[0], row[1]))  # time, then name: a greater name is newer
    stale, fresh = _split(regular, keep)
    for _mtime, _name, path, size, identity in stale:
        removable.append(_item(kind, path, size, _BACKUP_DROP, identity))
    for _mtime, _name, path, _size, _identity in fresh:
        kept.append(_note(kind, path, _BACKUP_KEEP))


def _regular(child: Path, kind: str, kept: list) -> tuple | None:
    try:
        info = child.lstat()
    except OSError as exc:
        kept.append(_note(kind, child, _UNREADABLE, error=type(exc).__name__))
        return None
    linked = _link_reason(info)
    if linked is not None:
        kept.append(_note(kind, child, linked))
        return None
    if not stat.S_ISREG(info.st_mode):
        kept.append(_note(kind, child, _NOT_REGULAR))
        return None
    return (info.st_mtime_ns, child.name, child, info.st_size, _identity(info))


def _link_reason(info: os.stat_result) -> str | None:
    """A symbolic link, or on Windows any other reparse point, such as a junction. Neither is followed."""
    if stat.S_ISLNK(info.st_mode):
        return _LINK
    if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        return _REPARSE
    return None


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _dir_status(directory: Path) -> tuple[str, str | None]:
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return "absent", None
    except OSError as exc:
        return _UNREADABLE, type(exc).__name__
    linked = _link_reason(info)
    if linked is not None:
        return linked, None
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
        size = _entry_bytes(path, info)
    except OSError as exc:
        kept.append(_note("temporary", path, _UNREADABLE, error=type(exc).__name__))
        return
    removable.append(_item("temporary", path, size, _TEMP_DROP, _identity(info)))


def _entry_bytes(path: Path, info: os.stat_result) -> int:
    if _link_reason(info) is not None:
        return 0  # the link itself; never the target
    if stat.S_ISREG(info.st_mode):
        return info.st_size
    if stat.S_ISDIR(info.st_mode):
        return _tree_bytes(path)
    return 0


def _tree_bytes(path: Path) -> int:
    """Regular files' bytes under `path`. A link or a reparse point is counted as nothing and not entered."""
    total = 0
    pending = [path]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if _link_reason(info) is not None:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                elif stat.S_ISREG(info.st_mode):
                    total += info.st_size
    return total


def _remove_all(items: list[dict]) -> list[dict]:
    removed = []
    for item in items:
        try:
            _remove_entry(Path(item["path"]), item["_identity"])
        except (OSError, RecursionError) as exc:  # A tree too deep to walk is a failed removal, not a crash.
            item["error"] = type(exc).__name__
        else:
            removed.append({key: item[key] for key in _KEYS})
    return removed


def _remove_entry(path: Path, identity: tuple[int, int, int]) -> None:
    """Remove one listed entry, if it is still the one listed. A link is unlinked; its target is never
    opened."""
    info = path.lstat()
    if _identity(info) != identity:
        raise EntryChanged(path.name)
    if _link_reason(info) is not None or not stat.S_ISDIR(info.st_mode):
        _unlink(path)
    elif _DESCRIPTORS:
        _remove_tree_bound(path, identity)
    else:
        # Windows: a link or a junction inside is unlinked, never entered.
        shutil.rmtree(path, **{_HANDLER: _retry_read_only})


def _remove_tree_bound(path: Path, identity: tuple[int, int, int]) -> None:
    """POSIX: remove a listed folder through descriptors only. The folder is opened without following a link
    and must be the one listed; what is inside is removed relative to it, each folder checked the same way;
    last, the name is removed only if it still names that folder."""
    parent = os.open(path.parent, _DIRECTORY)
    try:
        folder = os.open(path.name, _DIRECTORY, dir_fd=parent)
        try:
            if _identity(os.fstat(folder)) != identity:
                raise EntryChanged(path.name)
            _empty_folder(folder)
        finally:
            os.close(folder)
        _rmdir_if_same(parent, path.name, identity)
    finally:
        os.close(parent)


def _empty_folder(descriptor: int) -> None:
    """Remove everything in an open folder. A read-only folder is first made rwx for its user, through its
    descriptor; a link is unlinked itself, never followed."""
    mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
    if mode & stat.S_IRWXU != stat.S_IRWXU:
        os.fchmod(descriptor, mode | stat.S_IRWXU)
    with os.scandir(descriptor) as entries:
        listed = [(entry.name, entry.stat(follow_symlinks=False)) for entry in entries]
    for name, info in listed:
        if not stat.S_ISDIR(info.st_mode):
            os.unlink(name, dir_fd=descriptor)
            continue
        child = os.open(name, _DIRECTORY, dir_fd=descriptor)
        try:
            if _identity(os.fstat(child)) != _identity(info):
                raise EntryChanged(name)
            _empty_folder(child)
        finally:
            os.close(child)
        _rmdir_if_same(descriptor, name, _identity(info))


def _rmdir_if_same(parent: int, name: str, identity: tuple[int, int, int]) -> None:
    if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity:
        raise EntryChanged(name)
    os.rmdir(name, dir_fd=parent)

def _retry_read_only(function, path, error) -> None:
    """Windows: a read-only file or folder is made writable and removed again. A link never is."""
    failure = error if isinstance(error, BaseException) else error[1]
    if not isinstance(failure, PermissionError) or function not in {os.unlink, os.remove, os.rmdir}:
        raise failure
    info = os.lstat(path)
    read_only = getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_READONLY
    if _link_reason(info) is not None or not read_only:
        raise failure
    os.chmod(path, stat.S_IWRITE)
    function(path)


_HANDLER = "onexc" if sys.version_info >= (3, 12) else "onerror"


def _unlink(path: Path) -> None:
    """Remove a file or a link itself. On Windows a read-only file is made writable first; a link never
    is."""
    try:
        os.unlink(path)
    except PermissionError as exc:
        if os.name != "nt":
            raise
        _retry_read_only(os.unlink, path, exc)


def _remove_recorded(state_dir: Path, removable: list[dict]) -> tuple[list[dict], str]:
    """Remove inside the command's audit: nothing is removed unless its start is recorded. Counts and bytes
    only. A record that fails after the removal began is reported as `failed`, with what was removed."""
    import sqlite3

    from .auditing import command_audit
    from .config import Config
    from .ledger import Ledger

    path = state_dir / "audit.sqlite"
    removed: list[dict] | None = None
    try:
        # The configuration file is not read: --config only names sibling backups. The hash is the
        # default configuration, the same way `update` records a run that has no project file.
        with command_audit(path, "state-clean", Config()) as outcome:
            removed = _remove_all(removable)
            failed = sum("error" in item for item in removable)
            with Ledger(path) as ledger:
                ledger.append({
                    "event": "state_cleaned",
                    "removed_count": len(removed),
                    "removed_bytes": sum(item["bytes"] for item in removed),
                    "failed_count": failed,
                })
            outcome["exit_code"] = 1 if failed else 0
    except AssistantError:
        if removed is None:
            raise
        return removed, "failed"
    except (OSError, sqlite3.Error, ValueError) as exc:
        if removed is None:
            raise AssistantError("audit_unavailable") from exc
        return removed, "failed"
    return removed, "recorded"


def _ledger_present(state_dir: Path) -> bool:
    """Any entry named audit.sqlite counts, a link or a damaged file included: the ledger then decides."""
    return os.path.lexists(Path(state_dir) / "audit.sqlite")


def _verify_ledger(state_dir: Path) -> None:
    import sqlite3

    from .ledger import Ledger

    try:
        with Ledger(Path(state_dir) / "audit.sqlite", read_only=True) as ledger:
            ledger.verify()
    except AssistantError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise AssistantError("audit_unavailable") from exc


def _document(state_dir, origin, removable, kept, *, applied, removed, problem) -> dict:
    listed = [{key: value for key, value in item.items() if not key.startswith("_")} for item in removable]
    report = {
        "schema_version": 1, "mode": "state-clean", "applied": applied, "state_dir": str(state_dir),
        "state_dir_source": origin, "removable": listed, "removed": removed, "kept": kept,
        "removable_bytes": sum(item["bytes"] for item in removable),
        "removed_bytes": sum(item["bytes"] for item in removed),
    }
    if problem is not None:
        report["error"] = problem
    return report


def _emit(report: dict) -> None:
    from .security import canonical

    print(canonical(report).decode())


def _item(kind: str, path: Path, size: int, reason: str, identity: tuple[int, int, int]) -> dict:
    return {"kind": kind, "path": str(path), "bytes": size, "reason": reason, "_identity": identity}


def _note(kind: str, path: Path, reason: str, error: str | None = None) -> dict:
    entry = {"kind": kind, "path": str(path), "reason": reason}
    if error is not None:
        entry["error"] = error
    return entry


def _order(entry: dict) -> tuple:
    return (entry["kind"], entry["path"])
