"""Read-only version guards and explicit forward copies; original stores stay intact."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile

from .errors import AssistantError
from .security import digest, regular_path

SUPPORTED_EVIDENCE_SCHEMA = 2


class EvidenceSchemaError(AssistantError):
    def __init__(self, found: int):
        super().__init__("evidence_store_newer_schema_upgrade_required")
        self.public_details = {"store_schema": found, "supported_schema": SUPPORTED_EVIDENCE_SCHEMA,
                               "upgrade_hint": "Upgrade finledgerpoli before opening this evidence store."}


def _name_parts(path: Path) -> tuple[str, int | None, str]:
    # Path.stem treats a suffixless version marker as a file extension.
    # Parse the full name so evidence.v1 and evidence.v1.sqlite share a root.
    match = re.fullmatch(r"(.+)\.v([1-9][0-9]*)(\.[^.]+)?", path.name)
    if match:
        return match[1], int(match[2]), match[3] or ""
    return path.stem, None, path.suffix


def _named_version(path: Path) -> int | None:
    return _name_parts(path)[1]


def resolve_evidence_path(path: Path) -> Path:
    """A logical legacy filename selects the latest explicit migrated sibling.

    Explicit versioned paths remain explicit. Never fall back to the legacy
    file when a newer versioned store is beyond this reader's supported schema.
    """
    path = regular_path(path)
    if _named_version(path) is not None or not path.parent.exists():
        return path
    pattern = re.compile(re.escape(path.stem) + r"\.v([1-9][0-9]*)" + re.escape(path.suffix))
    candidates = []
    for entry in path.parent.iterdir():
        match = pattern.fullmatch(entry.name)
        if match:
            candidates.append((int(match[1]), regular_path(entry)))
    return max(candidates, key=lambda item: item[0])[1] if candidates else path


def _version(connection, path: Path) -> int:
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    named = _named_version(path)
    if version > SUPPORTED_EVIDENCE_SCHEMA or (named is not None and named > SUPPORTED_EVIDENCE_SCHEMA):
        raise EvidenceSchemaError(max(version, named or 0))
    if named is not None and version != named:
        raise AssistantError("evidence_store_schema_mismatch")
    return version


@contextmanager
def readonly_store(path: Path):
    path = regular_path(path)
    if not path.is_file():
        raise AssistantError("evidence_store_missing")
    connection = None
    try:
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=15)
        _version(connection, path)
        yield connection
    except sqlite3.Error as exc:
        raise AssistantError("evidence_store_unavailable") from exc
    finally:
        if connection is not None:
            connection.close()


def check_evidence_schema(path: Path) -> int | None:
    path = regular_path(path)
    if not path.exists():
        if _named_version(path) not in {None, SUPPORTED_EVIDENCE_SCHEMA}:
            raise AssistantError("evidence_store_schema_mismatch")
        return None
    try:
        # Inspect before a writable open (including WAL checkpoint/cleanup).
        # Sidecars are normal SQLite state, not a reason to refuse access.
        with readonly_store(path) as connection:
            return _version(connection, path)
    except AssistantError as exc:
        cause = exc.__cause__
        if not isinstance(cause, sqlite3.Error) or getattr(cause, "sqlite_errorcode", None) not in {
            sqlite3.SQLITE_READONLY_RECOVERY, sqlite3.SQLITE_READONLY_ROLLBACK,
        }:
            raise
    # A read-only connection cannot recover a hot rollback journal. Refuse an
    # identifiable future header/name before letting SQLite recover this store.
    with path.open("rb") as stream:
        header = stream.read(64)
    named = _named_version(path) or 0
    version = int.from_bytes(header[60:64], "big", signed=True) if header[:16] == b"SQLite format 3\x00" else 0
    if max(version, named) > SUPPORTED_EVIDENCE_SCHEMA:
        raise EvidenceSchemaError(max(version, named))
    connection = None
    try:
        connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=15)
        return _version(connection, path)
    except sqlite3.Error as exc:
        raise AssistantError("evidence_store_unavailable") from exc
    finally:
        if connection is not None:
            connection.close()


def verify_connection(connection) -> dict:
    require_evidence_layout(connection)
    if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
        raise AssistantError("evidence_store_integrity_failed")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise AssistantError("evidence_store_integrity_failed")
    entries = {}
    children = set()
    for identifier, payload, value_hash, supersedes, status in connection.execute(
        "SELECT id,payload,hash,supersedes,status FROM entries ORDER BY id"
    ):
        if digest(payload.encode()) != value_hash or status not in {"draft", "approved", "rejected"}:
            raise AssistantError("evidence_store_integrity_failed")
        try:
            document = json.loads(payload)
            identity = tuple(document[key] for key in ("entity", "metric", "unit", "period_start", "period_end", "period_kind"))
        except (ValueError, TypeError, KeyError) as exc:
            raise AssistantError("evidence_store_integrity_failed") from exc
        if supersedes is not None:
            if supersedes not in entries or supersedes in children or entries[supersedes][2] != identity:
                raise AssistantError("evidence_store_integrity_failed")
            children.add(supersedes)
        entries[identifier] = (value_hash, status, identity)
    decisions = {}
    for entry, status, value_hash in connection.execute("SELECT entry,status,hash FROM decisions ORDER BY id"):
        if (entry not in entries or entry in decisions or status not in {"approved", "rejected"}
                or entries[entry][:2] != (value_hash, status)):
            raise AssistantError("evidence_store_integrity_failed")
        decisions[entry] = status
    if any((status == "draft") != (identifier not in decisions) for identifier, (_, status, _) in entries.items()):
        raise AssistantError("evidence_store_integrity_failed")
    return {"verified": True, "schema_version": connection.execute("PRAGMA user_version").fetchone()[0],
            "entries": len(entries), "decisions": len(decisions)}


def require_evidence_layout(connection) -> None:
    required = {("entries", "table"), ("decisions", "table"),
                ("immutable_evidence", "trigger"), ("no_delete_evidence", "trigger"),
                ("immutable_decision", "trigger"), ("no_delete_decision", "trigger")}
    actual = set(connection.execute("SELECT name,type FROM sqlite_master WHERE type IN ('table','trigger')"))
    if not required <= actual:
        raise AssistantError("evidence_store_schema_invalid")


def verify_evidence_store(path: Path) -> dict:
    path = resolve_evidence_path(path)
    # Verification also permits SQLite's ordinary crash recovery, never schema
    # migration. Explicit migration retains its separate strict sidecar guard.
    check_evidence_schema(path)
    with readonly_store(path) as connection:
        return verify_connection(connection)


def _file_hash(path: Path) -> str:
    import hashlib

    value = hashlib.sha256()
    with regular_path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1_048_576), b""):
            value.update(block)
    return value.hexdigest()


def _no_sidecars(path: Path) -> None:
    # Require a closed/quiescent rollback-journal store. Copying a lone main
    # file from an active WAL store would not provide a self-contained backup.
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise AssistantError("evidence_store_busy_close_writers")


def migrate_evidence_store(path: Path, *, dry_run: bool = True) -> dict:
    logical = regular_path(path)
    source = resolve_evidence_path(logical)
    _no_sidecars(source)
    before_hash = _file_hash(source) if source.exists() else None
    with readonly_store(source) as connection:
        connection.execute("BEGIN")
        checked = verify_connection(connection)
        version = checked["schema_version"]
        if version == SUPPORTED_EVIDENCE_SCHEMA:
            return {**checked, "changed": False, "written": False, "backup": None, "destination": str(source)}
        if version not in {0, 1} or SUPPORTED_EVIDENCE_SCHEMA != 2:
            raise AssistantError("evidence_migration_unavailable")
        # An explicitly named older store still writes a sibling of its logical
        # root, never evidence.v1.v2.sqlite or an in-place version change.
        stem, _, suffix = _name_parts(logical)
        destination = regular_path(logical.with_name(stem + ".v2" + suffix))
        if destination.exists():
            raise AssistantError("evidence_migration_target_exists")
        report = {**checked, "changed": True, "written": False, "source_sha256": before_hash,
                  "target_schema_version": 2, "backup": str(source), "destination": str(destination)}
        if dry_run:
            return report
        descriptor, temporary_name = tempfile.mkstemp(prefix=".evidence-migrate-", suffix=".sqlite", dir=source.parent)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            temporary.chmod(0o600)
            target = sqlite3.connect(temporary)
            try:
                connection.backup(target)
                target.execute("PRAGMA user_version=2")
                target.commit()
                verify_connection(target)
            finally:
                target.close()
            # Windows _commit needs a writable descriptor. This is only the
            # verified private copy; the original store remains read-only.
            with temporary.open("r+b") as stream:
                os.fsync(stream.fileno())
            _no_sidecars(source)
            if _file_hash(source) != before_hash:
                raise AssistantError("evidence_source_changed_during_migration")
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise AssistantError("evidence_migration_target_exists") from exc
            if os.name == "posix":
                directory = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            return {**report, "written": True, "destination_sha256": _file_hash(destination)}
        finally:
            temporary.unlink(missing_ok=True)
