"""Local analyst-input lineage: immutable revisions and explicit approval, never model admission."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from .errors import AssistantError
from .finance import observation_check
from .security import canonical, check_text, digest
from . import evidence_schema


class EvidenceStore:
    def __init__(self, path: Path, *, extra_sensitive_patterns: tuple[str, ...] = ()):
        self.extra_sensitive_patterns = extra_sensitive_patterns
        path = evidence_schema.resolve_evidence_path(path)
        existed = path.exists()
        evidence_schema.check_evidence_schema(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=15)
        # Check again before any chmod/DDL: a connection to a pre-existing newer
        # schema must never initialize tables or mutate its bytes.
        try:
            if existed or self.db.execute("PRAGMA user_version").fetchone()[0] != 0:
                evidence_schema._version(self.db, path)
            if existed:
                evidence_schema.require_evidence_layout(self.db)
        except BaseException:
            self.db.close()
            raise
        self.path = path
        path.chmod(0o600)
        self.db.execute("PRAGMA foreign_keys=ON")
        if existed:
            # Opening an existing legacy/current store is not a migration or a
            # repair operation. Missing tables must fail rather than be created.
            return
        try:
            self._create_schema()
        except BaseException:
            self.db.close()
            raise

    def _create_schema(self) -> None:
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY, entity TEXT NOT NULL, metric TEXT NOT NULL,
                payload TEXT NOT NULL, hash TEXT NOT NULL, supersedes INTEGER REFERENCES entries(id),
                status TEXT NOT NULL CHECK(status IN ('draft','approved','rejected')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TRIGGER IF NOT EXISTS immutable_evidence BEFORE UPDATE OF
                id,entity,metric,payload,hash,supersedes,created_at ON entries BEGIN
                SELECT RAISE(ABORT,'immutable_evidence'); END;
            CREATE TRIGGER IF NOT EXISTS no_delete_evidence BEFORE DELETE ON entries BEGIN
                SELECT RAISE(ABORT,'immutable_evidence'); END;
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY, entry INTEGER NOT NULL REFERENCES entries(id),
                status TEXT NOT NULL, hash TEXT NOT NULL, decided_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TRIGGER IF NOT EXISTS immutable_decision BEFORE UPDATE ON decisions BEGIN
                SELECT RAISE(ABORT,'immutable_decision'); END;
            CREATE TRIGGER IF NOT EXISTS no_delete_decision BEFORE DELETE ON decisions BEGIN
                SELECT RAISE(ABORT,'immutable_decision'); END;
        """)
        self.db.execute(f"PRAGMA user_version={evidence_schema.SUPPORTED_EVIDENCE_SCHEMA}")

    def verify(self) -> dict:
        return evidence_schema.verify_connection(self.db)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()

    def add(self, observation: dict, *, supersedes: int | None = None) -> dict:
        if "status" in observation:
            raise AssistantError("approval_cannot_be_supplied_in_content")
        packet = {**observation, "status": "draft"}
        checked = observation_check(
            packet,
            decision_time=observation.get("retrieved_at", ""),
            max_age_days=100_000,
            require_approved=False,
        )
        if not checked["passed"]:
            raise AssistantError("invalid_evidence_metadata")
        check_text(canonical(observation).decode(), extra_patterns=self.extra_sensitive_patterns)
        encoded, value_hash = canonical(observation).decode(), digest(canonical(observation))
        try:
            self.db.execute("BEGIN IMMEDIATE")
            if supersedes is not None:
                old = self.db.execute("SELECT payload FROM entries WHERE id=?", (supersedes,)).fetchone()
                if old is None or self._identity(json.loads(old[0])) != self._identity(observation):
                    raise AssistantError("evidence_lineage_mismatch")
                if self.db.execute("SELECT 1 FROM entries WHERE supersedes=?", (supersedes,)).fetchone():
                    raise AssistantError("evidence_revision_already_exists")
            else:
                existing = self.db.execute(
                    "SELECT payload FROM entries WHERE entity=? AND metric=?",
                    (observation["entity"], observation["metric"]),
                ).fetchall()
                if any(self._identity(json.loads(row[0])) == self._identity(observation) for row in existing):
                    raise AssistantError("evidence_revision_required")
            row = self.db.execute(
                "INSERT INTO entries(entity,metric,payload,hash,supersedes,status) VALUES(?,?,?,?,?,'draft')",
                (observation["entity"], observation["metric"], encoded, value_hash, supersedes),
            )
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        return {"id": row.lastrowid, "hash": value_hash, "status": "draft", "supersedes": supersedes}

    def decide(self, identifier: int, approved_hash: str, *, status: str) -> dict:
        if status not in {"approved", "rejected"}:
            raise AssistantError("invalid_evidence_decision")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT hash,status FROM entries WHERE id=?", (identifier,)).fetchone()
            if row is None or row[0] != approved_hash:
                raise AssistantError("evidence_approval_hash_mismatch")
            if row[1] != "draft":
                raise AssistantError("evidence_decision_already_recorded")
            self.db.execute("UPDATE entries SET status=? WHERE id=?", (status, identifier))
            self.db.execute(
                "INSERT INTO decisions(entry,status,hash) VALUES(?,?,?)", (identifier, status, approved_hash)
            )
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        return {"id": identifier, "hash": approved_hash, "status": status}

    @staticmethod
    def _identity(observation: dict) -> tuple:
        return tuple(
            observation[k] for k in ("entity", "metric", "unit", "period_start", "period_end", "period_kind")
        )

    def latest_approved(
        self,
        entity: str,
        metric: str,
        *,
        period_end: str | None = None,
        unit: str | None = None,
        period_start: str | None = None,
        period_kind: str | None = None,
    ) -> dict:
        rows = self.db.execute(
            "SELECT id,payload,hash FROM entries WHERE entity=? AND metric=? AND status='approved' ORDER BY id DESC",
            (entity, metric),
        ).fetchall()
        eligible = []
        for row in rows:
            if digest(row[1].encode()) != row[2]:
                raise AssistantError("evidence_integrity_failed")
            data = json.loads(row[1])
            if (
                (period_end is None or data["period_end"] == period_end)
                and (unit is None or data["unit"] == unit)
                and (period_start is None or data["period_start"] == period_start)
                and (period_kind is None or data["period_kind"] == period_kind)
            ):
                eligible.append((row, data))
        if not eligible:
            raise AssistantError("approved_evidence_absent")
        if len({self._identity(data) for _, data in eligible}) != 1:
            raise AssistantError("evidence_scope_ambiguous")
        row, data = eligible[0]
        return {
            "id": row[0],
            "observation": {**data, "status": "approved"},
            "hash": row[2],
            "status": "approved",
        }
