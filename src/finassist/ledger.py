"""Concurrent private audit chain and conservative reservation of review spend."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import sqlite3
import uuid

from .errors import AssistantError
from .security import canonical, digest, regular_path


class Ledger:
    def __init__(self, path: Path):
        self.path = regular_path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        self.path.chmod(0o600)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY, previous TEXT NOT NULL, payload TEXT NOT NULL, hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS reservations (
                id TEXT PRIMARY KEY, day TEXT NOT NULL, reserved TEXT NOT NULL,
                actual TEXT, state TEXT NOT NULL);
        """)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def _append(self, payload: dict) -> str:
        # Only the caller's reduced metadata belongs here, never prompts or keys.
        last = self.db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        previous = last[0] if last else "ROOT"
        data = canonical(payload).decode()
        result = digest(previous.encode() + data.encode())
        self.db.execute("INSERT INTO events(previous,payload,hash) VALUES (?,?,?)", (previous, data, result))
        return result

    def append(self, payload: dict) -> str:
        with self.transaction():
            return self._append(payload)

    def verify(self) -> int:
        previous, count = "ROOT", 0
        for seq, prior, data, value in self.db.execute(
            "SELECT seq,previous,payload,hash FROM events ORDER BY seq"
        ):
            if seq != count + 1 or prior != previous or digest(prior.encode() + data.encode()) != value:
                raise AssistantError("audit_integrity_failed")
            json.loads(data)
            previous, count = value, count + 1
        return count

    def reserve(self, amount: Decimal, daily_limit: Decimal, run_limit: Decimal) -> str:
        if not amount.is_finite() or amount < 0 or amount > run_limit:
            raise AssistantError("run_budget_exceeded")
        day = datetime.now(timezone.utc).date().isoformat()
        with self.transaction():
            rows = self.db.execute("SELECT reserved,actual,state,day FROM reservations").fetchall()
            # Unreconciled calls remain reserved across date changes.
            used = sum(
                (
                    Decimal(actual if state == "settled" else reserved)
                    for reserved, actual, state, booked in rows
                    if booked == day or state == "reserved"
                ),
                Decimal(0),
            )
            if used + amount > daily_limit:
                raise AssistantError("daily_budget_exceeded")
            identifier = uuid.uuid4().hex
            self.db.execute(
                "INSERT INTO reservations VALUES (?,?,?,NULL,'reserved')", (identifier, day, str(amount))
            )
            self._append({"event": "reserved", "id": identifier, "amount": str(amount), "day": day})
        return identifier

    def settle(self, identifier: str, actual: Decimal) -> None:
        if not actual.is_finite() or actual < 0:
            raise AssistantError("invalid_actual_cost")
        with self.transaction():
            row = self.db.execute("SELECT state FROM reservations WHERE id=?", (identifier,)).fetchone()
            if row is None or row[0] != "reserved":
                raise AssistantError("reservation_not_open")
            self.db.execute(
                "UPDATE reservations SET actual=?,state='settled' WHERE id=?", (str(actual), identifier)
            )
            self._append({"event": "settled", "id": identifier, "actual": str(actual)})

    def open_reservations(self) -> list[dict]:
        return [
            {"id": row[0], "reserved": row[1], "day": row[2]}
            for row in self.db.execute("SELECT id,reserved,day FROM reservations WHERE state='reserved'")
        ]
