"""Concurrent private audit chain and conservative reservation of review spend."""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from datetime import datetime, timezone
from decimal import Decimal
import json
import re
from pathlib import Path
import sqlite3
import uuid

from .errors import AssistantError
from .security import canonical, digest, regular_path

CURRENT_RUN: ContextVar[str | None] = ContextVar("finassist_run", default=None)


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
        if {"recorded_at", "event_schema", "run_id"}.intersection(payload):
            raise AssistantError("audit_reserved_field")
        identifier = CURRENT_RUN.get()
        if identifier is not None and (
            not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier)
        ):
            raise AssistantError("audit_context_invalid")
        lifecycle = {"command_started", "command_completed", "command_failed"}
        if payload.get("event") in lifecycle:
            command = payload.get("command")
            if (
                identifier is None
                or not isinstance(command, str)
                or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", command)
            ):
                raise AssistantError("audit_context_required")
            history = []
            for (value,) in self.db.execute(
                "SELECT payload FROM events WHERE payload LIKE ? ORDER BY seq",
                ('%"run_id":"' + identifier + '"%',),
            ):
                event = json.loads(value)
                if event.get("run_id") == identifier and event.get("event") in lifecycle:
                    history.append((event["event"], event.get("command")))
            if (payload["event"] == "command_started" and history) or (
                payload["event"] != "command_started"
                and (not history or history[-1] != ("command_started", command))
            ):
                raise AssistantError("audit_lifecycle_invalid")
        last = self.db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        previous = last[0] if last else "ROOT"
        metadata = {**payload, "recorded_at": datetime.now(timezone.utc).isoformat(), "event_schema": 1}
        if CURRENT_RUN.get() is not None:
            metadata["run_id"] = CURRENT_RUN.get()
        data = canonical(metadata).decode()
        result = digest(previous.encode() + data.encode())
        self.db.execute("INSERT INTO events(previous,payload,hash) VALUES (?,?,?)", (previous, data, result))
        return result

    def append(self, payload: dict) -> str:
        with self.transaction():
            return self._append(payload)

    def verify(self) -> int:
        # Read event history and balances in one snapshot; concurrent writers
        # cannot create a transient mismatch during verification.
        with nullcontext() if self.db.in_transaction else self.transaction():
            previous, count, balances, runs = "ROOT", 0, {}, {}
            for seq, prior, data, value in self.db.execute(
                "SELECT seq,previous,payload,hash FROM events ORDER BY seq"
            ):
                if seq != count + 1 or prior != previous or digest(prior.encode() + data.encode()) != value:
                    raise AssistantError("audit_integrity_failed")
                try:
                    payload = json.loads(data)
                    if not isinstance(payload, dict):
                        raise ValueError("event must be an object")
                    event = payload.get("event")
                    if event in {"command_started", "command_completed", "command_failed"}:
                        identifier, command = payload.get("run_id"), payload.get("command")
                        if (
                            not isinstance(identifier, str)
                            or not re.fullmatch(r"[0-9a-f]{32}", identifier)
                            or not isinstance(command, str)
                        ):
                            raise ValueError("invalid command identity")
                        if event == "command_started":
                            if identifier in runs:
                                raise ValueError("duplicate command start")
                            runs[identifier] = (command, "started")
                        elif runs.get(identifier) != (command, "started"):
                            raise ValueError("unmatched command completion")
                        else:
                            runs[identifier] = (command, "closed")
                    if payload.get("event") == "reserved":
                        identifier = payload["id"]
                        if identifier in balances:
                            raise ValueError("duplicate reservation")
                        balances[identifier] = (payload["day"], payload["amount"], None, "reserved")
                    elif payload.get("event") == "settled":
                        day, reserved, _, state = balances[payload["id"]]
                        if state != "reserved":
                            raise ValueError("duplicate settlement")
                        balances[payload["id"]] = (day, reserved, payload["actual"], "settled")
                except (ValueError, TypeError, KeyError) as exc:
                    raise AssistantError("audit_integrity_failed") from exc
                previous, count = value, count + 1
            stored = {
                row[0]: tuple(row[1:])
                for row in self.db.execute("SELECT id,day,reserved,actual,state FROM reservations")
            }
            if balances != stored:
                raise AssistantError("audit_integrity_failed")
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

    def events(self, *, after: int = 0, limit: int = 1000) -> list[dict]:
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 10_000:
            raise AssistantError("invalid_audit_page")
        with nullcontext() if self.db.in_transaction else self.transaction():
            self.verify()
            return [
                {"seq": seq, "previous": previous, "payload": json.loads(payload), "hash": value}
                for seq, previous, payload, value in self.db.execute(
                    "SELECT seq,previous,payload,hash FROM events WHERE seq>? ORDER BY seq LIMIT ?",
                    (after, limit),
                )
            ]

    def incomplete_runs(self) -> list[dict]:
        with nullcontext() if self.db.in_transaction else self.transaction():
            self.verify()
            pending = {}
            for (data,) in self.db.execute("SELECT payload FROM events ORDER BY seq"):
                event = json.loads(data)
                identifier = event.get("run_id")
                if identifier and event.get("event") == "command_started":
                    pending[identifier] = {
                        "run_id": identifier,
                        "command": event.get("command"),
                        "started_at": event.get("recorded_at"),
                        "outcome": "unknown",
                    }
                elif identifier and event.get("event") in {"command_completed", "command_failed"}:
                    pending.pop(identifier, None)
            return list(pending.values())
