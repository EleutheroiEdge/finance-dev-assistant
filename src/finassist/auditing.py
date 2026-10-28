"""Metadata-only command lifecycle. No arguments, source, provider output or credentials."""

from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
import re
import time
import uuid

from .config import Config
from .errors import AssistantError, OperationOutcomeUnknown
from .ledger import CURRENT_RUN, Ledger
from .security import canonical, digest


@contextmanager
def command_audit(path: Path, command: str, config: Config):
    identifier = uuid.uuid4().hex
    started = time.monotonic()
    token = CURRENT_RUN.set(identifier)
    outcome = {"exit_code": 0}
    try:
        # Failure here happens before the operation. An unreachable/corrupt audit
        # sink cannot silently turn a mutation into an unaudited success.
        with Ledger(path) as ledger:
            ledger.verify()
            ledger.append(
                {
                    "event": "command_started",
                    "command": command,
                    "config_hash": digest(canonical(asdict(config))),
                }
            )
        try:
            yield outcome
        except BaseException as exc:
            if isinstance(exc, OperationOutcomeUnknown):
                raise
            code = exc.code if isinstance(exc, AssistantError) else "operation_failed"
            if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,80}", code):
                code = "operation_failed"
            with Ledger(path) as ledger:
                ledger.append(
                    {
                        "event": "command_failed",
                        "command": command,
                        "code": code,
                        "duration_ms": int((time.monotonic() - started) * 1000),
                    }
                )
            raise
        else:
            try:
                with Ledger(path) as ledger:
                    ledger.append(
                        {
                            "event": "command_completed",
                            "command": command,
                            "exit_code": outcome["exit_code"],
                            "duration_ms": int((time.monotonic() - started) * 1000),
                        }
                    )
            except Exception as exc:
                # The operation may already have happened. Keep its start event;
                # require reconciliation rather than recommending a blind retry.
                raise AssistantError("operation_finished_audit_completion_failed") from exc
    finally:
        CURRENT_RUN.reset(token)
