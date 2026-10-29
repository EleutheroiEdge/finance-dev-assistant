"""Replayable workflow checkpoints in the existing private audit ledger."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re

from .errors import AssistantError
from .ledger import Ledger
from .platform_support import read_utf8
from .security import canonical, digest, regular_path, write_private

_BASE = {"event", "workflow_schema", "workflow_run_id"}
_FIELDS = {
    "workflow_run_created": {"execution_hash", "plan_hash", "head", "backend", "steps"},
    "workflow_step_started": {"step_id", "attempt_id", "operation_id", "snapshot_hash"},
    "workflow_step_result": {"step_id", "attempt_id", "state", "artifact_hash", "receipt_hash", "cleanup_verified"},
    "workflow_step_unknown": {"step_id", "attempt_id"},
    "workflow_step_reconciled": {
        "step_id", "attempt_id", "state", "artifact_hash", "receipt_hash", "cleanup_verified", "resolution",
    },
    "workflow_step_retry": {"step_id", "attempt_id"},
    "workflow_run_cancelled": set(),
}
_METADATA = {"recorded_at", "event_schema", "run_id"}
_OPEN_PHASES = {"pending", "running", "unknown", "failed"}
MAX_WORKFLOW_ARTIFACT_BYTES = 4_000_000


def _matches(value, pattern: str) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def run_identifier(value: str) -> str:
    if not _matches(value, r"[0-9a-f]{32}"):
        raise AssistantError("workflow_run_identifier_invalid")
    return value


def operation_identifier(run_id: str, step_id: str) -> str:
    return digest(canonical({"workflow_run_id": run_id, "step_id": step_id}))


def run_phase(run: dict) -> str:
    states = {step["state"] for step in run["steps"].values()}
    if run["cancelled"]:
        return "cancelled"
    for state in ("running", "unknown", "failed"):
        if state in states:
            return state
    return "completed-checks" if states == {"succeeded"} else "pending"


def replay_workflows(events: list[tuple[int, dict]]) -> dict[str, dict]:
    """Reject impossible transitions even if the enclosing hash chain is intact."""
    runs, used_attempts = {}, set()
    for sequence, payload in events:
        event = payload.get("event")
        if not isinstance(event, str) or not event.startswith(("workflow_run_", "workflow_step_")):
            continue
        if event not in _FIELDS:
            raise AssistantError("workflow_state_invalid")
        row = {key: value for key, value in payload.items() if key not in _METADATA}
        if (
            set(row) != _BASE | _FIELDS[event]
            or type(row["workflow_schema"]) is not int or row["workflow_schema"] != 1
            or not _matches(row["workflow_run_id"], r"[0-9a-f]{32}")
        ):
            raise AssistantError("workflow_state_invalid")
        identifier = row["workflow_run_id"]
        if event == "workflow_run_created":
            steps = row["steps"]
            if (
                identifier in runs or not _matches(row["execution_hash"], r"[0-9a-f]{64}")
                or not _matches(row["plan_hash"], r"[0-9a-f]{64}")
                or not _matches(row["head"], r"[0-9a-f]{40}|[0-9a-f]{64}")
                or row["backend"] not in {"local", "docker", "podman"}
                or not isinstance(steps, list) or not 1 <= len(steps) <= 64
                or any(
                    not isinstance(step, dict) or set(step) != {"id", "depends_on"}
                    or not _matches(step["id"], r"[a-z][a-z0-9_-]{0,63}")
                    or not isinstance(step["depends_on"], list) or len(step["depends_on"]) > 64
                    or any(not _matches(dep, r"[a-z][a-z0-9_-]{0,63}") for dep in step["depends_on"])
                    or len(set(step["depends_on"])) != len(step["depends_on"])
                    for step in steps
                )
            ):
                raise AssistantError("workflow_state_invalid")
            if any(run["plan_hash"] == row["plan_hash"] and run_phase(run) in _OPEN_PHASES
                   for run in runs.values()):
                raise AssistantError("workflow_plan_run_unfinished")
            names = {step["id"] for step in steps}
            if len(names) != len(steps) or any(not set(step["depends_on"]) <= names for step in steps):
                raise AssistantError("workflow_state_invalid")
            visited = set()
            while visited != names:
                eligible = {step["id"] for step in steps if set(step["depends_on"]) <= visited} - visited
                if not eligible:
                    raise AssistantError("workflow_state_invalid")
                visited |= eligible
            runs[identifier] = {
                "workflow_run_id": identifier, "execution_hash": row["execution_hash"],
                "plan_hash": row["plan_hash"], "head": row["head"], "backend": row["backend"],
                "cancelled": False, "sequence": sequence,
                "steps": {step["id"]: {
                    "depends_on": step["depends_on"], "state": "pending", "attempt_id": None,
                    "snapshot_hash": None, "artifact_hash": None, "receipt_hash": None,
                    "cleanup_verified": False, "started_at": None,
                } for step in steps},
            }
            continue
        run = runs.get(identifier)
        if run is None or run["cancelled"]:
            raise AssistantError("workflow_state_invalid")
        if event == "workflow_run_cancelled":
            if run_phase(run) not in {"pending", "failed"}:
                raise AssistantError("workflow_state_invalid")
            run["cancelled"] = True
        else:
            step = run["steps"].get(row["step_id"]) if isinstance(row["step_id"], str) else None
            if step is None or not _matches(row["attempt_id"], r"[0-9a-f]{32}"):
                raise AssistantError("workflow_state_invalid")
            if event == "workflow_step_started":
                if (
                    step["state"] != "pending" or row["attempt_id"] in used_attempts
                    or run_phase(run) != "pending"
                    or any(run["steps"][dep]["state"] != "succeeded" for dep in step["depends_on"])
                    or row["operation_id"] != operation_identifier(identifier, row["step_id"])
                    or not _matches(row["snapshot_hash"], r"[0-9a-f]{64}")
                ):
                    raise AssistantError("workflow_state_invalid")
                used_attempts.add(row["attempt_id"])
                step.update(state="running", attempt_id=row["attempt_id"], snapshot_hash=row["snapshot_hash"],
                            artifact_hash=None, receipt_hash=None, cleanup_verified=False,
                            started_at=payload.get("recorded_at"))
            else:
                if row["attempt_id"] != step["attempt_id"]:
                    raise AssistantError("workflow_state_invalid")
                if event == "workflow_step_unknown":
                    if step["state"] != "running":
                        raise AssistantError("workflow_state_invalid")
                    step["state"] = "unknown"
                elif event == "workflow_step_retry":
                    if step["state"] != "failed" or not step["cleanup_verified"]:
                        raise AssistantError("workflow_state_invalid")
                    step.update(state="pending", artifact_hash=None, receipt_hash=None)
                else:
                    expected = "running" if event == "workflow_step_result" else "unknown"
                    if (
                        step["state"] != expected or row["state"] not in {"succeeded", "failed", "unknown"}
                        or type(row["cleanup_verified"]) is not bool
                        or (row["state"] == "unknown") == row["cleanup_verified"]
                    ):
                        raise AssistantError("workflow_state_invalid")
                    if event == "workflow_step_reconciled" and (
                        row["state"] == "unknown" or row["resolution"] not in {"artifact", "cleanup"}
                    ):
                        raise AssistantError("workflow_state_invalid")
                    cleanup_only = row.get("resolution") == "cleanup"
                    if cleanup_only:
                        if row["state"] != "failed" or row["artifact_hash"] is not None or row["receipt_hash"] is not None:
                            raise AssistantError("workflow_state_invalid")
                    elif any(not _matches(row[key], r"[0-9a-f]{64}") for key in ("artifact_hash", "receipt_hash")):
                        raise AssistantError("workflow_state_invalid")
                    step.update({key: row[key] for key in ("state", "artifact_hash", "receipt_hash", "cleanup_verified")})
        run["sequence"] = sequence
    return runs


def unfinished_workflows(events: list[tuple[int, dict]]) -> list[dict]:
    return [
        {"workflow_run_id": identifier, "status": run_phase(run), "plan_hash": run["plan_hash"]}
        for identifier, run in replay_workflows(events).items()
        if run_phase(run) in _OPEN_PHASES
    ]


@contextmanager
def workflow_lock(state_dir: Path, identifier: str):
    """A process-held lock has no timeout that can expire underneath live work."""
    run_identifier(identifier)
    path = regular_path(state_dir / "workflow-locks" / (identifier + ".lock"))
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    # An unbuffered seed cannot retry a rejected Windows locked-byte write
    # during close and mask the classified workflow_run_busy error.
    with os.fdopen(fd, "r+b", buffering=0) as stream:
        try:
            if stream.seek(0, os.SEEK_END) == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise AssistantError("workflow_run_busy") from exc
        # Closing the handle releases the lock, including on exception/process exit.
        # Keep the file: unlinking it could allow a second independently locked inode.
        yield


def _read_document(path: Path, limit: int = MAX_WORKFLOW_ARTIFACT_BYTES) -> dict:
    file = regular_path(path)
    if not file.is_file() or file.stat().st_size > limit:
        raise AssistantError("workflow_artifact_missing_or_changed")
    value = json.loads(read_utf8(file))
    if not isinstance(value, dict):
        raise AssistantError("workflow_artifact_missing_or_changed")
    return value


class WorkflowStore:
    def __init__(self, state_dir: Path, *, create: bool = False):
        self.root = regular_path(state_dir)
        if not create and not (self.root / "audit.sqlite").is_file():
            raise AssistantError("workflow_run_unknown")
        self.ledger = Ledger(self.root / "audit.sqlite")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.ledger.db.close()

    def events(self) -> list[tuple[int, dict]]:
        return [(seq, json.loads(payload)) for seq, payload in self.ledger.db.execute(
            "SELECT seq,payload FROM events ORDER BY seq"
        )]

    def states(self) -> dict[str, dict]:
        with self.ledger.transaction():
            self.ledger.verify()
            return replay_workflows(self.events())

    def record(self, event: str, identifier: str, **values) -> None:
        row = {"event": event, "workflow_schema": 1, "workflow_run_id": run_identifier(identifier), **values}
        with self.ledger.transaction():
            self.ledger.verify()
            events = self.events()
            replay_workflows([*events, (events[-1][0] + 1 if events else 1, row)])
            self.ledger._append(row)

    def run_directory(self, identifier: str) -> Path:
        return regular_path(self.root / "workflow-runs" / run_identifier(identifier))

    def create(self, descriptor: dict, plan: dict, packet: dict) -> None:
        identifier = run_identifier(descriptor["workflow_run_id"])
        if any(state["plan_hash"] == plan["plan_hash"] and run_phase(state) in _OPEN_PHASES
               for state in self.states().values()):
            raise AssistantError("workflow_plan_run_unfinished")
        directory = self.run_directory(identifier)
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        for name, value in (("run", descriptor), ("plan", plan), ("packet", packet)):
            write_private(directory / (name + ".json"), canonical(value) + b"\n")
        self.record(
            "workflow_run_created", identifier, execution_hash=digest(canonical(descriptor)),
            plan_hash=plan["plan_hash"], head=plan["head"], backend=descriptor["backend"],
            steps=[{"id": item["id"], "depends_on": item["depends_on"]} for item in plan["template"]["steps"]],
        )

    def load(self, identifier: str) -> tuple[dict, dict, dict, dict]:
        state = self.states().get(run_identifier(identifier))
        if state is None:
            raise AssistantError("workflow_run_unknown")
        directory = self.run_directory(identifier)
        descriptor, plan, packet = (_read_document(directory / (name + ".json")) for name in ("run", "plan", "packet"))
        if (
            set(descriptor) != {"schema_version", "workflow_run_id", "plan_hash", "packet_hash", "config_hash",
                                "head", "backend", "plan_document_hash", "packet_document_hash"}
            or type(descriptor.get("schema_version")) is not int or descriptor["schema_version"] != 1
            or descriptor["workflow_run_id"] != identifier
            or digest(canonical(descriptor)) != state["execution_hash"]
            or descriptor["plan_document_hash"] != digest(canonical(plan))
            or descriptor["packet_document_hash"] != digest(canonical(packet))
            or plan.get("schema_version") != 1 or plan.get("plan_hash") != state["plan_hash"]
            or any(descriptor[key] != plan.get(key) for key in ("plan_hash", "packet_hash", "config_hash", "head"))
            or descriptor["head"] != state["head"] or descriptor["backend"] != state["backend"]
        ):
            raise AssistantError("workflow_artifact_missing_or_changed")
        return state, descriptor, plan, packet

    def artifact_path(self, identifier: str, attempt_id: str) -> Path:
        run_identifier(attempt_id)
        return regular_path(self.run_directory(identifier) / "attempts" / (attempt_id + ".json"))

    def artifact(self, identifier: str, attempt_id: str) -> tuple[dict, str]:
        document = _read_document(self.artifact_path(identifier, attempt_id))
        return document, digest(canonical(document))

    def commit_result(self, identifier: str, step_id: str, attempt_id: str, document: dict,
                      *, reconciliation: bool = False) -> None:
        receipt = document["receipt"]
        status = "unknown" if not receipt["cleanup_verified"] else "succeeded" if receipt["passed"] else "failed"
        row = {
            "event": "workflow_step_reconciled" if reconciliation else "workflow_step_result",
            "workflow_schema": 1, "workflow_run_id": identifier, "step_id": step_id, "attempt_id": attempt_id,
            "state": status, "artifact_hash": digest(canonical(document)),
            "receipt_hash": digest(canonical(receipt)), "cleanup_verified": receipt["cleanup_verified"],
            **({"resolution": "artifact"} if reconciliation else {}),
        }
        with self.ledger.transaction():
            self.ledger.verify()
            events = self.events()
            states = replay_workflows([*events, (events[-1][0] + 1, row)])
            started_at = states[identifier]["steps"][step_id]["started_at"]
            if not isinstance(started_at, str):
                raise AssistantError("workflow_state_invalid")
            self.ledger._append({
                "event": "check_completed", "head": receipt["head"], "config_hash": receipt["config_hash"],
                "receipt_hash": row["receipt_hash"], "recipe": receipt["recipe"], "passed": receipt["passed"],
                "workflow_run_id": identifier, "step_id": step_id, "attempt_id": attempt_id,
                # Reconciliation must not restart the original evidence-age clock.
                "evidence_recorded_at": started_at,
            })
            self.ledger._append(row)
