"""Narrow first-run output provenance and local state exclusion."""

import json
import os
from pathlib import Path
import stat

from .config import config_document, save_config
from .errors import AssistantError
from .scope import git
from .security import canonical, digest, regular_path, write_private


def _bytes(path: Path, limit: int) -> bytes:
    path = regular_path(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise AssistantError("output_exists")
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise AssistantError("output_exists")
    return value


def save_initial_config(path: Path, config, state: Path, *, remember: bool, replace_initial: bool) -> bool:
    path = regular_path(path)
    receipt = regular_path(state / "setup" / (digest(str(path).encode()) + ".json"))
    replaced = False
    if path.exists():
        if not replace_initial:
            raise AssistantError("output_exists")
        before = _bytes(path, 2_000_000)
        try:
            proof = json.loads(_bytes(receipt, 8192))
        except (OSError, ValueError, AssistantError):
            raise AssistantError("output_exists") from None
        expected = {"schema_version": 1, "created_by": "plain-init", "path": str(path),
                    "sha256": digest(before), "replaceable": True}
        if proof != expected or not path.stat().st_mode & stat.S_IWUSR:
            raise AssistantError("output_exists")
        config.validate()
        # CLI setup has already materialized explicitly selected profiles.
        if config.profile_files:
            raise AssistantError("output_exists")
        after = canonical(config_document(config)) + b"\n"
        backup = receipt.parent / (receipt.stem + "-" + digest(before) + ".before.json")
        if backup.exists():
            if _bytes(backup, 2_000_000) != before:
                raise AssistantError("output_exists")
        else:
            write_private(backup, before)
        # Same optimistic recheck as config migration; keep exact recovery bytes.
        if _bytes(path, 2_000_000) != before:
            raise AssistantError("output_exists")
        write_private(path, after, replace=True)
        write_private(receipt, canonical({**proof, "replaceable": False}) + b"\n", replace=True)
        replaced = True
    else:
        save_config(path, config)
    if remember:
        proof = {"schema_version": 1, "created_by": "plain-init", "path": str(path),
                 "sha256": digest(_bytes(path, 2_000_000)), "replaceable": True}
        write_private(receipt, canonical(proof) + b"\n", replace=receipt.exists())
    return replaced


def local_state_exclude(repo: Path) -> dict:
    """Append one local rule, preserving existing rules; report a manual fallback."""
    report = {"line": ".finassist/", "file": ".git/info/exclude", "added": False}
    try:
        raw = git(repo, "rev-parse", "--git-path", "info/exclude").strip()
        path = Path(raw)
        path = regular_path(path if path.is_absolute() else repo / path)
        before = _bytes(path, 65_536) if path.exists() else b""
        if any(line.strip() in {b".finassist/", b"/.finassist/"} for line in before.splitlines()):
            return {**report, "status": "already_present"}
        path.parent.mkdir(parents=True, exist_ok=True)
        # Append, rather than replacing the file, so unrelated concurrent appends survive.
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "ab") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OSError("not a regular exclude file")
            stream.write((b"" if not before or before.endswith(b"\n") else b"\n") + b".finassist/\n")
            stream.flush()
            os.fsync(stream.fileno())
        return {**report, "added": True, "status": "added"}
    except (AssistantError, OSError, ValueError):
        return {**report, "status": "manual", "instruction": "Add .finassist/ on its own line to .git/info/exclude."}
