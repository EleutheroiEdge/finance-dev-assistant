"""Patch artifacts require explicit hash approval, a clean feature branch and source-bound scope."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import subprocess

from .config import Config
from .errors import AssistantError
from .scope import git, resolve
from .security import canonical, check_path, check_text, digest, regular_path, write_private


def patch_paths(patch: str, config: Config) -> list[str]:
    check_text(patch, extra_patterns=config.extra_sensitive_patterns)
    if len(patch.encode()) > config.max_packet_bytes:
        raise AssistantError("patch_limit_exceeded")
    paths = []
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            match = re.fullmatch(r"diff --git a/([^\s]+) b/([^\s]+)", line)
            if not match or match[1] != match[2]:
                raise AssistantError("patch_rename_or_path_invalid")
            name = check_path(match[1])
            if not config.allows(name) or config.protected(name):
                raise AssistantError("patch_path_not_approved")
            paths.append(name)
        elif line.startswith(("new file mode ", "deleted file mode ", "old mode ", "new mode ")):
            if line.split()[-1] not in {"100644", "100755"}:
                raise AssistantError("patch_special_file")
        elif line.startswith(("rename ", "copy ", "GIT binary patch", "Binary files ")):
            raise AssistantError("patch_format_not_supported")
        elif line.startswith(("--- ", "+++ ")):
            value = line[4:]
            if value != "/dev/null":
                if not value.startswith(("a/", "b/")) or check_path(value[2:]) not in paths:
                    raise AssistantError("patch_header_mismatch")
    if not paths or len(set(paths)) != len(paths):
        raise AssistantError("empty_or_duplicate_patch")
    return paths


def apply_patch_artifact(repo: Path, artifact: dict, approved_hash: str, config: Config) -> dict:
    if digest(canonical(artifact)) != approved_hash:
        raise AssistantError("patch_approval_mismatch")
    if set(artifact) != {"head", "patch", "summary"} or not all(
        isinstance(v, str) for v in artifact.values()
    ):
        raise AssistantError("patch_artifact_invalid")
    if resolve(repo, "HEAD") != artifact["head"]:
        raise AssistantError("patch_head_changed")
    branch = git(repo, "symbolic-ref", "--short", "HEAD")
    if branch in {"main", "master", "trunk", "production", "release"}:
        raise AssistantError("feature_branch_required")
    if git(repo, "status", "--porcelain", "--untracked-files=normal"):
        raise AssistantError("clean_worktree_required")
    paths = patch_paths(artifact["patch"], config)
    backup, modes = {}, {}
    for name in paths:
        target = regular_path(repo / name)
        if target.exists() and not target.is_file():
            raise AssistantError("patch_target_not_regular")
        backup[name] = base64.b64encode(target.read_bytes()).decode() if target.exists() else None
        modes[name] = target.stat().st_mode & 0o777 if target.exists() else None
    # Git parses the entire patch before any mutation; --check is not an execution hook.
    command = ["git", "-C", str(repo), "apply", "--whitespace=error"]
    try:
        subprocess.run(
            command + ["--check", "-"],
            input=artifact["patch"].encode(),
            capture_output=True,
            timeout=15,
            check=True,
        )
    except subprocess.SubprocessError as exc:
        raise AssistantError("patch_does_not_apply") from exc
    backup_path = repo / ".finassist" / "patches" / (approved_hash + ".json")
    backup_data = canonical({"head": artifact["head"], "before": backup, "modes": modes})
    write_private(backup_path, backup_data)
    try:
        subprocess.run(
            command + ["-"], input=artifact["patch"].encode(), capture_output=True, timeout=15, check=True
        )
    except subprocess.SubprocessError as exc:
        raise AssistantError("patch_apply_failed_inspect_backup") from exc
    after = {name: digest((repo / name).read_bytes()) if (repo / name).exists() else None for name in paths}
    after_modes = {
        name: (repo / name).stat().st_mode & 0o777 if (repo / name).exists() else None for name in paths
    }
    receipt = {
        "head": artifact["head"],
        "patch_hash": approved_hash,
        "after": after,
        "after_modes": after_modes,
        "backup_hash": digest(backup_data),
        "paths": paths,
        "committed": False,
        "tests_executed": False,
    }
    write_private(backup_path.with_suffix(".receipt.json"), canonical(receipt))
    return receipt


def rollback_patch(repo: Path, patch_hash: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", patch_hash):
        raise AssistantError("invalid_patch_hash")
    path = regular_path(repo / ".finassist" / "patches" / (patch_hash + ".json"))
    try:
        saved = json.loads(path.read_text())
        receipt = json.loads(path.with_suffix(".receipt.json").read_text())
    except (OSError, ValueError) as exc:
        raise AssistantError("patch_backup_unavailable") from exc
    if (
        digest(path.read_bytes()) != receipt.get("backup_hash")
        or receipt.get("patch_hash") != patch_hash
        or set(saved["before"]) != set(receipt["after"])
        or set(saved["modes"]) != set(saved["before"])
        or set(receipt["after_modes"]) != set(saved["before"])
    ):
        raise AssistantError("patch_backup_integrity_failed")
    if resolve(repo, "HEAD") != saved["head"]:
        raise AssistantError("rollback_head_changed")
    for name, expected in receipt["after"].items():
        target = regular_path(repo / check_path(name))
        actual = digest(target.read_bytes()) if target.exists() else None
        mode = target.stat().st_mode & 0o777 if target.exists() else None
        if actual != expected or mode != receipt["after_modes"][name]:
            raise AssistantError("rollback_would_overwrite_later_work")
    for name, before in saved["before"].items():
        target = regular_path(repo / check_path(name))
        if before is None:
            target.unlink(missing_ok=True)
        else:
            write_private(target, base64.b64decode(before, validate=True), replace=True)
            target.chmod(saved["modes"][name])
    return {"rolled_back": patch_hash, "paths": list(saved["before"])}
