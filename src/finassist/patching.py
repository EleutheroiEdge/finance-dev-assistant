"""Patch artifacts require explicit hash approval, a clean feature branch and source-bound scope."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import subprocess

from .config import Config
from .errors import AssistantError
from .scope import git, git_command, git_environment, resolve
from .security import canonical, check_path, check_text, digest, regular_path, write_private


def patch_paths(patch: str, config: Config) -> list[str]:
    check_text(patch, extra_patterns=config.extra_sensitive_patterns)
    if len(patch.encode()) > config.max_packet_bytes:
        raise AssistantError("patch_limit_exceeded")
    paths = []
    in_hunk = False
    headers, modes = set(), set()

    def complete_section():
        if not paths:
            return
        if headers == {"---", "+++"} and in_hunk:
            return
        if (
            not headers
            and not in_hunk
            and (modes == {"old mode", "new mode"} or modes in ({"new file mode"}, {"deleted file mode"}))
        ):
            return
        raise AssistantError("patch_header_mismatch")

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            complete_section()
            in_hunk = False
            headers, modes = set(), set()
            match = re.fullmatch(r"diff --git a/([^\s]+) b/([^\s]+)", line)
            if not match or match[1] != match[2]:
                raise AssistantError("patch_rename_or_path_invalid")
            name = check_path(match[1])
            if not config.allows(name) or config.protected(name):
                raise AssistantError("patch_path_not_approved")
            paths.append(name)
        elif line.startswith("@@ "):
            if not paths or headers != {"---", "+++"}:
                raise AssistantError("patch_header_mismatch")
            in_hunk = True
        elif in_hunk:
            # Removed SQL comments and added prefix operators can resemble file
            # headers. Only Git's actual header section defines target paths.
            continue
        elif line.startswith(("new file mode ", "deleted file mode ", "old mode ", "new mode ")):
            if line.split()[-1] not in {"100644", "100755"}:
                raise AssistantError("patch_special_file")
            modes.add(line.rsplit(" ", 1)[0])
        elif line.startswith(("rename ", "copy ", "GIT binary patch", "Binary files ")):
            raise AssistantError("patch_format_not_supported")
        elif line.startswith(("--- ", "+++ ")):
            if line[:3] in headers:
                raise AssistantError("patch_header_mismatch")
            headers.add(line[:3])
            value = line[4:]
            if value != "/dev/null":
                if not paths or not value.startswith(("a/", "b/")) or check_path(value[2:]) != paths[-1]:
                    raise AssistantError("patch_header_mismatch")
    complete_section()
    if not paths or len(set(paths)) != len(paths):
        raise AssistantError("empty_or_duplicate_patch")
    return paths


def apply_patch_artifact(repo: Path, artifact: dict, approved_hash: str, config: Config) -> dict:
    config.validate()
    if digest(canonical(artifact)) != approved_hash:
        raise AssistantError("patch_approval_mismatch")
    if set(artifact) != {"head", "patch", "summary"} or not all(
        isinstance(v, str) for v in artifact.values()
    ):
        raise AssistantError("patch_artifact_invalid")
    if resolve(repo, "HEAD") != artifact["head"]:
        raise AssistantError("patch_head_changed")
    branch = git(repo, "symbolic-ref", "--short", "HEAD")
    remote_defaults = set()
    for row in git(repo, "for-each-ref", "--format=%(refname) %(symref)", "refs/remotes").splitlines():
        ref, _, target = row.partition(" ")
        if ref.endswith("/HEAD") and target:
            prefix = ref.removesuffix("HEAD")
            if not target.startswith(prefix):
                raise AssistantError("remote_default_invalid")
            remote_defaults.add(target.removeprefix(prefix))
    if config.protected_branch(branch) or branch in remote_defaults:
        raise AssistantError("feature_branch_required")
    if git(repo, "ls-files", "--", ".finassist"):
        raise AssistantError("private_state_tracked")
    if git(repo, "status", "--porcelain", "--untracked-files=normal", "--", ".", ":(exclude).finassist"):
        raise AssistantError("clean_worktree_required")
    prior_patches = regular_path(repo / ".finassist" / "patches")
    if prior_patches.exists():
        for prior in prior_patches.glob("*.json"):
            regular_path(prior)
            if prior.name.endswith(".receipt.json"):
                continue
            try:
                previous_receipt = json.loads(regular_path(prior.with_suffix(".receipt.json")).read_text())
                valid = (
                    isinstance(previous_receipt, dict)
                    and previous_receipt.get("backup_hash") == digest(prior.read_bytes())
                    and previous_receipt.get("patch_hash") == prior.stem
                    and previous_receipt.get("state", "applied") in {"applied", "rolled_back"}
                )
            except (OSError, ValueError):
                valid = False
            if not valid:
                raise AssistantError("incomplete_patch_reconciliation_required")
    paths = patch_paths(artifact["patch"], config)
    backup, modes = {}, {}
    for name in paths:
        target = regular_path(repo / name)
        if target.exists() and not target.is_file():
            raise AssistantError("patch_target_not_regular")
        backup[name] = base64.b64encode(target.read_bytes()).decode() if target.exists() else None
        modes[name] = target.stat().st_mode & 0o777 if target.exists() else None
    # Git parses the entire patch before any mutation; --check is not an execution hook.
    command = git_command(repo, "apply", "--whitespace=error")
    try:
        subprocess.run(
            command + ["--check", "-"],
            input=artifact["patch"].encode(),
            capture_output=True,
            timeout=15,
            env=git_environment(),
            check=True,
        )
    except subprocess.SubprocessError as exc:
        raise AssistantError("patch_does_not_apply") from exc
    backup_path = repo / ".finassist" / "patches" / (approved_hash + ".json")
    backup_data = canonical({"head": artifact["head"], "before": backup, "modes": modes})
    write_private(backup_path, backup_data)
    try:
        subprocess.run(
            command + ["-"],
            input=artifact["patch"].encode(),
            capture_output=True,
            timeout=15,
            env=git_environment(),
            check=True,
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
        "state": "applied",
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
    if receipt.get("state", "applied") != "applied":
        raise AssistantError("patch_not_applied")
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
    receipt["state"] = "rolled_back"
    write_private(path.with_suffix(".receipt.json"), canonical(receipt), replace=True)
    return {"rolled_back": patch_hash, "paths": list(saved["before"])}
