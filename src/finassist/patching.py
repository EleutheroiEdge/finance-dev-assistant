"""Patch artifacts require explicit hash approval, a clean feature branch and source-bound scope."""

from __future__ import annotations

from .platform_support import read_utf8

import base64
import json
from pathlib import Path
import re
import subprocess

from .config import Config
from .platform_support import executable_modes_supported
from .errors import AssistantError
from .scope import git, git_command, git_environment, resolve
from .security import canonical, check_text, digest, regular_path, write_private


def patch_paths(patch: str, config: Config) -> list[str]:
    check_text(patch, extra_patterns=config.extra_sensitive_patterns)
    if len(patch.encode()) > config.max_packet_bytes:
        raise AssistantError("patch_limit_exceeded")
    paths = []
    remaining_old = remaining_new = 0
    has_hunk = allow_marker = False
    headers, modes = set(), set()

    def complete_section():
        if not paths:
            return
        if remaining_old or remaining_new:
            raise AssistantError("patch_hunk_invalid")
        if headers == {"---", "+++"} and has_hunk:
            return
        if (
            not headers
            and not has_hunk
            and (modes == {"old mode", "new mode"} or modes in ({"new file mode"}, {"deleted file mode"}))
        ):
            return
        raise AssistantError("patch_header_mismatch")

    for line in patch.splitlines():
        if remaining_old or remaining_new:
            if line == "\\ No newline at end of file" and allow_marker:
                allow_marker = False
                continue
            if not line or line[0] not in {" ", "+", "-"}:
                raise AssistantError("patch_hunk_invalid")
            remaining_old -= line[0] in {" ", "-"}
            remaining_new -= line[0] in {" ", "+"}
            if remaining_old < 0 or remaining_new < 0:
                raise AssistantError("patch_hunk_invalid")
            allow_marker = True
            continue
        if line == "\\ No newline at end of file" and allow_marker:
            allow_marker = False
            continue
        allow_marker = False
        if line.startswith("diff --git "):
            complete_section()
            has_hunk = False
            headers, modes = set(), set()
            match = re.fullmatch(r"diff --git a/([^\s]+) b/([^\s]+)", line)
            if not match or match[1] != match[2]:
                raise AssistantError("patch_rename_or_path_invalid")
            name = config.check_path(match[1])
            if not config.allows(name) or config.protected(name):
                raise AssistantError("patch_path_not_approved")
            paths.append(name)
        elif line.startswith("@@ "):
            if not paths or headers != {"---", "+++"}:
                raise AssistantError("patch_header_mismatch")
            match = re.fullmatch(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@(?: .*)?", line)
            if not match:
                raise AssistantError("patch_hunk_invalid")
            remaining_old = int(match[1]) if match[1] is not None else 1
            remaining_new = int(match[2]) if match[2] is not None else 1
            if not (remaining_old or remaining_new):
                raise AssistantError("patch_hunk_invalid")
            has_hunk = True
        elif line.startswith(("new file mode ", "deleted file mode ", "old mode ", "new mode ")):
            if line.split()[-1] not in {"100644", "100755"}:
                raise AssistantError("patch_special_file")
            modes.add(line.rsplit(" ", 1)[0])
        elif line.startswith(("rename ", "copy ", "GIT binary patch", "Binary files ")):
            raise AssistantError("patch_format_not_supported")
        elif line.startswith(("--- ", "+++ ")):
            if not paths or has_hunk or line[:3] in headers:
                raise AssistantError("patch_header_mismatch")
            headers.add(line[:3])
            value = line[4:]
            if value != "/dev/null":
                prefix = "a/" if line.startswith("--- ") else "b/"
                if not value.startswith(prefix) or config.check_path(value[2:]) != paths[-1]:
                    raise AssistantError("patch_header_mismatch")
        elif (
            not re.fullmatch(r"index [0-9a-f]+\.\.[0-9a-f]+(?: 100(?:644|755))?", line)
            or not paths
            or has_hunk
        ):
            raise AssistantError("patch_format_not_supported")
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
                previous_receipt = json.loads(read_utf8(regular_path(prior.with_suffix(".receipt.json"))))
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
    if not executable_modes_supported() and any(
        line.startswith(("old mode ", "new mode ", "new file mode 100755"))
        for line in artifact["patch"].splitlines()
    ):
        raise AssistantError("executable_mode_change_not_supported")
    # Independently compare Git's complete interpretation, including traditional
    # sections and mode-only files, before trusting our scope for backups.
    try:
        result = subprocess.run(
            git_command(repo, "apply", "--numstat", "-z", "-"),
            input=artifact["patch"].encode(),
            capture_output=True,
            check=True,
            env=git_environment(),
            timeout=30,
        )
        parsed_paths = []
        for row in result.stdout.split(b"\0"):
            if not row:
                continue
            added, removed, path = row.split(b"\t", 2)
            if not added.isdigit() or not removed.isdigit():
                raise AssistantError("patch_format_not_supported")
            parsed_paths.append(config.check_path(path.decode()))
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as exc:
        raise AssistantError("patch_invalid") from exc
    if len(parsed_paths) != len(paths) or set(parsed_paths) != set(paths):
        raise AssistantError("patch_scope_mismatch")
    backup, modes = {}, {}
    for name in paths:
        target = regular_path(repo / name)
        if target.exists() and not target.is_file():
            raise AssistantError("patch_target_not_regular")
        backup[name] = base64.b64encode(target.read_bytes()).decode() if target.exists() else None
        modes[name] = target.stat().st_mode & 0o777 if target.exists() else None
    # Git parses the entire patch before any mutation; --check is not an execution hook.
    command = git_command(repo, "apply", "--whitespace=error")
    command[1:1] = ["-c", "core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol"]
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
    backup_data = canonical(
        {
            "head": artifact["head"],
            "before": backup,
            "modes": modes,
            "path_policy": {"denied_parts": config.denied_parts, "text_suffixes": config.text_suffixes},
        }
    )
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


def rollback_patch(repo: Path, patch_hash: str, config: Config | None = None) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", patch_hash):
        raise AssistantError("invalid_patch_hash")
    path = regular_path(repo / ".finassist" / "patches" / (patch_hash + ".json"))
    try:
        saved = json.loads(read_utf8(path))
        receipt = json.loads(read_utf8(path.with_suffix(".receipt.json")))
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
    selected_policy = saved.get("path_policy", {})
    if not isinstance(selected_policy, dict) or set(selected_policy) - {"denied_parts", "text_suffixes"}:
        raise AssistantError("patch_backup_integrity_failed")
    policy = Config(allow_paths=(), protected_paths=(), **selected_policy).validate()
    if config is not None:
        config.validate()
        for name in saved["before"]:
            config.check_path(name)
            if not config.allows(name) or config.protected(name):
                raise AssistantError("rollback_outside_active_policy")
            for encoded in (saved["before"][name],):
                if encoded is not None:
                    check_text(
                        base64.b64decode(encoded, validate=True).decode("utf-8"),
                        extra_patterns=config.extra_sensitive_patterns,
                    )
            target = regular_path(repo / name)
            if target.is_file():
                check_text(target.read_text(encoding="utf-8"), extra_patterns=config.extra_sensitive_patterns)
    for name, expected in receipt["after"].items():
        target = regular_path(repo / policy.check_path(name))
        actual = digest(target.read_bytes()) if target.exists() else None
        mode = target.stat().st_mode & 0o777 if target.exists() else None
        if actual != expected or mode != receipt["after_modes"][name]:
            raise AssistantError("rollback_would_overwrite_later_work")
    for name, before in saved["before"].items():
        target = regular_path(repo / policy.check_path(name))
        if before is None:
            target.unlink(missing_ok=True)
        else:
            write_private(target, base64.b64decode(before, validate=True), replace=True)
            target.chmod(saved["modes"][name])
    receipt["state"] = "rolled_back"
    write_private(path.with_suffix(".receipt.json"), canonical(receipt), replace=True)
    return {"rolled_back": patch_hash, "paths": list(saved["before"])}
