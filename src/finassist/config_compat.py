"""Additive configuration compatibility and explicit reversible rename migrations."""

from dataclasses import dataclass
from datetime import datetime, timezone
import difflib
import json
from pathlib import Path
import re
import warnings

from . import installed_version
from .errors import AssistantError
from .security import canonical, check_text, digest, regular_path, write_private


class ConfigCompatibilityError(AssistantError):
    """Fixed code plus bounded option/version hints, never configuration values."""

    def __init__(self, code: str, details: dict):
        super().__init__(code)
        self.public_details = details


def stable_version(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or re.fullmatch(r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})", value) is None:
        raise AssistantError("invalid_min_version")
    return tuple(int(part) for part in value.split("."))


def check_min_version(value: str) -> None:
    if value == "":
        return
    required = stable_version(value)
    current_text = installed_version()
    if stable_version(current_text) < required:
        raise ConfigCompatibilityError("minimum_version_required", {
            "required_version": value, "installed_version": current_text,
            "upgrade_hint": f"Upgrade finledgerpoli to {value} or later before reading this configuration.",
        })


def safe_option_name(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value) is None:
        return "(redacted)"
    try:
        check_text(value)
    except AssistantError:
        return "(redacted)"
    return value


OPTION_INTRODUCED = {"min_version": "0.5.0"}


def unknown_option(name: str) -> ConfigCompatibilityError:
    safe = safe_option_name(name)
    details = {"option": safe, "upgrade_hint": "Upgrade finledgerpoli if this configuration requires a newer release."}
    if safe in OPTION_INTRODUCED:
        details["introduced_in"] = OPTION_INTRODUCED[safe]
    return ConfigCompatibilityError("unknown_config_option", details)


@dataclass(frozen=True)
class DeprecatedOption:
    replacement: str
    deprecated_in: str
    remove_after: str

    def validate(self, old: str) -> None:
        since, until = stable_version(self.deprecated_in), stable_version(self.remove_after)
        if (safe_option_name(old) != old or safe_option_name(self.replacement) != self.replacement
                or old == self.replacement or until[0] != since[0] or until[1] < since[1] + 2):
            raise AssistantError("invalid_deprecation_window")


# No production option is renamed just to exercise this framework. A real rename
# must add a reviewed entry and keep its compatibility window for two minors.
DEPRECATED_OPTIONS: dict[str, DeprecatedOption] = {}


def compatible_document(raw: dict, *, emit_warnings: bool = True) -> tuple[dict, list[dict]]:
    result, deprecated = dict(raw), []
    for old, rule in DEPRECATED_OPTIONS.items():
        rule.validate(old)
        if old not in result:
            continue
        if rule.replacement in result:
            raise AssistantError("deprecated_option_conflict")
        result[rule.replacement] = result.pop(old)
        row = {"option": old, "replacement": rule.replacement, "remove_after": rule.remove_after}
        deprecated.append(row)
        if emit_warnings:
            warnings.warn(f"Configuration option {old} is deprecated; use {rule.replacement}. "
                          f"Supported until at least {rule.remove_after}.", FutureWarning, stacklevel=2)
    return result, deprecated


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise AssistantError("config_duplicate_key")
        result[name] = value
    return result


def decode_config(content: bytes) -> dict:
    try:
        raw = json.loads(content.decode("utf-8"), object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AssistantError("invalid_config") from exc
    if not isinstance(raw, dict):
        raise AssistantError("invalid_config")
    # JSON syntax must be decoded first; the floor precedes schema hints,
    # unknown-key checks, profile-file reads and all option validation.
    check_min_version(raw.get("min_version", ""))
    return raw


@dataclass(frozen=True)
class ConfigMigration:
    path: Path
    before: bytes
    after: bytes
    diff: str

    def report(self) -> dict:
        return {"changed": self.before != self.after, "source_sha256": digest(self.before), "diff": self.diff}


def preview_config_migration(path: Path) -> ConfigMigration:
    from .config import load_config

    path = regular_path(path)
    if path.stat().st_size > 2_000_000:
        raise AssistantError("config_file_too_large")
    before = path.read_bytes()
    raw = decode_config(before)
    normalized, renamed = compatible_document(raw, emit_warnings=False)
    after = canonical(normalized) + b"\n" if renamed else before
    # No values enter diff output until the document passes ordinary validation
    # and mandatory content screening; no network or provider action occurs.
    check_text(before.decode())
    load_config(path, content=after)
    diff = "".join(difflib.unified_diff(before.decode().splitlines(keepends=True), after.decode().splitlines(keepends=True),
                                       fromfile="configuration (before)", tofile="configuration (after)"))
    return ConfigMigration(path, before, after, diff)


def apply_config_migration(plan: ConfigMigration) -> dict:
    path = regular_path(plan.path)
    if path.read_bytes() != plan.before:
        raise AssistantError("config_changed_during_migration")
    if plan.before == plan.after:
        return {**plan.report(), "backup": None, "written": False}
    # Recompute the migration before a write; a hand-built/stale plan cannot
    # supply arbitrary replacement bytes through this safe-migration surface.
    fresh = preview_config_migration(path)
    if fresh.before != plan.before or fresh.after != plan.after:
        raise AssistantError("config_migration_plan_mismatch")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup = path.with_name(path.name + ".backup-" + stamp)
    write_private(backup, plan.before)
    if path.read_bytes() != plan.before:
        raise AssistantError("config_changed_during_migration")
    write_private(path, plan.after, replace=True)
    return {**plan.report(), "backup": str(backup), "written": True}
