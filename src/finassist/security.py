"""Fail-closed input checks. These supplement explicit scope and OS isolation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import stat
import sys

from .errors import AssistantError
from .platform_support import canonical_system_path

DENIED_PARTS = {
    ".finassist",
    ".git",
    ".ssh",
    ".aws",
    ".azure",
    ".env",
    ".venv",
    "node_modules",
    "credentials",
    "secrets",
    "portfolios",
    "holdings",
    "memory",
    "sessions",
    "uploads",
}
DENIED_SUFFIXES = {
    ".csv",
    ".tsv",
    ".parquet",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".xlsx",
    ".xls",
    ".pdf",
    ".png",
    ".jpg",
    ".zip",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
}
TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".txt",
    ".rst",
    ".toml",
    ".json",
    ".yaml",
    ".yml",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".html",
    ".css",
    ".sql",
    ".sh",
    ".rs",
    ".go",
    ".java",
    ".lock",
    ".in",
    ".dockerfile",
}
PUBLIC_ASSETS = {".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".ico"}
# Assignment patterns start only at a whole label-token boundary. A word
# boundary would retry the greedy prefix after every hyphen, causing quadratic
# scans. Keep unbounded prefixes so long labels cannot hide sensitive suffixes.
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
    re.compile(
        r"(?i)(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*(?:api[_-]?key|password|secret|access[_-]?token|gh[_-]?token|github[_-](?:enterprise[_-])?token)\b[\"']?\s*[=:]\s*"
        r"(?:[\"'][^\"'\n]{12,}[\"']|[A-Za-z0-9][A-Za-z0-9_./+=:@-]{11,})"
    ),
    re.compile(
        r"(?i)(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*(?:account[_ -]?(?:number|id)|routing[_ -]?number)[\"']?\s*[=:]\s*[\"']?\d{6,}"
    ),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned_image(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:[A-Za-z0-9][A-Za-z0-9._/:+-]*@)?sha256:[0-9a-f]{64}", value
    ):
        raise AssistantError("pinned_runner_image_required")
    return value


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or ":" in value
        or "\0" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise AssistantError("unsafe_path")
    return str(path)


def check_path(
    value: str,
    *,
    source_only: bool = True,
    metadata_only: bool = False,
    denied_parts=None,
    text_suffixes=None,
) -> str:
    name = safe_relative(value)
    check_text(name)
    parts = PurePosixPath(name).parts
    if parts[-1].lower() in {"auth.json", "user.md", "memory.md", "session.md"}:
        raise AssistantError("private_profile_path")
    denied = DENIED_PARTS if denied_parts is None else denied_parts
    suffixes = TEXT_SUFFIXES if text_suffixes is None else text_suffixes
    if any(
        p.lower() in denied or p.lower().startswith(".env") or p.lower() in {".git", ".finassist"}
        for p in parts
    ):
        raise AssistantError("private_path")
    suffix = PurePosixPath(name).suffix.lower()
    if suffix in DENIED_SUFFIXES and not (metadata_only and suffix in PUBLIC_ASSETS):
        raise AssistantError("private_or_binary_path")
    if (
        source_only
        and suffix not in suffixes
        and parts[-1]
        not in {"LICENSE", "Dockerfile", "Makefile", ".gitignore", ".dockerignore", ".gitattributes"}
    ):
        raise AssistantError("unsupported_file_type")
    return name


_PRIVATE = {"data", "private", "client", "clients", "household", "households",
            "client-config", "client_config", "household-config", "household_config"}


def check_model_path(path: str) -> str:
    """Mandatory model context path screening, including policy-owned profiles."""
    check_path(path)
    if len(path) > 512 or any(part.lower() in _PRIVATE for part in PurePosixPath(path).parts):
        raise AssistantError("gate_private_path")
    name = PurePosixPath(path).name.lower()
    if name in {"client.json", "clients.json", "household.json", "households.json",
                "credentials.json", "credential.json", "secrets.json"} or re.search(
        r"(?:household|client)[_-]?(?:config|settings|profile)", name
    ):
        raise AssistantError("gate_private_path")
    return path



def check_text(text: str, *, extra_patterns: tuple[str, ...] = ()) -> None:
    if "\0" in text:
        raise AssistantError("binary_input")
    if any(p.search(text) for p in SECRET_PATTERNS):
        raise AssistantError("sensitive_content")
    try:
        if any(re.search(p, text, re.IGNORECASE) for p in extra_patterns):
            raise AssistantError("project_content_blocked")
    except re.error as exc:
        raise AssistantError("invalid_content_pattern") from exc


def regular_path(path: Path) -> Path:
    """Reject symlink ancestors before resolving, including not-yet-created files."""
    path = Path(path).expanduser().absolute()
    # Inspect raw ancestors before collapsing .., including older Python builds
    # without Path.is_junction(). Only fixed, verified Darwin OS aliases qualify.
    for item in (path, *path.parents):
        try:
            attributes = getattr(item.lstat(), "st_file_attributes", 0)
        except FileNotFoundError:
            attributes = 0
        if (item.is_symlink() or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT) and canonical_system_path(
            item
        ) == item:
            raise AssistantError("linked_path")
        if item.is_symlink():
            if not (
                sys.platform == "darwin"
                and len(item.parts) == 2
                and item.name in {"var", "tmp", "etc"}
                and canonical_system_path(item) != item
            ):
                raise AssistantError("linked_path")
        elif attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise AssistantError("linked_path")
    return canonical_system_path(path)


def write_private(path: Path, data: bytes, *, replace: bool = False) -> None:
    path = regular_path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and not replace:
        raise AssistantError("output_exists")
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            readonly_mode = None
            if sys.platform == "win32" and path.exists() and not path.stat().st_mode & stat.S_IWRITE:
                readonly_mode = path.stat().st_mode
                path.chmod(readonly_mode | stat.S_IWRITE)
            try:
                Path(name).replace(path)
            finally:
                if readonly_mode is not None and path.exists():
                    path.chmod(readonly_mode)
        else:
            # An exclusive hard-link prevents silently overwriting concurrent output.
            try:
                path.hardlink_to(Path(name))
            except FileExistsError as exc:
                raise AssistantError("output_exists") from exc
    finally:
        Path(name).unlink(missing_ok=True)
