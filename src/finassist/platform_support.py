"""Portable text, executable and private-state conventions."""

import os
from pathlib import Path
import shutil
import sys

from .errors import AssistantError


def find_tool(name: str) -> str:
    if name not in {"git", "gh", "docker", "podman", "ps"}:
        raise AssistantError("unsupported_tool")
    executable = shutil.which(name)
    if executable is None:
        raise AssistantError(name + "_executable_missing")
    # Batch shims can invoke a command interpreter despite shell=False.
    if Path(executable).suffix.lower() in {".cmd", ".bat"}:
        raise AssistantError("batch_tool_not_supported")
    return executable


def read_utf8(path) -> str:
    """Universal-newline input; source blob hashes still use original Git bytes."""
    with path.open("r", encoding="utf-8", newline=None) as stream:
        return stream.read()


def canonical_system_path(path: Path) -> Path:
    """Accept only macOS's fixed OS aliases, never arbitrary user symlinks."""
    if sys.platform == "darwin" and len(path.parts) > 1 and path.parts[1] in {"var", "tmp", "etc"}:
        alias = Path("/") / path.parts[1]
        expected = Path("/private") / path.parts[1]
        if alias.is_symlink() and alias.resolve() == expected:
            return expected.joinpath(*path.parts[2:])
    return path


def clean_environment() -> dict[str, str]:
    names = ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP")
    result = {name: os.environ[name] for name in names if name in os.environ}
    result.setdefault("PATH", os.defpath)
    result.update(LANG="C.UTF-8", PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    return result


def executable_modes_supported() -> bool:
    return os.name == "posix"


def private_state_protection() -> str:
    return (
        "POSIX owner-only modes"
        if os.name == "posix"
        else "Windows inherited ACLs: use a private user directory and review access"
    )
