"""Portable text, executable and private-state conventions."""

import os
from pathlib import Path
import shutil

from .errors import AssistantError


def find_tool(name: str) -> str:
    if name not in {"git", "gh", "docker", "podman"}:
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
