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
    parts = []
    for part in path.parts:
        if part == ".." and parts and parts[-1] not in {path.anchor, ".."}:
            parts.pop()
        elif part == ".." and path.is_absolute() and parts == [path.anchor]:
            continue
        else:
            parts.append(part)
    path = Path(*parts)
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


def container_environment(backend: str) -> dict[str, str]:
    """Host CLI selectors only. Candidate container variables are literal argv."""
    names = ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SSH_AUTH_SOCK"]
    if backend == "docker":
        names += ["DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"]
    else:
        names += [
            "XDG_DATA_HOME",
            "XDG_CONFIG_HOME",
            "XDG_RUNTIME_DIR",
            "CONTAINER_HOST",
            "CONTAINER_CONNECTION",
            "CONTAINERS_CONF",
            "CONTAINERS_STORAGE_CONF",
        ]
    environment = clean_environment()
    environment.update({name: os.environ[name] for name in names if name in os.environ})
    environment.setdefault("HOME", str(Path.home()))
    if backend == "docker":
        environment.setdefault("DOCKER_CONFIG", str(Path(environment["HOME"]) / ".docker"))
    return environment


def tool_present(name: str) -> bool:
    try:
        find_tool(name)
        return True
    except AssistantError:
        return False
