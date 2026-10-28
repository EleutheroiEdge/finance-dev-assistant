"""Non-mutating local capability metadata shared by CLI and dashboard."""

import os
import platform
import shutil

from . import __version__
from .config import Config


def doctor_report(config: Config) -> dict:
    return {
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.system(),
        "provider": config.provider,
        "model_configured": bool(config.model),
        "network_enabled": config.allow_network,
        "key_present": bool(os.environ.get(config.key_name)) if config.key_name else None,
        "docker_binary_present": bool(shutil.which("docker")),
        "podman_binary_present": bool(shutil.which("podman")),
        "container_daemon_checked": False,
        "recipes": sorted(config.recipes),
        "profile": config.profile,
        "private_state_protection": "POSIX owner-only modes"
        if os.name == "posix"
        else "Windows inherited ACLs: use a private user directory and review access",
        "next_step": "inspect a plan packet before enabling any provider or running a recipe",
    }
