"""Non-mutating local capability metadata shared by CLI and dashboard."""

import os
import platform

from . import installed_version
from .config import Config
from .platform_support import tool_present, private_state_protection


def doctor_report(config: Config) -> dict:
    return {
        "version": installed_version(),
        "python": platform.python_version(),
        "platform": platform.system(),
        "provider": config.provider,
        "model_configured": bool(config.model),
        "network_enabled": config.allow_network,
        "key_present": bool(os.environ.get(config.key_name)) if config.key_name else None,
        "docker_binary_present": tool_present("docker"),
        "podman_binary_present": tool_present("podman"),
        "container_daemon_checked": False,
        "recipes": sorted(config.recipes),
        "profile": config.profile,
        "deprecated_config_options": list(getattr(config, "_deprecated_options", ())),
        "private_state_protection": private_state_protection(),
        "next_step": "inspect a plan packet before enabling any provider or running a recipe",
    }
