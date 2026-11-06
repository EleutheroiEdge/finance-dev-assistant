"""Non-mutating local capability metadata shared by CLI and dashboard."""

import os
from pathlib import Path
import platform

from . import installed_version
from .config import Config
from .platform_support import tool_present, private_state_protection


def config_warnings(config: Config, config_path: Path | None = None, *, file_selected: bool = False) -> list[dict]:
    """Settings that have no effect or block later steps, each with what to do instead.

    file_selected means a configuration file was chosen, even if it then failed to
    load; only a run that never chose a file is told to pass one.
    """
    from .security import DENIED_SUFFIXES, TEXT_FIXTURE_SUFFIXES

    warnings = []
    if config_path is None and not file_selected and Path("finassist.json").is_file():
        warnings.append({"code": "config_file_not_loaded",
                         "hint": "Defaults are reported. Pass --config finassist.json to check that file."})
    for suffix in sorted(set(config.text_suffixes) & DENIED_SUFFIXES):
        remedy = ("Admit synthetic fixtures with fixture_roots in a gate policy."
                  if suffix in TEXT_FIXTURE_SUFFIXES else
                  "This format can't be admitted as a fixture either; remove it from text_suffixes.")
        warnings.append({"code": "text_suffix_always_denied", "suffix": suffix,
                         "hint": "Files with this suffix are always refused, so listing it has no effect. " + remedy})
    prices = {"input_usd_per_million": config.input_usd_per_million,
              "output_usd_per_million": config.output_usd_per_million}
    if config.provider not in {"offline", "ollama"} and any(value <= 0 for value in prices.values()):
        warnings.append({"code": "provider_prices_missing",
                         "missing": sorted(name for name, value in prices.items() if value <= 0),
                         "hint": "Reviews are refused until both prices are set, in US dollars per million tokens."})
    return warnings


def doctor_report(config: Config, *, update_check: dict | None = None, config_path: Path | None = None,
                  file_selected: bool = False) -> dict:
    from .updater import update_status

    updates = update_status()
    if update_check is not None:
        updates.update(update_check)
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
        "config_source": "defaults" if config_path is None else "file",
        "config_warnings": config_warnings(config, config_path, file_selected=file_selected),
        "updates": updates,
        "private_state_protection": private_state_protection(),
        "next_step": "inspect a plan packet before enabling any provider or running a recipe",
    }
