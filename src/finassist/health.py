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


def evidence_status(state_dir: Path, config: Config) -> tuple[dict | None, list[dict]]:
    """Saved check records and workflow plans in the audit ledger bound to another configuration.

    The configuration hash covers every setting with its default, so a default that changes
    between releases changes it too. Evidence recorded before an upgrade that adds settings
    then stops counting, and the warning says what to run again. The ledger is opened
    read-only; nothing is written. Without a ledger there is nothing to report.
    """
    from dataclasses import asdict
    import sqlite3

    from .errors import AssistantError
    from .ledger import Ledger
    from .security import canonical, digest

    path = Path(state_dir) / "audit.sqlite"
    if not path.is_file():
        return None, []
    current = digest(canonical(asdict(config)))
    kinds = {"check_completed": "check_records", "workflow_plan_bound": "workflow_plans"}
    recorded, other = dict.fromkeys(kinds.values(), 0), dict.fromkeys(kinds.values(), 0)
    try:
        with Ledger(path, read_only=True) as ledger:
            after = 0
            while page := ledger.events(after=after, limit=1000):
                for row in page:
                    kind, bound = kinds.get(row["payload"].get("event")), row["payload"].get("config_hash")
                    if kind and isinstance(bound, str):
                        recorded[kind] += 1
                        other[kind] += bound != current
                after = page[-1]["seq"]
    except (AssistantError, sqlite3.Error, OSError) as exc:
        return {"readable": False, "reason": getattr(exc, "code", type(exc).__name__)}, []
    status = {"readable": True, "config_hash": current, "recorded": recorded, "other_configuration": other}
    if not any(other.values()):
        return status, []
    return status, [{"code": "evidence_configuration_changed", **other,
                     "hint": "These no longer count for readiness. Run `finassist check` for each required recipe "
                             "and `finassist review` again, and bind new workflow plans. The hash covers every "
                             "setting with its default, so an upgrade that adds settings changes it too."}]


def doctor_report(config: Config, *, update_check: dict | None = None, config_path: Path | None = None,
                  file_selected: bool = False, state_dir: Path | None = None) -> dict:
    from .updater import update_status

    updates = update_status()
    if update_check is not None:
        updates.update(update_check)
    evidence, stale = evidence_status(state_dir, config) if state_dir is not None else (None, [])
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
        "config_warnings": config_warnings(config, config_path, file_selected=file_selected) + stale,
        **({"evidence": evidence} if evidence is not None else {}),
        "updates": updates,
        "private_state_protection": private_state_protection(),
        "next_step": "inspect a plan packet before enabling any provider or running a recipe",
    }
