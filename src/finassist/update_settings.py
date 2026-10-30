"""Small user-level update preferences, separate from reviewed project configuration."""

import json
import os
from pathlib import Path
import sys

from .errors import AssistantError
from .security import regular_path


def user_directory(kind: str) -> Path:
    if kind not in {"config", "cache"}:
        raise AssistantError("invalid_user_directory_kind")
    if sys.platform == "win32":
        variable = "APPDATA" if kind == "config" else "LOCALAPPDATA"
        base = Path(os.environ.get(variable) or Path.home() / "AppData" / ("Roaming" if kind == "config" else "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / ("Application Support" if kind == "config" else "Caches")
    else:
        base = Path(os.environ.get("XDG_" + kind.upper() + "_HOME") or Path.home() / ("." + kind))
    if not base.is_absolute():
        raise AssistantError("user_directory_must_be_absolute")
    return regular_path(base / "finledgerpoli")


def update_setting() -> str:
    path = user_directory("config") / "settings.json"
    if not path.exists():
        return "off"
    path = regular_path(path)
    if not path.is_file() or path.stat().st_size > 16_384:
        raise AssistantError("invalid_update_settings")
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate update preference")
                result[key] = value
            return result

        value = json.loads(path.read_bytes(), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AssistantError("invalid_update_settings") from exc
    if (not isinstance(value, dict) or set(value) - {"update_check"}
            or not isinstance(value.get("update_check", "off"), str)
            or value.get("update_check", "off") not in {"off", "notify"}):
        raise AssistantError("invalid_update_settings")
    return value.get("update_check", "off")


def checks_disabled() -> bool:
    # Presence is deliberately sufficient, including an empty assignment.
    return "FINASSIST_NO_UPDATE_CHECK" in os.environ
