"""Inspect the owning installer and run one explicitly requested package upgrade."""

from importlib import metadata, util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from .errors import AssistantError, OperationOutcomeUnknown
from .platform_support import clean_environment
from .update_check import cached_check, check_report
from .update_settings import checks_disabled, update_setting


def installation() -> dict:
    prefix = Path(sys.prefix)
    method, editable, reason = "unknown", False, None
    manager_environment = {}
    try:
        distribution = metadata.distribution("finledgerpoli")
        installer = (distribution.read_text("INSTALLER") or "").strip()
        direct = distribution.read_text("direct_url.json")
        if direct:
            if len(direct) > 16_384:
                raise ValueError("invalid installer metadata")
            editable = json.loads(direct).get("dir_info", {}).get("editable") is True
        # Only inspect marker existence: manager receipts can contain private
        # index settings. Do not parse or project their contents.
        if (prefix / "pipx_metadata.json").exists():
            if prefix.name == "finledgerpoli" and prefix.parent.name == "venvs":
                method = "pipx"
                manager_environment["PIPX_HOME"] = str(prefix.parent.parent)
        elif (prefix / "uv-receipt.toml").exists():
            method = "uv tool" if prefix.name == "finledgerpoli" else "unknown"
            if method == "uv tool":
                manager_environment["UV_TOOL_DIR"] = str(prefix.parent)
        elif installer in {"pip", "uv"}:
            method = "pip"
    except (metadata.PackageNotFoundError, OSError, ValueError, TypeError, AttributeError):
        reason = "installer-metadata-unavailable"
    manager = {"pipx": "pipx", "uv tool": "uv"}.get(method)
    if manager:
        executable = shutil.which(manager)
        argv = [executable or manager, *(["tool"] if method == "uv tool" else []), "upgrade", "finledgerpoli"]
        if (executable is None or not Path(executable).is_absolute()
                or Path(executable).suffix.lower() in {".bat", ".cmd"}):
            reason = "installer-executable-unavailable"
    elif method == "pip":
        argv = [sys.executable, "-I", "-m", "pip", "install", "--upgrade", "finledgerpoli"]
        if util.find_spec("pip") is None:
            reason = "pip-module-unavailable"
    else:
        argv = []
        reason = reason or "installation-method-unknown"
    if editable:
        reason = "editable-install-use-source-workflow"
    if sys.platform == "win32":
        def ps_quote(value):
            return "'" + value.replace("'", "''") + "'"
        command = "".join("$env:" + name + "=" + ps_quote(value) + "; " for name, value in manager_environment.items())
        command += "& " + " ".join(map(ps_quote, argv)) if argv else ""
    else:
        display = (["env", *(name + "=" + value for name, value in manager_environment.items())] if manager_environment else []) + argv
        command = shlex.join(display)
    return {"install_method": method, "editable_install": editable,
            "upgrade_argv": argv, "upgrade_environment": manager_environment, "upgrade_command": command or None,
            "can_upgrade": reason is None, "upgrade_blocked_reason": reason}


def update_status() -> dict:
    try:
        setting = update_setting()
    except (OSError, ValueError, TypeError, AssistantError):
        setting = "invalid"
    return {**check_report(cached_check()), **installation(), "automatic_installs": False,
            "update_check": setting, "checks_disabled_by_environment": checks_disabled()}


def run_upgrade(*, confirmed: bool) -> dict:
    if not confirmed:
        raise AssistantError("upgrade_confirmation_required")
    info = installation()
    if not info["can_upgrade"]:
        raise AssistantError("upgrade_installation_not_supported")
    env = clean_environment()
    names = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME")
    env.update({name: os.environ[name] for name in names if name in os.environ})
    env.update(PIP_NO_INPUT="1", PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_CONFIG_FILE=os.devnull,
               UV_NO_PROGRESS="1", UV_NO_PYTHON_DOWNLOADS="1")
    # Bind a custom manager home to the environment actually running this code,
    # rather than upgrading an unrelated default/user-selected installation.
    env.update(info["upgrade_environment"])
    try:
        result = subprocess.run(info["upgrade_argv"], shell=False, check=False, env=env, timeout=300,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        # Installation may have partially completed. Do not suggest a retry.
        raise OperationOutcomeUnknown("upgrade_outcome_unknown_inspect_installation") from exc
    except OSError as exc:
        raise AssistantError("upgrade_installer_unavailable") from exc
    return {"install_method": info["install_method"], "upgrade_command": info["upgrade_command"],
            "installer_exit_code": result.returncode, "status": "installer-succeeded" if result.returncode == 0 else "installer-failed",
            "restart_required": result.returncode == 0, "automatic_installs": False,
            "configuration_migrated": False, "evidence_migrated": False}
