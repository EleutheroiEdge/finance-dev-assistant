"""Local doctor metadata: no request, key output, filesystem creation or network probe."""

import os
from pathlib import Path
import re
import subprocess
import unicodedata
from urllib.parse import urlsplit

from .config import Config, DEFAULT_ENDPOINTS, DEFAULT_KEYS
from .errors import AssistantError
from .error_hints import error_fields
from .doctor_key_uses import KEY_USES
from .platform_support import find_tool
from .security import check_text, regular_path
from .update_settings import user_directory


def _shown_path(value: str) -> str:
    # Absolute paths are intentional here, unlike repository-relative packet names.
    try:
        if any(unicodedata.category(char) in {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"} for char in value):
            return "[redacted]"
        check_text(value)
    except AssistantError:
        return "[redacted]"
    return value


def key_state(name: str, environment=None) -> str:
    """Inspect only the chosen variable for absence/emptiness; never retain its value."""
    environment = os.environ if environment is None else environment
    if name not in frozenset(iter(environment)):
        return "missing"
    return "set" if environment.get(name) else "empty"


def key_diagnostic(name: str, environment) -> dict:
    state = key_state(name, environment) if name else None
    return {"key_variable": name or None, "key_state": state, "key_variable_set": state in {"set", "empty"}}


def git_status() -> dict:
    from .scope import _supports_no_lazy_fetch, git_environment

    result = {"path": None, "version": None, "features": [], "blockers": [], "warnings": []}
    try:
        executable = find_tool("git")
        result["path"] = _shown_path(executable)
        done = subprocess.run([executable, "--version"], env=git_environment(), stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=10, check=False)
        # Vendor suffixes may differ. Never echo raw stdout/stderr.
        match = re.fullmatch(rb"git version (\d+)\.(\d+)(?:\.(\d+))?[^\r\n]*\r?\n?", done.stdout)
        if done.returncode or not match or len(done.stdout) > 1024:
            raise AssistantError("git_capability_check_failed")
        version = tuple(int(value or b"0") for value in match.groups())
        result["version"] = ".".join(map(str, version))
        for name, minimum, feature in [
            ("init_initial_branch", (2, 28, 0), "evaluate fixture setup"),
            ("attributes_at_revision", (2, 40, 0), "init layout detection"),
        ]:
            available = version >= minimum
            result["features"].append({"name": name, "minimum_version": ".".join(map(str, minimum)),
                                       "available": available, "check": "version", "used_by": feature,
                                       "fallback": None})
            if not available:
                result["warnings"].append({"code": "git_feature_unavailable", "feature": name,
                                           **error_fields("git_feature_unavailable")})
        lazy = _supports_no_lazy_fetch(executable)
        result["features"].append({"name": "no_lazy_fetch", "minimum_version": "2.45.0", "available": lazy,
                                   "check": "probe", "used_by": "offline Git object reads",
                                   "fallback": None if lazy else "Full clones only; partial clones are refused."})
    except (AssistantError, OSError, subprocess.SubprocessError, ValueError) as exc:
        code = (exc.code if isinstance(exc, AssistantError) and exc.code in
                {"git_executable_missing", "batch_tool_not_supported"} else "git_capability_check_failed")
        result["blockers"].append({"code": code, **error_fields(code)})
    return result


def directory_status(path: Path, *, windows: bool | None = None) -> dict:
    """Access estimate only. Never create a probe file or follow user symlinks."""
    windows = os.name == "nt" if windows is None else windows
    report = {"path": None, "exists": False, "writable": None if windows else False,
              "writability_check": ("unknown: Windows ACLs are not checked; no file created" if windows else
                                   "os.access on nearest existing directory; no file created; writes may still fail")}
    try:
        path = regular_path(path)
        report["path"] = _shown_path(str(path))
        report["exists"] = path.exists()
        ancestor = path
        while not ancestor.exists():
            if ancestor.parent == ancestor:
                raise AssistantError("doctor_directory_unusable")
            ancestor = ancestor.parent
        if not ancestor.is_dir():
            raise AssistantError("doctor_directory_unusable")
        if not windows:
            report["writable"] = os.access(ancestor, os.W_OK | os.X_OK)
            if not report["writable"]:
                raise AssistantError("doctor_directory_unusable")
    except (AssistantError, OSError, ValueError, RuntimeError):
        report.update(code="doctor_directory_unusable", **error_fields("doctor_directory_unusable"))
    return report


def _use(config: Config, *, model: dict | None = None, policy: dict | None = None) -> dict:
    host = urlsplit(config.resolved_endpoint).hostname
    gate = model is not None
    limits = ({"max_request_bytes": model["max_request_bytes"], "max_run_usd": model["max_run_usd"],
               "daily_budget_usd": model["daily_budget_usd"], "monthly_budget_usd": config.monthly_budget_usd,
               "monthly_budget_source": "Fixed gate adapter guard, not a configurable policy field."}
              if gate else {"max_packet_bytes": config.max_packet_bytes, "max_request_bytes": None,
                            "request_limit": "Packet limit excludes instructions and protocol envelope.",
                            "max_run_usd": config.max_run_usd, "daily_budget_usd": config.daily_budget_usd,
                            "monthly_budget_usd": config.monthly_budget_usd})
    limits["max_output_tokens"] = config.max_output_tokens
    default_host = urlsplit(DEFAULT_ENDPOINTS.get(config.provider, "")).hostname
    return {
        "source": "gate policy" if gate else "configuration",
        "provider": config.provider, "model": config.model, "host": host,
        "host_permission": ("model_review.allowed_host" if gate else
                            "provider default endpoint" if host == default_host else "allowed_hosts"),
        "network_permission": ("model_review in the policy at base, exact policy hash and gate validation."
                               if gate else "allow_network=true plus command --allow-network and request approval."),
        "network_enabled": True if gate else config.allow_network, "authorization_granted": False,
        **({"policy": policy} if gate else {}),
        "used_by": [row["command"] for row in KEY_USES if row["source"] == ("gate policy" if gate else "configuration")],
        "sends": KEY_USES[0]["sends"],
        "limits": limits,
    }


def key_uses(config: Config | None, *, gate_config=None, gate_model=None, policy=None, environment=None) -> tuple[list, list]:
    environment = os.environ if environment is None else environment
    rows, warnings = {}, []
    for selected, model in [(config, None), (gate_config, gate_model)]:
        if selected is None or selected.provider == "offline":
            continue
        name = selected.key_name
        if not name:
            continue
        if name not in rows:
            rows[name] = {"variable": name, "state": key_state(name, environment), "used_by": [], "uses": []}
        row = rows[name]
        use = _use(selected, model=model, policy=policy)
        row["uses"].append(use)
        row["used_by"] = sorted(set(row["used_by"] + use["used_by"]))
        expected = next((urlsplit(DEFAULT_ENDPOINTS[provider]).hostname
                         for provider, variable in DEFAULT_KEYS.items() if variable == name), None)
        if expected and use["host"] != expected:
            warnings.append({"code": "provider_key_host_mismatch", "variable": name, "host": use["host"],
                             "expected_host": expected, "source": use["source"],
                             **error_fields("provider_key_host_mismatch")})
    return list(rows.values()), warnings


def environment_report(config: Config | None, *, config_path: Path | None = None, state_dir: Path | None = None,
                       gate_config=None, gate_model=None, policy=None, environment=None, route="installation") -> dict:
    """CLI-only local report. Do not place it in packets, the ledger or dashboard health."""
    environment = os.environ if environment is None else environment
    git = git_status()
    paths = {"configuration": {"path": _shown_path(str(Path(config_path).absolute())) if config_path else None,
                               "source": "file" if config_path else "defaults"}}
    paths["state"] = {"path": None, "source": "Not selected by this preflight."}
    if state_dir is not None:
        paths["state"] = directory_status(Path(state_dir))
    for kind in ("config", "cache"):
        try:
            paths["user_" + kind] = directory_status(user_directory(kind))
        except (AssistantError, OSError, ValueError, RuntimeError):
            paths["user_" + kind] = {"path": None, "exists": False, "writable": None, "writability_check": "unavailable",
                                     "code": "doctor_directory_unusable", **error_fields("doctor_directory_unusable")}
    rows, warnings = key_uses(config, gate_config=gate_config, gate_model=gate_model, policy=policy,
                              environment=environment)
    names = frozenset(iter(environment))
    proxies = sorted(names & {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                              "http_proxy", "https_proxy", "all_proxy", "no_proxy"})
    certs = sorted(names & {"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"})
    if proxies:
        warnings.append({"code": "provider_proxy_not_used", "variables": proxies,
                         **error_fields("provider_proxy_not_used")})
    if certs:
        warnings.append({"code": "provider_custom_ca_not_used", "variables": certs,
                         **error_fields("provider_custom_ca_not_used")})
    blockers = list(git["blockers"])
    for role, path in paths.items():
        if "code" in path:
            warnings.append({"code": "doctor_directory_unusable", "path_role": role, **error_fields("doctor_directory_unusable")})
    for row in rows:
        if row["state"] != "set":
            code = "provider_key_empty" if row["state"] == "empty" else "provider_key_missing"
            selected = any(use["source"] == route for use in row["uses"])
            target = blockers if selected else warnings
            target.append({"code": code, "variable": row["variable"], "state": row["state"], **error_fields(code)})
    return {"git": git, "paths": paths, "keys": rows, "blockers": blockers,
            "warnings": [*git["warnings"], *warnings], "network_used": False, "key_values_returned": False,
            "key_value_read": any(row["state"] != "missing" for row in rows),
            "proxy_variables_seen": proxies, "custom_ca_variables_seen": certs,
            "provider_proxy_inheritance": False, "provider_custom_ca_supported": False}


def attach_environment(report: dict, environment: dict) -> None:
    """Apply findings for this selected route before deciding its exit/status."""
    report["environment"] = environment
    report["key_value_read"] |= environment["key_value_read"]
    for kind in ("blockers", "warnings"):
        for entry in environment[kind]:
            if not any(old["code"] == entry["code"] and old.get("variable") == entry.get("variable")
                       and old.get("path_role") == entry.get("path_role") for old in report[kind]):
                report[kind].append(entry)
    if report["blockers"]:
        report["status"] = "blocked"
        report["next_step"] = "Fix every blocker listed, then run this preflight again."
