"""Local doctor metadata: no request, key output, filesystem creation or network probe."""

import os
from pathlib import Path
import re
import subprocess
import unicodedata
from urllib.parse import urlsplit

from .config import Config, DEFAULT_ENDPOINTS, DEFAULT_KEYS
from .errors import AssistantError
from .platform_support import find_tool
from .security import check_text, regular_path
from .update_settings import user_directory


def _shown_path(value: str) -> str:
    # Absolute paths are intentional here, unlike repository-relative packet names.
    try:
        if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
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
    return {"key_variable": name or None, "key_state": state, "key_variable_set": state == "set"}


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
        for name, minimum, feature, hint in [
            ("init_initial_branch", (2, 28, 0), "evaluate fixture setup",
             "Upgrade Git to 2.28 or later before building evaluation fixtures."),
            ("attributes_at_revision", (2, 40, 0), "init layout detection",
             "Upgrade Git to 2.40 or later, or set generated_paths explicitly."),
        ]:
            available = version >= minimum
            result["features"].append({"name": name, "minimum_version": ".".join(map(str, minimum)),
                                       "available_by_version": available, "used_by": feature})
            if not available:
                result["warnings"].append({"code": "git_feature_unavailable", "feature": name, "hint": hint})
        lazy = _supports_no_lazy_fetch(executable)  # Backports count; use the actual offline guard's probe.
        result["features"].append({"name": "no_lazy_fetch", "minimum_version": "2.45.0", "available": lazy,
                                   "fallback": None if lazy else "Full clones only; partial clones are refused."})
    except (AssistantError, OSError, subprocess.SubprocessError, ValueError) as exc:
        result["blockers"].append({"code": "git_executable_missing" if isinstance(exc, AssistantError) and exc.code == "git_executable_missing"
                                  else "git_capability_check_failed", "hint": "Install a native Git executable on an absolute PATH "
                                  "entry, then run doctor again. No batch shim or network fetch is used."})
    return result


def directory_status(path: Path) -> dict:
    """Access estimate only. Do not create even a probe file, and do not follow links."""
    report = {"path": _shown_path(str(path.absolute())), "exists": False, "writable": False,
              "writability_check": "metadata and os.access; no file created, ACLs/mounts may still refuse writes"}
    try:
        path = regular_path(path)
        report["exists"] = path.exists()
        ancestor = path
        while not ancestor.exists():
            ancestor = ancestor.parent
        if not ancestor.is_dir():
            raise AssistantError("doctor_directory_unusable")
        # Mode bits also catch read-only POSIX directories when tests run as root.
        mode_writable = os.name != "posix" or bool(ancestor.stat().st_mode & 0o222)
        report["writable"] = mode_writable and os.access(ancestor, os.W_OK | os.X_OK)
        if not report["writable"]:
            raise AssistantError("doctor_directory_unusable")
    except (AssistantError, OSError, ValueError):
        report.update(code="doctor_directory_unusable",
                      hint="Choose a private writable directory without symlinks; check its permissions and parent.")
    return report


def _use(config: Config, *, model: dict | None = None, policy: dict | None = None) -> dict:
    host = urlsplit(config.resolved_endpoint).hostname
    gate = model is not None
    limits = ({"max_request_bytes": model["max_request_bytes"], "max_run_usd": model["max_run_usd"],
               "daily_budget_usd": model["daily_budget_usd"], "monthly_budget_usd": None,
               "monthly_budget": "No policy monthly limit; gate uses its per-run and per-day reservations."}
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
        "used_by": ["gate run"] if gate else ["review", "propose", "evaluate"],
        "sends": "Screened packet and instructions, with the required response schema; the key authenticates "
                 "only this request. No other local files or environment values.",
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
                             "hint": "Confirm this service should receive that key; prefer a dedicated key variable "
                                     "and explicit host approval. This warning does not authorize sending it."})
    return list(rows.values()), warnings


def environment_report(config: Config | None, *, config_path: Path | None = None, state_dir: Path | None = None,
                       gate_config=None, gate_model=None, policy=None, environment=None) -> dict:
    """CLI-only local report. Do not place it in packets, the ledger or dashboard health."""
    environment = os.environ if environment is None else environment
    git = git_status()
    paths = {"configuration": {"path": _shown_path(str(Path(config_path).absolute())) if config_path else None,
                               "source": "file" if config_path else "defaults"}}
    paths["state"] = {"path": None, "source": "Not selected by this preflight; gate run requires --state-dir."}
    if state_dir is not None:
        paths["state"] = directory_status(Path(state_dir))
    for kind in ("config", "cache"):
        try:
            paths["user_" + kind] = directory_status(user_directory(kind))
        except (AssistantError, OSError, ValueError):
            paths["user_" + kind] = {"path": None, "writable": False, "code": "doctor_directory_unusable",
                                     "hint": "Set an absolute private user directory with no symlink components."}
    rows, warnings = key_uses(config, gate_config=gate_config, gate_model=gate_model, policy=policy,
                              environment=environment)
    names = frozenset(iter(environment))
    proxies = sorted(names & {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                              "http_proxy", "https_proxy", "all_proxy", "no_proxy"})
    certs = sorted(names & {"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"})
    if proxies:
        warnings.append({"code": "provider_proxy_not_used", "variables": proxies,
                         "hint": "Provider requests do not inherit proxies. Use a directly reachable approved endpoint; "
                                 "remove unused proxy variables to clear this warning."})
    if certs:
        warnings.append({"code": "provider_custom_ca_not_used", "variables": certs,
                         "hint": "Provider transport does not support these custom CA settings. Use a certificate "
                                 "trusted by its default CA bundle; remove unused variables to clear this warning."})
    blockers = list(git["blockers"])
    for role, path in paths.items():
        if "code" in path:
            blockers.append({"code": "doctor_directory_unusable", "path_role": role, "hint": path["hint"]})
    for row in rows:
        if row["state"] != "set":
            blockers.append({"code": "provider_key_missing", "variable": row["variable"], "state": row["state"],
                             "hint": "Set this variable to a non-empty provider key in your process environment; "
                                     "never put the value in configuration or share this value."})
    return {"git": git, "paths": paths, "keys": rows, "blockers": blockers,
            "warnings": [*git["warnings"], *warnings], "network_used": False, "key_values_returned": False,
            "proxy_variables_seen": proxies, "custom_ca_variables_seen": certs,
            "provider_proxy_inheritance": False, "provider_custom_ca_supported": False}
