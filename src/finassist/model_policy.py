"""Opt-in model policy from pinned base bytes, independent of v1 checks policy."""

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import re
import unicodedata
from urllib.parse import urlsplit

import jsonschema

from .ci_policy import decode_document, revision
from .config import Config, load_config
from .errors import AssistantError
from .profiles import PROFILES
from .scope import read_entry
from .security import canonical, check_model_path, check_path, check_text, digest

_PATHS = {"type": "array", "maxItems": 128, "uniqueItems": True,
          "items": {"type": "string", "minLength": 1, "maxLength": 512}}
_INT = {"type": "integer", "minimum": 1, "maximum": 2_000_000}
_MONEY = {"type": "number", "minimum": 0, "maximum": 1_000_000}
_PROPERTIES = {
    "enabled": {"const": True},
    "provider": {"enum": ["openai", "anthropic", "google", "compatible", "ollama"]},
    "model": {"type": "string", "minLength": 1, "maxLength": 200},
    "endpoint": {"type": "string", "minLength": 1, "maxLength": 2048},
    "allowed_host": {"type": "string", "pattern": r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$"},
    "api_key_env": {"type": "string", "pattern": r"^[A-Z][A-Z0-9_]{0,127}$"},
    "allow_paths": {**_PATHS, "minItems": 1}, "deny_paths": _PATHS,
    "max_request_bytes": _INT, "max_file_bytes": _INT,
    "max_files": {"type": "integer", "minimum": 1, "maximum": 2000},
    "profile": {"type": "string", "minLength": 1, "maxLength": 64},
    "max_output_tokens": _INT,
    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 300},
    "max_run_usd": _MONEY, "daily_budget_usd": _MONEY,
    "input_usd_per_million": _MONEY, "output_usd_per_million": _MONEY,
    "blocking_severities": {"type": "array", "uniqueItems": True, "maxItems": 5,
                            "items": {"enum": ["critical", "high", "medium", "low", "info"]}},
}
_PROFILE_PROPERTIES = {
    "profile_text": {"type": "array", "minItems": 1, "maxItems": 64,
                     "items": {"type": "string", "minLength": 1, "maxLength": 2000,
                               "pattern": r"^[^\r\n]+$"}},
    "profile_path": {"type": "string", "minLength": 1, "maxLength": 512},
    "profile_sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
}
_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "model_review"],
    "properties": {
        "schema_version": {"type": "integer", "const": 2},
        "model_review": {"type": "object", "additionalProperties": False,
                         "required": list(_PROPERTIES),
                         "properties": {**_PROPERTIES, **_PROFILE_PROPERTIES},
                         "dependentRequired": {"profile_path": ["profile_sha256"],
                                               "profile_sha256": ["profile_path"]},
                         "not": {"required": ["profile_text", "profile_path"]}},
    },
}


@dataclass(frozen=True)
class ModelGatePolicy:
    document: dict
    config: Config
    path: str
    sha256: str
    base: str
    profile_path: str | None = None


def _prefix(value: str) -> str:
    if any(character in value for character in "*?[]"):
        raise AssistantError("gate_policy_path_invalid")
    check_path(value.removesuffix("/"), source_only=False)
    return value


def _profile_lines(lines: list[str]) -> list[str]:
    # JSON Schema's $ permits a trailing newline, and CR/LF checks miss other
    # Unicode line separators and invisible format/control instructions.
    for line in lines:
        if (line.splitlines() != [line] or not line.strip()
                or any(unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}
                       for char in line)):
            raise AssistantError("gate_profile_line_invalid")
    return lines


def _profile(repo: Path, base: str, model: dict) -> tuple[list[str] | None, str | None]:
    """Resolve only policy-owned text; never use a working-tree profile loader."""
    if "profile_text" in model:
        # Config validates every decoded line, including JSON-escaped secrets.
        return _profile_lines(model["profile_text"]), None
    if "profile_path" not in model:
        return None, None
    path = check_model_path(model["profile_path"])
    if any(path.startswith(prefix) if prefix.endswith("/") else path == prefix
           for prefix in model["deny_paths"]):
        raise AssistantError("gate_denied_path")
    raw, _ = read_entry(repo, base, path, 128_000)
    if raw is None:
        raise AssistantError("gate_profile_missing_at_base")
    if digest(raw) != model["profile_sha256"]:
        raise AssistantError("gate_profile_pin_mismatch")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise AssistantError("gate_profile_encoding_invalid") from exc
    check_text(text)
    return _profile_lines([line for line in text.splitlines() if line.strip()]), path


def load_model_policy(repo: Path, base: str, path: str, pin: str) -> ModelGatePolicy:
    revision(base)
    path = check_path(path, source_only=False)
    if not isinstance(pin, str) or re.fullmatch(r"[0-9a-f]{64}", pin) is None:
        raise AssistantError("gate_policy_pin_required")
    raw, _ = read_entry(repo, base, path, 128_000)
    if raw is None:
        raise AssistantError("gate_policy_missing_at_base")
    if digest(raw) != pin:
        raise AssistantError("gate_policy_pin_mismatch")
    document = decode_document(raw, "gate_policy_invalid")
    if document.get("schema_version") == 1:
        raise AssistantError("gate_model_opt_in_required")
    try:
        jsonschema.Draft202012Validator(_SCHEMA).validate(document)
    except jsonschema.ValidationError as exc:
        raise AssistantError("gate_policy_invalid") from exc
    model = document["model_review"]
    if type(document["schema_version"]) is not int or model["enabled"] is not True:
        raise AssistantError("gate_policy_invalid")
    for field, schema in _PROPERTIES.items():
        if schema.get("type") == "integer" and type(model[field]) is not int:
            raise AssistantError("gate_policy_invalid")
    # The only key material accepted by a policy is a variable NAME. All other
    # fields are screened, including unknown fields rejected by the schema.
    check_text(canonical(document).decode())
    for prefix in (*model["allow_paths"], *model["deny_paths"]):
        _prefix(prefix)
    endpoint = urlsplit(model["endpoint"])
    if endpoint.hostname != model["allowed_host"]:
        raise AssistantError("gate_endpoint_host_mismatch")
    if model["provider"] != "ollama" and any(
        model[field] <= 0 for field in ("input_usd_per_million", "output_usd_per_million")
    ):
        raise AssistantError("provider_prices_required")
    config_fields = {key: model[key] for key in (
        "provider", "model", "endpoint", "api_key_env", "profile", "allow_paths",
        "max_file_bytes", "max_output_tokens", "timeout_seconds", "max_run_usd", "daily_budget_usd",
        "input_usd_per_million", "output_usd_per_million", "blocking_severities",
    )}
    config_fields.update(allow_network=True, allowed_hosts=[model["allowed_host"]], generated_paths=[],
                         max_packet_bytes=2_000_000,
                         monthly_budget_usd=1_000_000)
    profile_text, profile_path = _profile(repo, base, model)
    if profile_text is not None:
        profiles = deepcopy(PROFILES)
        profiles[model["profile"]] = profile_text
        config_fields["profiles"] = profiles
    config = load_config(content=canonical(config_fields))
    return ModelGatePolicy(document, config, path, pin, base, profile_path)
