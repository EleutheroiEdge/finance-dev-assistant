"""Opt-in model policy from pinned base bytes, independent of v1 checks policy."""

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import re
import unicodedata
from urllib.parse import urlsplit

import jsonschema

from .ci_policy import decode_document, revision
from .config import MAX_PACKET_BYTES, Config
from .errors import AssistantError, prices_required
from .policy_fixtures import FIXTURE_PROPERTIES, fixture_settings, load_policy_config
from .profiles import PROFILES
from .scope import read_entry
from .security import canonical, check_model_path, check_path, check_text, digest, safe_relative

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
    "max_request_bytes": {**_INT, "maximum": MAX_PACKET_BYTES}, "max_file_bytes": _INT,
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
_TOKEN_PROPERTIES = {
    "forbidden_token_file": {"type": "string", "minLength": 1, "maxLength": 4096},
    "forbidden_token_hashes": {"type": "array", "minItems": 1, "maxItems": 1024, "uniqueItems": True,
                              "items": {"type": "string", "pattern": r"^[0-9a-f]{64}$"}},
}
# Optional. refuse (the default) keeps today's behaviour; skip-and-report withholds private paths.
_COVERAGE_PROPERTIES = {"private_paths": {"enum": ["refuse", "skip-and-report"]},
                        "related_context": {"enum": ["none", "related"]},
                        "related_max_bytes": {"type": "integer", "minimum": 1, "maximum": 400_000}}
_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "model_review"],
    "properties": {
        "schema_version": {"type": "integer", "const": 2},
        "model_review": {"type": "object", "additionalProperties": False,
                         "required": list(_PROPERTIES),
                         "properties": {**_PROPERTIES, **_PROFILE_PROPERTIES, **FIXTURE_PROPERTIES, **_TOKEN_PROPERTIES,
                                        **_COVERAGE_PROPERTIES},
                         "dependentRequired": {"profile_path": ["profile_sha256"],
                                               "profile_sha256": ["profile_path"]},
                         "not": {"required": ["profile_text", "profile_path"]}},
    },
}


def missing_fields(document: dict) -> list[str]:
    """Required fields a policy draft does not state yet, for a person to fill in."""
    model = document.get("model_review", {})
    return sorted(set(_PROPERTIES) - set(model)) + ([] if "schema_version" in document else ["schema_version"])


def check_draft(document: dict) -> None:
    """Schema check only: nothing is read from a repository and no price or path rule runs."""
    try:
        jsonschema.Draft202012Validator(_SCHEMA).validate(document)
    except jsonschema.ValidationError as exc:
        raise AssistantError("gate_policy_invalid") from exc


@dataclass(frozen=True)
class ModelGatePolicy:
    document: dict
    config: Config
    path: str
    sha256: str
    base: str
    profile_path: str | None = None
    repo: Path | None = None


def _prefix(value: str, fixture_roots: tuple[str, ...] = (), *, denied: bool = False) -> str:
    """One allow_paths or deny_paths entry: a literal path or directory prefix.

    An allow entry also meets the path policy, because it admits files for review. A deny
    entry reads and sends nothing, so it may name a private path such as `.env.example`.
    """
    if any(character in value for character in "*?[]"):
        raise AssistantError("gate_policy_path_invalid")
    if denied:
        check_text(safe_relative(value.removesuffix("/")))
    else:
        check_path(value.removesuffix("/"), source_only=False, fixture_roots=fixture_roots)
    return value


def _profile_lines(lines: list[str]) -> list[str]:
    # Permit visible Unicode letters/marks/numbers/punctuation/symbols and ASCII
    # space only. Some marks and letters are invisible despite their category.
    invisible = {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180F,
                 0x2800, 0x3164, 0xFFA0, 0x13441, 0x13442, 0x16FE4, 0x1BC9D}
    for line in lines:
        if not line.strip(" ") or any(
            (char != " " and unicodedata.category(char)[0] not in "LMNPS")
            or ord(char) in invisible
            or 0x180B <= ord(char) <= 0x180D
            or 0xFE00 <= ord(char) <= 0xFE0F
            or 0xE0100 <= ord(char) <= 0xE01EF
            for char in line
        ):
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
    # Only LF and CRLF delimit physical instruction lines. Other separators,
    # including whitespace-only controls, must reach the line validator intact.
    lines = text.replace("\r\n", "\n").split("\n")
    return _profile_lines([line for line in lines if line.strip(" ")]), path


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
    settings = fixture_settings(repo, base, model)
    for name in ("allow_paths", "deny_paths"):
        for prefix in model[name]:
            _prefix(prefix, tuple(model.get("fixture_roots", ())), denied=name == "deny_paths")
    endpoint = urlsplit(model["endpoint"])
    if endpoint.hostname != model["allowed_host"]:
        raise AssistantError("gate_endpoint_host_mismatch")
    prices = {field: model[field] for field in ("input_usd_per_million", "output_usd_per_million")}
    if model["provider"] != "ollama" and any(value <= 0 for value in prices.values()):
        raise prices_required(prices)
    profile_text, profile_path = _profile(repo, base, model)
    config = load_policy_config(policy_config_fields(model, profile_text), settings)
    return ModelGatePolicy(document, config, path, pin, base, profile_path, repo)


def policy_config_fields(model: dict, profile_text: list[str] | None) -> dict:
    """The gate's Config fields: network, hosts and packet bounds are fixed by policy."""
    config_fields = {key: model[key] for key in (
        "provider", "model", "endpoint", "api_key_env", "profile", "allow_paths",
        "max_file_bytes", "max_output_tokens", "timeout_seconds", "max_run_usd", "daily_budget_usd",
        "input_usd_per_million", "output_usd_per_million", "blocking_severities",
    )}
    config_fields.update(allow_network=True, allowed_hosts=[model["allowed_host"]], generated_paths=[],
                         max_packet_bytes=max(2_000_000, model["max_request_bytes"]),
                         monthly_budget_usd=1_000_000)
    for key in ("private_paths", "related_context", "related_max_bytes"):
        if key in model:
            config_fields[key] = model[key]
    if profile_text is not None:
        profiles = deepcopy(PROFILES)
        profiles[model["profile"]] = profile_text
        config_fields["profiles"] = profiles
    return config_fields
