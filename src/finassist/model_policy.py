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
from .figure_source_entries import OPT_IN, SOURCE_ENTRY_SCHEMA, check_opt_in
from .figure_sources import ROUND_OPTIONS, ROUND_RULE, SOURCE_RULE, source_rule
from .forbidden_tokens import MATCHES, MAX_MIN_DIGITS, MAX_SOURCE_FILES, MAX_TOKENS, MIN_DIGITS
from .hidden_text import check_hidden
from .occurrence_identity import MAX_OCCURRENCE_ENTRIES, is_yaml_path
from .security import (DENIED_SUFFIXES, MAX_PLACEHOLDER_PATHS, canonical, check_credentials, check_model_path, check_name, check_path,
                       check_text, digest, safe_relative)

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
    "forbidden_token_hashes": {"type": "array", "minItems": 1, "maxItems": MAX_TOKENS, "uniqueItems": True,
                              "items": {"type": "string", "pattern": r"^[0-9a-f]{64}$"}},
    # A path, or a {path, delimiter, decimal_mark} object that declares the file's layout.
    "forbidden_token_sources": {"type": "array", "minItems": 1, "maxItems": MAX_SOURCE_FILES, "uniqueItems": True,
                               "items": SOURCE_ENTRY_SCHEMA},
    "forbidden_token_match": {"enum": list(MATCHES)},
    "forbidden_token_min_digits": {"type": "integer", "minimum": MIN_DIGITS, "maximum": MAX_MIN_DIGITS},
    # The rule the sources are read by, stated in the reviewed bytes: required with sources, and only with them.
    "forbidden_token_source_rule": {"type": "integer", "enum": [SOURCE_RULE, ROUND_RULE]},
    # list: the sources' round figures too, read by rule 27; only with sources.
    "forbidden_token_round_figures": {"enum": list(ROUND_OPTIONS)},
    # true: read the sources, an experimental reader that can miss figures. Without it a policy with sources is refused.
    OPT_IN: {"const": True},
}
# Optional. refuse (the default) keeps today's behaviour; skip-and-report withholds private paths.
_COVERAGE_PROPERTIES = {"private_paths": {"enum": ["refuse", "skip-and-report"]},
                        "unreviewable_paths": {"enum": ["refuse", "skip-and-report"]},
                        "placeholder_credential_paths": {
                            "type": "array", "maxItems": MAX_PLACEHOLDER_PATHS, "uniqueItems": True,
                            "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                        # The reviewable suffixes, as in the configuration. Data and binary formats stay
                        # refused whatever this says.
                        "text_suffixes": {
                            "type": "array", "minItems": 1, "maxItems": 128, "uniqueItems": True,
                            "items": {"type": "string", "pattern": r"^\.[a-z][a-z0-9]{0,15}$"}},
                        # Reviewed public synthetic YAML values the credential label rules let through, each
                        # bound to its exact place: see occurrence_identity.
                        "placeholder_credential_occurrences": {
                            "type": "array", "maxItems": MAX_OCCURRENCE_ENTRIES, "uniqueItems": True,
                            "items": {"type": "object", "additionalProperties": False,
                                      "required": ["path", "occurrence_sha256"],
                                      "properties": {
                                          "path": {"type": "string", "minLength": 1, "maxLength": 512},
                                          "occurrence_sha256": {"type": "string",
                                                                "pattern": r"^[0-9a-f]{64}$"}}}},
                        "related_context": {"enum": ["none", "related"]},
                        # block (the default) refuses a range with nothing in scope; not-applicable is the
                        # policy author's statement that such a range needs no review (an explicit opt-in).
                        "out_of_scope_ranges": {"enum": ["block", "not-applicable"]},
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


def stated_source_rule(model: dict) -> int:
    """The source rule a policy's own settings call for: 27 with `"forbidden_token_round_figures": "list"`, else 26."""
    rounds = model.get("forbidden_token_round_figures")
    return source_rule(rounds) if isinstance(rounds, str) else SOURCE_RULE


def source_rule_issue(document: object) -> bool:
    """Whether a policy's `forbidden_token_source_rule` disagrees with its sources: missing beside them, present
    without them, or anything but the rule its settings call for as an integer; or a round-figure setting without
    sources. Such a policy is refused before anything is read or sent, and is never read by another rule than the one
    its reviewed bytes state."""
    model = document.get("model_review") if isinstance(document, dict) else None
    if not isinstance(model, dict):
        return False
    rule = model.get("forbidden_token_source_rule")
    if "forbidden_token_sources" not in model:
        return "forbidden_token_source_rule" in model or "forbidden_token_round_figures" in model
    return type(rule) is not int or rule != stated_source_rule(model)


def missing_fields(document: dict) -> list[str]:
    """Required fields a policy draft does not state yet, for a person to fill in."""
    model = document.get("model_review", {})
    return sorted(set(_PROPERTIES) - set(model)) + ([] if "schema_version" in document else ["schema_version"])


def coverage_issues(model: dict) -> list[tuple[str, str]]:
    """(code, field) for each coverage setting the gate refuses once the schema passes: a data or binary format in
    `text_suffixes`, which is never reviewable, and a `placeholder_credential_occurrences` entry that names no exact
    repository path to a YAML file. The gate, doctor and the draft check all judge them here, and read nothing."""
    issues = []
    if set(model.get("text_suffixes", ())) & DENIED_SUFFIXES:
        issues.append(("gate_policy_invalid", "/model_review/text_suffixes"))
    for index, entry in enumerate(model.get("placeholder_credential_occurrences", ())):
        try:
            check_path(entry["path"], source_only=False)
            exact = is_yaml_path(entry["path"]) and "*" not in entry["path"]
        except AssistantError:
            exact = False
        if not exact:
            issues.append(("invalid_placeholder_credential_occurrences",
                           f"/model_review/placeholder_credential_occurrences/{index}"))
    return issues


def check_draft(document: dict) -> None:
    """The source rule beside the sources, first, as the gate and doctor check it, then the schema and the coverage
    settings: nothing is read from a repository and no price rule or allow or deny path rule runs."""
    if source_rule_issue(document):
        raise AssistantError("gate_policy_source_rule_required")
    try:
        jsonschema.Draft202012Validator(_SCHEMA).validate(document)
    except jsonschema.ValidationError as exc:
        raise AssistantError("gate_policy_invalid") from exc
    check_opt_in(document["model_review"])  # experimental figure sources, as the gate and doctor check them
    issues = coverage_issues(document["model_review"])
    if issues:
        raise AssistantError(issues[0][0])


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
        check_name(safe_relative(value.removesuffix("/")))
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
    check_credentials(text)
    # Only LF and CRLF delimit physical instruction lines. Other separators,
    # including whitespace-only controls, must reach the line validator intact.
    lines = text.replace("\r\n", "\n").split("\n")
    instructions = _profile_lines([line for line in lines if line.strip(" ")])
    check_hidden(text)  # The second half of check_text, after the line rule has named what it refuses.
    return instructions, path


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
    if source_rule_issue(document):
        raise AssistantError("gate_policy_source_rule_required")
    try:
        jsonschema.Draft202012Validator(_SCHEMA).validate(document)
    except jsonschema.ValidationError as exc:
        raise AssistantError("gate_policy_invalid") from exc
    model = document["model_review"]
    if type(document["schema_version"]) is not int or model["enabled"] is not True:
        raise AssistantError("gate_policy_invalid")
    check_opt_in(model)  # before any source or other file is read
    for field, schema in _PROPERTIES.items():
        if schema.get("type") == "integer" and type(model[field]) is not int:
            raise AssistantError("gate_policy_invalid")
    # The only key material accepted by a policy is a variable NAME. All other
    # fields are screened, including unknown fields rejected by the schema.
    check_text(canonical(document).decode())
    issues = coverage_issues(model)
    if issues:
        raise AssistantError(issues[0][0])
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
    for key in ("private_paths", "unreviewable_paths", "placeholder_credential_paths", "related_context",
                "related_max_bytes", "text_suffixes"):
        if key in model:
            config_fields[key] = model[key]
    if profile_text is not None:
        profiles = deepcopy(PROFILES)
        profiles[model["profile"]] = profile_text
        config_fields["profiles"] = profiles
    return config_fields
