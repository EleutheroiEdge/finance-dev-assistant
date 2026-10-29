"""Resolve pinned local declarative packs; never install code or grant capabilities."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path

import jsonschema

from .config import Config
from .errors import AssistantError
from .security import canonical, check_text, digest, regular_path, write_private
from .workflow import parse_template

_ID = {"type": "string", "pattern": r"^[a-z][a-z0-9-]{0,63}(?![\s\S])"}
_HASH = {"type": "string", "pattern": r"^[0-9a-f]{64}(?![\s\S])"}
_PATH = {"type": "string", "minLength": 1, "maxLength": 512}
_RECIPE = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}(?![\s\S])"}
_INTEGER_CAPS = {"max_file_bytes", "max_packet_bytes", "max_output_tokens", "timeout_seconds", "readiness_max_age_seconds"}
_COST_CAPS = {"max_run_usd", "daily_budget_usd", "monthly_budget_usd"}
_FALSE_ONLY = {"allow_network", "allow_partial_review", "allow_local_readiness"}
_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _object(properties: dict, *, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties, "required": list(properties) if required is None else required,
            "additionalProperties": False}


def _list(item: dict, maximum: int = 64, *, minimum: int = 1) -> dict:
    return {"type": "array", "items": item, "minItems": minimum, "maxItems": maximum, "uniqueItems": True}


_BUNDLE_SCHEMA = _object({
    "schema_version": {"type": "integer", "const": 1}, "name": _ID, "profile": _ID,
    "packs": _list(_object({"path": _PATH, "sha256": _HASH}), 16),
    "recipe_bindings": {"type": "object", "propertyNames": _RECIPE, "additionalProperties": _RECIPE,
                        "maxProperties": 64},
})
_POLICY_SCHEMA = _object({
    **{key: {"type": "integer", "minimum": 1, "maximum": 2_000_000} for key in _INTEGER_CAPS},
    **{key: {"type": "number", "minimum": 0, "maximum": 1_000_000_000} for key in _COST_CAPS},
    **{key: {"const": False} for key in _FALSE_ONLY},
    "required_recipes": _list(_RECIPE),
    "blocking_severities": _list({"enum": list(_SEVERITIES)}, 5),
}, required=[])
_PROFILE_SCHEMA = {
    "type": "object", "minProperties": 1, "maxProperties": 64, "propertyNames": _ID,
    "additionalProperties": _list({"type": "string", "minLength": 1, "maxLength": 2000}),
}
_PACK_SCHEMA = _object({
    "schema_version": {"type": "integer", "const": 1}, "name": _ID,
    "version": {"type": "string", "pattern": r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?![\s\S])"},
    "kind": {"enum": ["profile", "workflow", "checks", "policy"]},
    "compatibility": _object({"config_schema": {"type": "integer", "const": 1},
                               "workflow_schema": {"type": "integer", "const": 1}}),
    "data": {"type": "object"},
})
_SOURCE_SCHEMA = _object({"path": _PATH, "sha256": _HASH, **{
    key: _PACK_SCHEMA["properties"][key] for key in ("name", "version", "kind")
}})
_RESOLUTION_SCHEMA = _object({
    "schema_version": {"type": "integer", "const": 1}, "bundle_name": _ID,
    **{key: _HASH for key in ("bundle_hash", "base_config_hash", "config_hash", "template_hash", "resolution_hash")},
    "sources": _list(_SOURCE_SCHEMA, 16),
    "decisions": _list(_object({
        "field": {"type": "string", "pattern": r"^[A-Za-z0-9_.-]{1,256}(?![\s\S])"},
        "rule": {"enum": ["add-or-identical", "explicit-binding", "minimum-cap", "disable-only",
                           "required-union", "blocking-union"]},
        "source": _RECIPE, "value": _RECIPE,
    }, required=["field", "rule", "source"]), 2048),
})


def _validate(value: dict, schema: dict, code: str) -> None:
    try:
        jsonschema.Draft202012Validator(schema).validate(value)
    except jsonschema.ValidationError as exc:
        raise AssistantError(code) from exc
    if "schema_version" in value and type(value["schema_version"]) is not int:
        raise AssistantError(code)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AssistantError("workflow_pack_duplicate_key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise AssistantError("workflow_pack_invalid")


def read_bundle(path: Path) -> dict:
    file = regular_path(path)
    if not file.is_file():
        raise AssistantError("workflow_bundle_unavailable")
    with file.open("rb") as stream:
        content = stream.read(128_001)
    if len(content) > 128_000:
        raise AssistantError("workflow_bundle_too_large")
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, RecursionError) as exc:
        raise AssistantError("workflow_bundle_invalid") from exc
    _validate(value, _BUNDLE_SCHEMA, "workflow_bundle_invalid")
    return value


def _load_pack(reference: dict, repo: Path, config: Config) -> tuple[dict, dict]:
    path = config.check_path(reference["path"], source_only=False)
    if not path.endswith(".json"):
        raise AssistantError("workflow_pack_path_invalid")
    file = regular_path(repo / path)
    if not file.is_file() or file.stat().st_size > 128_000:
        raise AssistantError("workflow_pack_unavailable_or_large")
    with file.open("rb") as stream:
        content = stream.read(128_001)
    if len(content) > 128_000 or digest(content) != reference["sha256"]:
        raise AssistantError("workflow_pack_digest_mismatch")
    try:
        text = content.decode("utf-8")
    except UnicodeError as exc:
        raise AssistantError("workflow_pack_invalid") from exc
    check_text(text, extra_patterns=config.extra_sensitive_patterns)
    try:
        pack = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, RecursionError) as exc:
        raise AssistantError("workflow_pack_invalid") from exc
    _validate(pack, _PACK_SCHEMA, "workflow_pack_invalid")
    if any(type(value) is not int for value in pack["compatibility"].values()):
        raise AssistantError("workflow_pack_invalid")
    source = {"path": path, "sha256": reference["sha256"],
              **{key: pack[key] for key in ("name", "version", "kind")}}
    return pack, source


def _check_data(data: dict) -> None:
    # Reuse the authoritative workflow schema for identifiers and graph records;
    # whole-graph validation happens after all contributions are assembled.
    from .workflow import _TEMPLATE_SCHEMA

    _validate(data, _object({key: _TEMPLATE_SCHEMA["properties"][key] for key in ("requirements", "steps")}),
              "workflow_check_pack_invalid")


def resolve_bundle(bundle: dict, repo: Path, config: Config) -> dict:
    """Pure local resolution. The base configuration remains the authority ceiling."""
    config.validate()
    _validate(bundle, _BUNDLE_SCHEMA, "workflow_bundle_invalid")
    check_text(canonical(bundle).decode(), extra_patterns=config.extra_sensitive_patterns)
    if len({item["path"] for item in bundle["packs"]}) != len(bundle["packs"]):
        raise AssistantError("workflow_pack_duplicate_path")
    profiles = deepcopy(dict(config.profiles))
    workflow, checks, policies, sources, decisions, identities = None, [], [], [], [], set()
    for reference in bundle["packs"]:
        pack, source = _load_pack(reference, repo, config)
        if pack["name"] in identities:
            raise AssistantError("workflow_pack_duplicate_name")
        identities.add(pack["name"])
        sources.append(source)
        data, kind = pack["data"], pack["kind"]
        if kind == "profile":
            _validate(data, _PROFILE_SCHEMA, "workflow_profile_pack_invalid")
            for name, checklist in data.items():
                if name in profiles and profiles[name] != checklist:
                    raise AssistantError("workflow_profile_conflict")
                profiles[name] = deepcopy(checklist)
                decisions.append({"field": "profiles." + name, "rule": "add-or-identical", "source": pack["name"]})
        elif kind == "workflow":
            if workflow is not None:
                raise AssistantError("workflow_pack_multiple_workflows")
            workflow = deepcopy(data)
        elif kind == "checks":
            _check_data(data)
            checks.append(deepcopy(data))
        else:
            _validate(data, _POLICY_SCHEMA, "workflow_policy_pack_invalid")
            if any(type(data[key]) is not int for key in _INTEGER_CAPS & data.keys()):
                raise AssistantError("workflow_policy_pack_invalid")
            policies.append((pack["name"], data))
    if workflow is None:
        raise AssistantError("workflow_pack_workflow_required")
    # Validate a complete base template before any merge can conceal malformed
    # input. Recipes are symbolic contract names until the explicit binding step.
    parse_template(workflow, config)
    for addition in checks:
        workflow["requirements"].extend(addition["requirements"])
        workflow["steps"].extend(addition["steps"])
        for requirement in addition["requirements"]:
            for path in requirement["methodology"]:
                if path not in workflow["methodology"]:
                    workflow["methodology"].append(path)
    contracts = {requirement["recipe"] for requirement in workflow["requirements"]}
    contracts |= {name for _source, policy in policies for name in policy.get("required_recipes", [])}
    if set(bundle["recipe_bindings"]) - contracts:
        raise AssistantError("workflow_recipe_binding_unused")

    def bound(name: str) -> str:
        result = bundle["recipe_bindings"].get(name, name)
        if result not in config.recipes:
            raise AssistantError("workflow_recipe_binding_unknown")
        return result

    if len({bound(name) for name in contracts}) != len(contracts):
        raise AssistantError("workflow_duplicate_recipe")

    for requirement in workflow["requirements"]:
        original = requirement["recipe"]
        requirement["recipe"] = bound(original)
        decisions.append({"field": "requirements." + requirement["id"] + ".recipe", "rule": "explicit-binding",
                          "source": original, "value": requirement["recipe"]})
    updates = {"profiles": profiles, "profile": bundle["profile"], "profile_files": ()}
    required, severities = set(config.required_recipes), set(config.blocking_severities)
    for source_name, policy in policies:
        for key, value in policy.items():
            if key in _INTEGER_CAPS:
                updates[key] = min(updates.get(key, getattr(config, key)), value)
                rule = "minimum-cap"
            elif key in _COST_CAPS:
                updates[key] = min(float(updates.get(key, getattr(config, key))), float(value))
                rule = "minimum-cap"
            elif key in _FALSE_ONLY:
                updates[key] = False
                rule = "disable-only"
            elif key == "required_recipes":
                required.update(bound(name) for name in value)
                rule = "required-union"
            else:
                severities.update(value)
                rule = "blocking-union"
            decisions.append({"field": key, "rule": rule, "source": source_name})
    updates.update(required_recipes=tuple(sorted(required)),
                   blocking_severities=tuple(value for value in _SEVERITIES if value in severities))
    effective = replace(config, **updates).validate()
    parse_template(workflow, effective)
    if not set(effective.required_recipes) <= {item["recipe"] for item in workflow["requirements"]}:
        raise AssistantError("workflow_required_recipe_omitted")
    configuration = asdict(effective)
    resolution = {
        "schema_version": 1, "bundle_name": bundle["name"], "bundle_hash": digest(canonical(bundle)),
        "base_config_hash": digest(canonical(asdict(config))), "config_hash": digest(canonical(configuration)),
        "template_hash": digest(canonical(workflow)), "sources": sources, "decisions": decisions,
    }
    resolution["resolution_hash"] = digest(canonical(resolution))
    for value in (configuration, workflow, resolution):
        if len(canonical(value)) + 1 > 2_000_000:
            raise AssistantError("workflow_resolution_limit_exceeded")
    return {"config": configuration, "template": workflow, "resolution": resolution}


def verify_resolution(resolution: dict, template: dict, config: Config) -> str:
    """Bind a provenance record to effective inputs; not an origin attestation."""
    config.validate()
    _validate(resolution, _RESOLUTION_SCHEMA, "workflow_resolution_invalid")
    check_text(canonical(resolution).decode(), extra_patterns=config.extra_sensitive_patterns)
    if (
        resolution["resolution_hash"] != digest(canonical({
            key: value for key, value in resolution.items() if key != "resolution_hash"
        }))
    ):
        raise AssistantError("workflow_resolution_invalid")
    if resolution["config_hash"] != digest(canonical(asdict(config))) or resolution["template_hash"] != digest(canonical(template)):
        raise AssistantError("workflow_resolution_inputs_changed")
    return resolution["resolution_hash"]


def export_resolution(result: dict, destination: Path) -> dict:
    destination = regular_path(destination)
    try:
        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise AssistantError("workflow_resolution_destination_exists") from exc
    for key, filename in (("config", "config.json"), ("template", "template.json"), ("resolution", "resolution.json")):
        write_private(destination / filename, canonical(result[key]) + b"\n")
    return {
        "directory": str(destination), "resolution_hash": result["resolution"]["resolution_hash"],
        "config_hash": result["resolution"]["config_hash"], "template_hash": result["resolution"]["template_hash"],
        "execution_authorized": False,
    }
