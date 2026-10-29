"""Pinned base-revision CI policy; source changes cannot grant themselves authority."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re

import jsonschema

from .config import Config, load_config
from .errors import AssistantError
from .scope import read_entry
from .security import canonical, check_path, check_text, digest, pinned_image, regular_path
from .workflow import parse_template

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "repository", "events", "base_branches", "forks", "backend",
                 "review", "guard_paths", "max_steps", "max_check_seconds", "config", "workflow"],
    "properties": {
        "schema_version": {"type": "integer", "const": 1},
        "repository": {"type": "string", "maxLength": 201},
        "events": {"const": ["pull_request"]},
        "base_branches": {"type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": True,
                          "items": {"type": "string", "minLength": 1, "maxLength": 256}},
        "forks": {"enum": ["deny", "checks-only"]}, "backend": {"enum": ["docker", "podman"]},
        "review": {"enum": ["not-requested", "required"]},
        "guard_paths": {"type": "array", "maxItems": 64, "uniqueItems": True,
                        "items": {"type": "string", "minLength": 1, "maxLength": 512}},
        "max_steps": {"type": "integer", "minimum": 1, "maximum": 64},
        "max_check_seconds": {"type": "integer", "minimum": 1, "maximum": 3600},
        "config": {"type": "object"}, "workflow": {"type": "object"},
    },
}


def repository_name(value: str) -> str:
    if not isinstance(value, str) or _REPOSITORY.fullmatch(value) is None or any(
        part in {".", ".."} for part in value.split("/")
    ):
        raise AssistantError("ci_repository_invalid")
    return value.lower()


def revision(value: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise AssistantError("ci_revision_invalid")
    return value


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise AssistantError("ci_json_duplicate_key")
        value[key] = item
    return value


def _constant(_value):
    raise AssistantError("ci_json_invalid")


def decode_document(content: bytes, code: str) -> dict:
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AssistantError(code) from exc
    if not isinstance(value, dict):
        raise AssistantError(code)
    return value


def read_document(path: Path, *, limit: int = 1_000_000) -> dict:
    file = regular_path(path)
    if not file.is_file():
        raise AssistantError("ci_input_unavailable")
    with file.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise AssistantError("ci_input_too_large")
    return decode_document(content, "ci_input_invalid")


@dataclass(frozen=True)
class CIPolicy:
    document: dict
    config: Config
    path: str
    sha256: str
    revision: str

    @property
    def guarded_paths(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.path, ".github/", *self.document["workflow"]["methodology"],
                                    *self.document["guard_paths"])))


def load_ci_policy(repo: Path, base: str, path: str, approved_sha256: str) -> CIPolicy:
    revision(base)
    path = check_path(path, source_only=False)
    if not isinstance(approved_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", approved_sha256) is None:
        raise AssistantError("ci_policy_pin_required")
    raw, _mode = read_entry(repo, base, path, 128_000)
    if raw is None:
        raise AssistantError("ci_policy_missing_at_base")
    if digest(raw) != approved_sha256:
        raise AssistantError("ci_policy_pin_mismatch")
    document = decode_document(raw, "ci_policy_invalid")
    try:
        jsonschema.Draft202012Validator(_SCHEMA).validate(document)
    except jsonschema.ValidationError as exc:
        raise AssistantError("ci_policy_invalid") from exc
    if any(type(document[key]) is not int for key in ("schema_version", "max_steps", "max_check_seconds")):
        raise AssistantError("ci_policy_invalid")
    repository_name(document["repository"])
    for branch in document["base_branches"]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,255}", branch) or ".." in branch:
            raise AssistantError("ci_policy_invalid")
    for guarded in document["guard_paths"]:
        check_path(guarded.removesuffix("/"), source_only=False)
    check_text(raw.decode())
    if document["config"].get("profile_files"):
        raise AssistantError("ci_external_profiles_forbidden")
    if document["config"].get("provider", "offline") != "offline" or any(
        document["config"].get(key, False) is not False
        for key in ("allow_network", "allow_partial_review", "allow_local_readiness")
    ):
        raise AssistantError("ci_policy_capability_forbidden")
    config = load_config(content=canonical(document["config"]))
    if config.provider != "offline" or config.allow_network or config.allow_partial_review or config.allow_local_readiness:
        raise AssistantError("ci_policy_capability_forbidden")
    pinned_image(config.runner_image)
    template = parse_template(document["workflow"], config)
    recipes = {item.recipe for item in template.requirements}
    if not config.required_recipes or not set(config.required_recipes) <= recipes or not recipes <= set(config.recipes):
        raise AssistantError("ci_policy_requirements_invalid")
    return CIPolicy(document, config, path, approved_sha256, base)
