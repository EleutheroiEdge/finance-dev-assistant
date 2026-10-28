"""Generate the editor schema from Config fields, annotations and metadata.

Runtime validation remains authoritative for path/content policies, endpoint
approval, cross-field references and external profile files. No network access.
"""

from dataclasses import asdict, fields
import json
from typing import get_origin, get_type_hints

from .config import Config

SCHEMA_ID = "https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/main/schemas/finassist.schema.json"


def configuration_schema() -> dict:
    defaults = json.loads(json.dumps(asdict(Config())))
    hints = get_type_hints(Config)
    properties = {"$schema": {"type": "string", "maxLength": 2048, "description": "Editor hint only; never fetched by finassist."}}
    types = {str: "string", int: "integer", float: "number", bool: "boolean", dict: "object"}
    for item in fields(Config):
        hint = hints[item.name]
        schema = {"title": item.name.replace("_", " ").capitalize(), "default": defaults[item.name]}
        if get_origin(hint) is tuple:
            schema.update(type="array", items={"type": "string"})
        else:
            schema["type"] = types[hint]  # Fail generation when a new unsupported type is introduced.
        schema.update(item.metadata.get("json_schema", {}))
        properties[item.name] = schema
    properties["profiles"].update(
        minProperties=1, maxProperties=64, required=["general"],
        propertyNames={"pattern": "^[a-z][a-z0-9-]{0,63}$"},
        additionalProperties={"type": "array", "minItems": 1, "maxItems": 64,
                              "items": {"type": "string", "minLength": 1, "maxLength": 2000}},
    )
    properties["recipes"].update(
        propertyNames={"pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},
        additionalProperties={"type": "array", "minItems": 1, "items": {"type": "string"}},
    )
    for name, limit in [("generated_paths", 128), ("denied_parts", 128), ("text_suffixes", 128), ("profile_files", 16)]:
        properties[name].update(maxItems=limit, uniqueItems=True)
    properties["text_suffixes"].update(minItems=1, items={"type": "string", "pattern": r"^\.[a-z][a-z0-9]{0,15}$"})
    properties["protected_branches"]["minItems"] = 1
    properties["required_recipes"]["uniqueItems"] = True
    properties["blocking_severities"]["items"] = {"enum": ["critical", "high", "medium", "low", "info"]}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": SCHEMA_ID,
        "title": "finassist configuration", "type": "object", "additionalProperties": False,
        "description": "Editor structure and limits. CLI validation additionally enforces sensitive paths/content, provider approval and file/cross-field policies.",
        "properties": properties,
        "allOf": [{"if": {"required": ["provider"], "properties": {"provider": {"not": {"const": "offline"}}}},
                   "then": {"required": ["model"], "properties": {"model": {"minLength": 1}}}}],
    }


def schema_text() -> str:
    return json.dumps(configuration_schema(), indent=2, ensure_ascii=False, sort_keys=True) + "\n"
