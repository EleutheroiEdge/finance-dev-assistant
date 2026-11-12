"""Packet structure used by verify_packet and the exported editor schema."""
from .document_contracts import array_schema, object_schema


def _related_schema() -> dict:
    from .related import MAX_SKIPPED, MAX_SNIPPETS, RELATIONS, RULE_VERSION

    text = {"type": "string"}
    reference = {"oneOf": [object_schema({"path": text, "line": {"type": "integer", "minimum": 1}}),
                            object_schema({"path": text, "symbol": text})]}
    line = {"type": "array", "prefixItems": [{"type": "integer", "minimum": 1}, text],
            "items": False, "minItems": 2, "maxItems": 2}
    snippet = object_schema({"path": text, "symbol": text, "relation": {"enum": list(RELATIONS)},
                             "reference": reference, "lines": array_schema(line, minItems=1),
                             "sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"}})
    skipped = object_schema({"path": text, "symbol": {"type": ["string", "null"]},
                             "reason": {"type": "string", "pattern": r"^[a-z][a-z0-9_]{0,80}$"}})
    return object_schema({
        "rule_version": {"const": RULE_VERSION},
        "budget_bytes": {"type": "integer", "minimum": 0},
        "snippets": array_schema(snippet, maxItems=MAX_SNIPPETS),
        "skipped": array_schema(skipped, maxItems=MAX_SKIPPED),
        "skipped_count": {"type": "integer", "minimum": 0, "maximum": 1_000_000},
    })


def _file_schema(version: int) -> dict:
    text = {"type": ["string", "null"]}
    sha = {"type": ["string", "null"], "pattern": r"^[0-9a-f]{64}$"}
    properties = {"path": {"type": "string"}, "status": {"enum": ["A", "D", "M", "T"]},
                  "before": text, "after": text, "before_hash": sha, "after_hash": sha}
    if version == 2:
        properties.update({side + "_mode": {"enum": [None, "100644", "100755"]} for side in ("before", "after")})
    result = object_schema(properties)
    result["not"] = {"properties": {"before": {"type": "null"}, "after": {"type": "null"}}}
    result["allOf"] = []
    for side in ("before", "after"):
        nulls = {side + "_hash": {"type": "null"}}
        present = {side + "_hash": {"type": "string"}}
        if version == 2:
            nulls[side + "_mode"] = {"type": "null"}
            present[side + "_mode"] = {"enum": ["100644", "100755"]}
        result["allOf"].append({"if": {"properties": {side: {"type": "null"}}},
                                "then": {"properties": nulls}, "else": {"properties": present}})
    return result


def packet_schema() -> dict:
    from .scope import WITHHELD_REASON

    text = {"type": "string"}
    revision = {"type": "string", "pattern": r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"}
    properties = {
        "schema_version": {"type": "integer", "enum": [1, 2]},
        "base": revision, "head": revision, "merge_base": revision, "profile": text,
        "changed_paths": array_schema(text, maxItems=2000, uniqueItems=True),
        "files": {"type": "array"},
        "omitted": array_schema(object_schema({"path": text, "reason": {"type": "string",
                                                                       "not": {"const": WITHHELD_REASON}}})),
        # Legacy packet validation does not constrain these descriptive fields.
        "data_class": {}, "classification_limit": {},
        "generated_paths": array_schema(text), "allow_paths": array_schema(text),
        "packet_hash": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
        "withheld": object_schema({"count": {"type": "integer", "minimum": 1, "maximum": 2000},
                                   "reason": {"const": WITHHELD_REASON}}),
        "related": _related_schema(),
    }
    result = object_schema(properties, properties.keys() - {"allow_paths", "withheld", "related"})
    result["allOf"] = [
        {"if": {"properties": {"schema_version": {"const": version}}},
         "then": {"properties": {"files": array_schema(_file_schema(version))}}} for version in (1, 2)]
    return result
