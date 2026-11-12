"""Packet structure used by verify_packet and the exported editor schema."""
from .document_contracts import array_schema, fullmatch_pattern, object_schema


def _related_schema() -> dict:
    from .related import CODE_PATTERN, MAX_SKIPPED, MAX_SKIPPED_COUNT, MAX_SNIPPETS, RELATIONS, RULE_VERSION
    from .scope import SHA256_PATTERN

    text = {"type": "string"}
    reference = {"oneOf": [object_schema({"path": text, "line": {"type": "integer", "minimum": 1}}),
                            object_schema({"path": text, "symbol": text})]}
    line = {"type": "array", "prefixItems": [{"type": "integer", "minimum": 1}, text],
            "items": False, "minItems": 2, "maxItems": 2}
    snippet = object_schema({"path": text, "symbol": text, "relation": {"enum": list(RELATIONS)},
                             "reference": reference, "lines": array_schema(line, minItems=1),
                             "sha256": {"type": "string", "pattern": fullmatch_pattern(SHA256_PATTERN)}})
    skipped = object_schema({"path": text, "symbol": {"type": ["string", "null"]},
                             "reason": {"type": "string", "pattern": fullmatch_pattern(CODE_PATTERN)}})
    return object_schema({
        "rule_version": {"const": RULE_VERSION},
        "budget_bytes": {"type": "integer", "minimum": 0},
        "snippets": array_schema(snippet, maxItems=MAX_SNIPPETS),
        "skipped": array_schema(skipped, maxItems=MAX_SKIPPED),
        "skipped_count": {"type": "integer", "minimum": 0, "maximum": MAX_SKIPPED_COUNT},
    })


def _file_schema(version: int) -> dict:
    from .scope import BLOB_MODES, FILE_STATUSES, SHA256_PATTERN

    text = {"type": ["string", "null"]}
    sha = {"type": ["string", "null"], "pattern": fullmatch_pattern(SHA256_PATTERN)}
    properties = {"path": {"type": "string"}, "status": {"enum": list(FILE_STATUSES)},
                  "before": text, "after": text}
    if version == 2:
        properties.update({side + "_mode": {"enum": [None, *BLOB_MODES]} for side in ("before", "after")})
    properties.update(before_hash=sha, after_hash=sha)
    result = object_schema(properties)
    result["not"] = {"properties": {"before": {"type": "null"}, "after": {"type": "null"}}}
    result["allOf"] = []
    for side in ("before", "after"):
        nulls = {side + "_hash": {"type": "null"}}
        present = {side + "_hash": {"type": "string"}}
        if version == 2:
            nulls = {side + "_mode": {"type": "null"}, **nulls}
            present = {side + "_mode": {"enum": list(BLOB_MODES)}, **present}
        result["allOf"].append({"if": {"properties": {side: {"type": "null"}}},
                                "then": {"properties": nulls}, "else": {"properties": present}})
    return result


def packet_schema() -> dict:
    from .scope import MAX_CHANGED_PATHS, PACKET_VERSIONS, REVISION_PATTERN, SHA256_PATTERN, WITHHELD_REASON

    text = {"type": "string"}
    revision = {"type": "string", "pattern": fullmatch_pattern(REVISION_PATTERN)}
    properties = {
        "schema_version": {"type": "integer", "enum": list(PACKET_VERSIONS)},
        "base": revision, "head": revision, "merge_base": revision, "profile": text,
        "changed_paths": array_schema(text, maxItems=MAX_CHANGED_PATHS, uniqueItems=True),
        "files": {"type": "array"},
        "omitted": array_schema(object_schema({"path": text, "reason": {"type": "string",
                                                                       "not": {"const": WITHHELD_REASON}}})),
        # Legacy packet validation does not constrain these descriptive fields.
        "data_class": {}, "classification_limit": {},
        "generated_paths": array_schema(text), "allow_paths": array_schema(text),
        "packet_hash": {"type": "string", "pattern": fullmatch_pattern(SHA256_PATTERN)},
        "withheld": object_schema({"count": {"type": "integer", "minimum": 1, "maximum": MAX_CHANGED_PATHS},
                                   "reason": {"const": WITHHELD_REASON}}),
        "related": _related_schema(),
    }
    result = object_schema(properties, properties.keys() - {"allow_paths", "withheld", "related"})
    result["allOf"] = [
        {"if": {"properties": {"schema_version": {"const": version}}},
         "then": {"properties": {"files": array_schema(_file_schema(version))}}} for version in PACKET_VERSIONS]
    return result
