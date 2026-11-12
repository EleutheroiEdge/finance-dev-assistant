"""Structural contracts shared by runtime validation and editor schema generation.

These checks supplement the content, filesystem, integrity and approval checks.
They never normalize an input document or authorize an operation.
"""
from functools import lru_cache

from jsonschema import Draft202012Validator, ValidationError

from .errors import AssistantError


def object_schema(properties: dict, required=None) -> dict:
    return {"type": "object", "properties": properties, "additionalProperties": False,
            "required": sorted(properties) if required is None else sorted(required)}


def array_schema(items: dict, **limits) -> dict:
    return {"type": "array", "items": items, **limits}


def suite_envelope_valid(value) -> bool:
    """Accept either spelling, or both agreeing, without changing the hashed input."""
    if not isinstance(value, dict):
        return False
    versions = set(value) & {"version", "schema_version"}
    return (bool(versions) and set(value) == versions | {"cases"}
            and all(type(value[key]) is int and value[key] == 1 for key in versions))


def _suite(case: dict) -> dict:
    schema = object_schema({"version": {"type": "integer", "const": 1},
                            "schema_version": {"type": "integer", "const": 1},
                            "cases": array_schema(case, minItems=1, maxItems=50)}, ["cases"])
    schema["anyOf"] = [{"required": ["version"]}, {"required": ["schema_version"]}]
    return schema


def evaluation_suite_schema() -> dict:
    return _suite(object_schema({
        "id": {"type": "string", "minLength": 1}, "path": {"type": "string", "minLength": 1},
        "before": {"type": "string", "minLength": 1, "maxLength": 48_000},
        "after": {"type": "string", "minLength": 1, "maxLength": 48_000},
        "expected_defect": {"type": "boolean"},
    }))


def history_suite_schema() -> dict:
    from .history_suite import SEVERITY_WEIGHTS

    identifier = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$"}
    revision = {"type": "string", "pattern": r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"}
    repository = {"type": "string", "minLength": 1, "maxLength": 4096,
                  "not": {"pattern": "://"}}
    expected = object_schema({
        "label": identifier, "severity": {"enum": list(SEVERITY_WEIGHTS)},
        "paths": array_schema({"type": "string", "minLength": 1}, minItems=1, maxItems=50, uniqueItems=True),
    })
    policy = object_schema({
        "path": {"type": "string", "minLength": 1},
        "sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
        "repo_path": repository, "commit": {"type": "string", "pattern": r"^[0-9a-f]{40}$"},
    }, ["path", "sha256"])
    fields = {"id": identifier, "repo_path": repository, "base_sha": revision, "head_sha": revision,
              "profile": identifier, "expected": array_schema(expected, maxItems=50),
              "negative_control": {"type": "boolean"}, "policy": policy}
    case = object_schema(fields, fields.keys() - {"policy"})
    case["allOf"] = [
        {"if": {"properties": {"negative_control": {"const": True}}},
         "then": {"properties": {"expected": {"maxItems": 0}}},
         "else": {"properties": {"expected": {"minItems": 1}}}},
        {"if": {"required": ["policy"], "properties": {"policy": {"not": {"required": ["commit"]}}}},
         "then": {"properties": {"base_sha": {"pattern": r"^[0-9a-f]{40}$"}}}},
    ]
    return _suite(case)


@lru_cache(maxsize=4)
def _validator(kind: str) -> Draft202012Validator:
    if kind == "packet":
        from .packet_schema import packet_schema
        schema = packet_schema()
    elif kind == "review-report":
        from .review_report_schema import review_report_schema
        schema = review_report_schema()
    else:
        schema = {"evaluation-suite": evaluation_suite_schema,
                  "history-suite": history_suite_schema}[kind]()
    return Draft202012Validator(schema)


def validate_document_shape(document: dict, kind: str, error: str) -> None:
    try:
        _validator(kind).validate(document)
    except ValidationError as exc:
        raise AssistantError(error) from exc
