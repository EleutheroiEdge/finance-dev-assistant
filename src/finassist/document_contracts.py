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


def fullmatch_pattern(expression: str) -> str:
    # JSON Schema uses search, while enforcing modules use fullmatch. Unlike $
    # alone, the final assertion also refuses a trailing newline.
    return "^(?:" + expression + r")$(?![\s\S])"


def _suite(case: dict, *, version: int, max_cases: int) -> dict:
    schema = object_schema({"version": {"type": "integer", "const": version},
                            "schema_version": {"type": "integer", "const": version},
                            "cases": array_schema(case, minItems=1, maxItems=max_cases)}, ["cases"])
    schema["anyOf"] = [{"required": ["version"]}, {"required": ["schema_version"]}]
    return schema


def evaluation_suite_schema() -> dict:
    from .evaluation import MAX_CASES, MAX_SOURCE_BYTES, SUITE_VERSION

    return _suite(object_schema({
        "id": {"type": "string", "minLength": 1}, "path": {"type": "string", "minLength": 1},
        "before": {"type": "string", "minLength": 1, "maxLength": MAX_SOURCE_BYTES,
                   "description": "Character bound only; runtime additionally caps UTF-8 encoded bytes at this limit."},
        "after": {"type": "string", "minLength": 1, "maxLength": MAX_SOURCE_BYTES,
                   "description": "Character bound only; runtime additionally caps UTF-8 encoded bytes at this limit."},
        "expected_defect": {"type": "boolean"},
    }), version=SUITE_VERSION, max_cases=MAX_CASES)


def history_suite_schema() -> dict:
    from .history_suite import (IDENTIFIER_PATTERN, MAX_CASES, MAX_EXPECTED, MAX_EXPECTED_PATHS,
                                MAX_REPOSITORY_LENGTH, POLICY_COMMIT_PATTERN, SEVERITY_WEIGHTS, SUITE_VERSION)
    from .scope import REVISION_PATTERN, SHA256_PATTERN

    identifier = {"type": "string", "pattern": fullmatch_pattern(IDENTIFIER_PATTERN)}
    revision = {"type": "string", "pattern": fullmatch_pattern(REVISION_PATTERN)}
    repository = {"type": "string", "minLength": 1, "maxLength": MAX_REPOSITORY_LENGTH,
                  "not": {"pattern": "://"}}
    expected = object_schema({
        "label": identifier, "severity": {"enum": list(SEVERITY_WEIGHTS)},
        "paths": array_schema({"type": "string", "minLength": 1}, minItems=1, maxItems=MAX_EXPECTED_PATHS, uniqueItems=True),
    })
    policy = object_schema({
        "path": {"type": "string", "minLength": 1},
        "sha256": {"type": "string", "pattern": fullmatch_pattern(SHA256_PATTERN)},
        "repo_path": repository, "commit": {"type": "string", "pattern": fullmatch_pattern(POLICY_COMMIT_PATTERN)},
    }, ["path", "sha256"])
    fields = {"id": identifier, "repo_path": repository, "base_sha": revision, "head_sha": revision,
              "profile": identifier, "expected": array_schema(expected, maxItems=MAX_EXPECTED),
              "negative_control": {"type": "boolean"}, "policy": policy}
    case = object_schema(fields, fields.keys() - {"policy"})
    case["allOf"] = [
        {"if": {"properties": {"negative_control": {"const": True}}},
         "then": {"properties": {"expected": {"maxItems": 0}}},
         "else": {"properties": {"expected": {"minItems": 1}}}},
        {"if": {"required": ["policy"], "properties": {"policy": {"not": {"required": ["commit"]}}}},
         "then": {"properties": {"base_sha": {"pattern": fullmatch_pattern(POLICY_COMMIT_PATTERN)}}}},
    ]
    return _suite(case, version=SUITE_VERSION, max_cases=MAX_CASES)


@lru_cache(maxsize=6)
def _validator(kind: str) -> Draft202012Validator:
    if kind == "related":
        from .packet_schema import _related_schema
        schema = _related_schema()
    elif kind == "history-expected":
        case = history_suite_schema()["properties"]["cases"]["items"]
        schema = object_schema({key: case["properties"][key] for key in ("expected", "negative_control")})
        schema["allOf"] = [case["allOf"][0]]
    elif kind == "packet":
        from .packet_schema import packet_schema
        schema = packet_schema()
    elif kind == "review-report":
        from .review_report_schema import review_report_schema
        schema = review_report_schema()
    else:
        schema = {"evaluation-suite": evaluation_suite_schema,
                  "history-suite": history_suite_schema}[kind]()
    return Draft202012Validator(schema)


def _raise_shape_error(kind, exc):
    """Keep documented field-level errors while the shared schema owns structure."""
    path = list(exc.absolute_path)
    if kind == "evaluation-suite" and path and path[0] == "cases":
        if len(path) == 1:
            raise AssistantError("invalid_eval_cases")
        if len(path) == 2:
            raise AssistantError("invalid_eval_case")
        if path[2] in {"id", "expected_defect"}:
            raise AssistantError("invalid_eval_identity")
        if path[2] == "path" and exc.instance == "":
            raise AssistantError("unsafe_path")
        if path[2] in {"before", "after"}:
            raise AssistantError("invalid_eval_source")
        raise AssistantError("invalid_eval_case")
    if kind == "history-expected":
        path = ["cases", 0, *path]
        kind = "history-suite"
    if kind == "history-suite" and path and path[0] == "cases":
        if len(path) == 1:
            raise AssistantError("history_cases_invalid")
        if len(path) == 2:
            raise AssistantError("history_case_invalid")
        field = path[2]
        if field in {"id", "profile"}:
            raise AssistantError("history_identity_invalid")
        if field == "repo_path":
            raise AssistantError("history_repository_invalid")
        if field in {"base_sha", "head_sha"}:
            if field == "base_sha" and "allOf" in exc.absolute_schema_path:
                raise AssistantError("history_policy_commit_invalid")
            raise AssistantError("ci_revision_invalid")
        if ((field == "expected" and len(path) > 4 and path[4] == "paths"
             or field == "policy" and path[3:] == ["path"]) and exc.instance == ""):
            raise AssistantError("unsafe_path")
        if field in {"negative_control", "expected"}:
            raise AssistantError("history_identity_invalid" if len(path) > 4 and path[4] == "label" else "history_expected_invalid")
        if field == "policy":
            if len(path) > 3 and path[3] == "repo_path":
                raise AssistantError("history_policy_repository_invalid")
            if len(path) > 3 and path[3] == "commit":
                raise AssistantError("history_policy_commit_invalid")
            raise AssistantError("history_policy_invalid")
    if kind == "packet" and path:
        if path[0] == "changed_paths":
            if len(path) == 1 and exc.validator == "type":
                raise AssistantError("packet_schema_invalid")
            raise AssistantError("packet_file_count_limit" if exc.validator == "maxItems" else "packet_coverage_invalid")
        if path[0] == "allow_paths":
            raise AssistantError("packet_allow_paths_mismatch")
        if path[0] == "generated_paths":
            raise AssistantError("packet_generated_paths_mismatch")
        if path[0] == "profile":
            raise AssistantError("packet_profile_mismatch")
        if path[0] == "files" and len(path) > 2:
            if path[2].endswith("_mode"):
                raise AssistantError("packet_mode_invalid")
            if path[2].endswith("_hash"):
                raise AssistantError("file_integrity_failed")
        if path[0] == "packet_hash":
            raise AssistantError("packet_integrity_failed")
        if path[0] == "related" and not (path[1:] == ["rule_version"] and exc.instance is True):
            raise AssistantError("packet_related_invalid")

def validate_document_shape(document: dict, kind: str, error: str) -> None:
    try:
        _validator(kind).validate(document)
    except ValidationError as exc:
        _raise_shape_error(kind, exc)
        raise AssistantError(error) from exc
