"""Structural schema for the saved offline or model review report."""
from .document_contracts import array_schema, fullmatch_pattern, object_schema


def review_report_schema() -> dict:
    from .config import PROVIDERS
    from .review import FINDINGS_STATUS, NO_FINDINGS_STATUS, OFFLINE_STATUS, PARTIAL_STATUS, review_schema
    from .scope import WITHHELD_REASON, MAX_CHANGED_PATHS, REVISION_PATTERN, SHA256_PATTERN

    response = review_schema()
    response.pop("$schema", None)  # A subschema has no dialect of its own.
    text = {"type": "string"}
    revision = {"type": "string", "pattern": fullmatch_pattern(REVISION_PATTERN)}
    sha = {"type": "string", "pattern": fullmatch_pattern(SHA256_PATTERN)}
    triage = object_schema({
        "risks": array_schema(text), "recommended_checks": array_schema(text),
        "coverage_complete": {"type": "boolean"}, "changes_present": {"type": "boolean"},
        "next_action": text,
    })
    common = {
        "head": revision, "packet_hash": sha, "triage": triage,
        "qualification": text, "merge_authority": {"const": False},
        "withheld": object_schema({"count": {"type": "integer", "minimum": 1, "maximum": MAX_CHANGED_PATHS},
                                   "reason": {"const": WITHHELD_REASON}}),
    }
    offline = {**common, "status": {"const": OFFLINE_STATUS}, "provider": {"const": "offline"},
               "findings": {"type": "array", "maxItems": 0}}
    model = {**common, "status": {"enum": [PARTIAL_STATUS, FINDINGS_STATUS, NO_FINDINGS_STATUS]},
             "base": revision, "provider": {"enum": sorted(PROVIDERS - {"offline"})},
             "model": text, "config_hash": sha, "review": response,
             "reservation": {"type": "string", "minLength": 1},
             "omitted": array_schema(object_schema({"path": text, "reason": text})), "receipt": sha}
    return {"oneOf": [object_schema(offline, offline.keys() - {"withheld"}),
                       object_schema(model, model.keys() - {"withheld"})]}
