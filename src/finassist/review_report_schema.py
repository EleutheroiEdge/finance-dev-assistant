"""Structural schema for the saved offline or model review report."""
from .document_contracts import array_schema, object_schema


def review_report_schema() -> dict:
    from .config import PROVIDERS
    from .review import review_schema
    from .scope import WITHHELD_REASON

    text = {"type": "string"}
    revision = {"type": "string", "pattern": r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"}
    sha = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
    triage = object_schema({
        "risks": array_schema(text), "recommended_checks": array_schema(text),
        "coverage_complete": {"type": "boolean"}, "changes_present": {"type": "boolean"},
        "next_action": text,
    })
    common = {
        "head": revision, "packet_hash": sha, "triage": triage,
        "qualification": text, "merge_authority": {"const": False},
        "withheld": object_schema({"count": {"type": "integer", "minimum": 1, "maximum": 2000},
                                   "reason": {"const": WITHHELD_REASON}}),
    }
    offline = {**common, "status": {"const": "offline-analysis"}, "provider": {"const": "offline"},
               "findings": {"type": "array", "maxItems": 0}}
    model = {**common, "status": {"enum": ["partial-review", "findings", "no-findings-reported"]},
             "base": revision, "provider": {"enum": sorted(PROVIDERS - {"offline"})},
             "model": text, "config_hash": sha, "review": review_schema(),
             "reservation": {"type": "string", "minLength": 1},
             "omitted": array_schema(object_schema({"path": text, "reason": text})), "receipt": sha}
    return {"oneOf": [object_schema(offline, offline.keys() - {"withheld"}),
                       object_schema(model, model.keys() - {"withheld"})]}
