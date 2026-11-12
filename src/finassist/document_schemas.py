"""Export installed structural validators without changing runtime request hashes."""
from copy import deepcopy
from importlib.resources import files
import json

from . import __version__
from .config_schema import configuration_schema

SCHEMA_FILES = {
    "config": "finassist.schema.json",
    "gate-policy": "gate-policy.schema.json",
    "ci-policy": "ci-policy.schema.json",
    "packet": "packet.schema.json",
    "gate-report": "gate-report.schema.json",
    "gate-report-v1": "gate-report-v1.schema.json",
    "review-report": "review-report.schema.json",
    "review-response": "review-response.schema.json",
    "evaluation-suite": "evaluation-suite.schema.json",
    "history-suite": "history-suite.schema.json",
}


def document_schema(kind: str = "config") -> dict:
    if kind == "config":
        schema = configuration_schema()
    elif kind in {"gate-policy", "ci-policy"}:
        from . import ci_policy, model_policy
        schema = (model_policy if kind == "gate-policy" else ci_policy)._SCHEMA
    elif kind == "review-report":
        from .review_report_schema import review_report_schema
        schema = review_report_schema()
    elif kind == "packet":
        from .packet_schema import packet_schema
        schema = packet_schema()
    elif kind in {"evaluation-suite", "history-suite"}:
        from .document_contracts import evaluation_suite_schema, history_suite_schema
        schema = (evaluation_suite_schema if kind == "evaluation-suite" else history_suite_schema)()
    else:
        resource = {"gate-report": "model-gate-report.schema.json",
                    "gate-report-v1": "model-gate-report-v1.schema.json",
                    "review-response": "review.schema.json"}[kind]
        schema = json.loads(files("finassist").joinpath("resources/" + resource).read_text(encoding="utf-8"))
    # In particular, review_schema is serialized into provider request hashes. Editor
    # metadata belongs to this export, never to the live request or submitted document.
    schema = deepcopy(schema)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = (f"https://raw.githubusercontent.com/EleutheroiEdge/finance-dev-assistant/"
                     f"v{__version__}/schemas/{SCHEMA_FILES[kind]}")
    return schema


def document_schema_text(kind: str = "config") -> str:
    return json.dumps(document_schema(kind), indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def add_schema_command(actions) -> None:
    schema = actions.add_parser("schema", help="Print an installed document schema offline")
    schema.add_argument("--kind", choices=tuple(SCHEMA_FILES), default="config")
