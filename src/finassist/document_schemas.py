"""Export installed structural validators without changing runtime request hashes."""
from copy import deepcopy
from importlib.resources import files
import json

from .config_schema import SCHEMA_ID, configuration_schema

SCHEMA_FILES = {
    "config": "finassist.schema.json",
    "gate-policy": "gate-policy.schema.json",
    "ci-policy": "ci-policy.schema.json",
    "workflow-template": "workflow-template.schema.json",
    "packet": "packet.schema.json",
    "gate-report": "model-gate-report.schema.json",
    "gate-report-v1": "model-gate-report-v1.schema.json",
    "review-report": "review-report.schema.json",
    "review-response": "review-response.schema.json",
    "evaluation-suite": "evaluation-suite.schema.json",
    "history-suite": "history-suite.schema.json",
}

# Contract revisions are independent of package releases. Unversioned documents
# (review documents) have an explicit schema revision of their own.
SCHEMA_IDS = {
    "config": SCHEMA_ID,
    "gate-policy": "urn:finledgerpoli:schema:gate-policy:2",
    "ci-policy": "urn:finledgerpoli:schema:ci-policy:1",
    "workflow-template": "urn:finledgerpoli:schema:workflow-template:1",
    "packet": "urn:finledgerpoli:schema:packet:2",
    "gate-report": "urn:finledgerpoli:schema:gate-report:2",
    "gate-report-v1": "urn:finledgerpoli:schema:gate-report:1",
    "review-report": "urn:finledgerpoli:schema:review-report:1",
    "review-response": "urn:finledgerpoli:schema:review-response:1",
    "evaluation-suite": "urn:finledgerpoli:schema:evaluation-suite:1",
    "history-suite": "urn:finledgerpoli:schema:history-suite:1",
}


def document_schema(kind: str = "config") -> dict:
    if kind == "config":
        schema = configuration_schema()
    elif kind in {"gate-policy", "ci-policy"}:
        from . import ci_policy, model_policy
        schema = (model_policy if kind == "gate-policy" else ci_policy)._SCHEMA
    elif kind == "workflow-template":
        from .workflow import _TEMPLATE_SCHEMA
        schema = _TEMPLATE_SCHEMA
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
    if kind == "ci-policy":
        from .ci_policy import BRANCH_PATTERN, _REPOSITORY
        from .document_contracts import fullmatch_pattern
        # Editors register the separately published contracts by their stable IDs.
        # Runtime loaders retain their semantic checks, error codes and check order.
        schema["properties"]["config"] = {"$ref": SCHEMA_ID}
        schema["properties"]["workflow"] = {"$ref": SCHEMA_IDS["workflow-template"]}
        schema["properties"]["repository"].update(
            pattern=fullmatch_pattern(_REPOSITORY.pattern),
            **{"not": {"pattern": r"^(?:\.{1,2}/|[^/]+/\.{1,2}$)"}})
        schema["properties"]["base_branches"]["items"].update(
            pattern=fullmatch_pattern(BRANCH_PATTERN), **{"not": {"pattern": r"\.\."}})
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = SCHEMA_IDS[kind]
    return schema


def installed_document_schema(kind: str = "config") -> dict:
    """Print exactly the schema shipped in this installation, with no project IO."""
    return json.loads(files("finassist").joinpath("resources/" + SCHEMA_FILES[kind]).read_text(encoding="utf-8"))


def document_schema_text(kind: str = "config") -> str:
    return json.dumps(document_schema(kind), indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def add_schema_command(actions) -> None:
    schema = actions.add_parser("schema", help="Print an installed document schema offline")
    schema.add_argument("--kind", choices=tuple(SCHEMA_FILES), default="config")
