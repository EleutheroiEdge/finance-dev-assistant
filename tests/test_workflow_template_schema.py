"""Shared workflow fixtures exercise editor structure and the authoritative loader."""
from copy import deepcopy
from dataclasses import replace
from importlib.resources import files
import json

import pytest
from jsonschema import ValidationError

from finassist import ci_policy, workflow
from finassist.config import Config
from finassist.document_schemas import document_schema
from finassist.errors import AssistantError
from finassist.security import canonical, digest
from test_document_schemas import exported_validator


def template(count=1, path="docs/methodology.md"):
    return {
        "schema_version": 1, "name": "synthetic-workflow", "goal": "Check synthetic source",
        "methodology": [path],
        "requirements": [
            {"id": f"requirement-{n}", "recipe": f"Recipe-{n}", "methodology": [path]}
            for n in range(count)
        ],
        "steps": [
            {"id": f"step-{n}", "requirement": f"requirement-{n}",
             "depends_on": [f"step-{i}" for i in range(n)]}
            for n in range(count)
        ],
    }


def container(document, path):
    for key in path:
        document = document[key]
    return document


@pytest.mark.parametrize("count", [1, 64])
@pytest.mark.parametrize("long_fields", [False, True])
def test_workflow_structural_boundaries_are_accepted_by_both(count, long_fields):
    document = template(count)
    if long_fields:
        document["name"] = "a" * 64
        document["goal"] = "g" * 2000
        paths = ["docs/" + "m" * 504 + ".md", *[f"docs/m-{n}.md" for n in range(63)]]
        document["methodology"] = paths
        for n, requirement in enumerate(document["requirements"]):
            requirement.update(id=f"r{n:02d}" + "x" * 61, recipe=f"R{n:02d}" + "x" * 61,
                               methodology=paths[:])
            document["steps"][n]["requirement"] = requirement["id"]
        document["steps"][-1]["id"] = "s" * 64
    exported_validator("workflow-template").validate(document)
    assert workflow.parse_template(document, Config()).name == document["name"]


# Each closed object is tested both for a missing required field and for an
# unknown field; the same document is passed to the editor and runtime loader.
OBJECTS = [((), ("schema_version", "name", "goal", "methodology", "requirements", "steps")),
           (("requirements", 0), ("id", "recipe", "methodology")),
           (("steps", 0), ("id", "requirement", "depends_on"))]


@pytest.mark.parametrize("path,field", [
    (path, field) for path, fields in OBJECTS for field in (*fields, "unexpected")
])
def test_workflow_required_fields_and_closed_objects_agree(path, field):
    document = template()
    target = container(document, path)
    if field == "unexpected":
        target[field] = True
    else:
        del target[field]
    with pytest.raises(ValidationError):
        exported_validator("workflow-template").validate(document)
    with pytest.raises(AssistantError, match="workflow_template_invalid"):
        workflow.parse_template(document, Config())


@pytest.mark.parametrize("path,value", [
    (("schema_version",), value) for value in [0, 2, True, "1", None]
] + [
    (("name",), value) for value in ["", "A", "1name", "a" * 65, "name\n", "with space", None]
] + [
    (("goal",), value) for value in ["", "g" * 2001, 7]
] + [
    (("methodology",), value) for value in [
        [], ["docs/m.md"] * 2, [""], ["docs/" + "x" * 505 + ".md"], [1],
        [f"docs/m-{i}.md" for i in range(65)], "docs/m.md",
    ]
] + [
    (("requirements",), value) for value in [[], [None], [template()["requirements"][0]] * 65]
] + [
    (("steps",), value) for value in [[], [None], [template()["steps"][0]] * 65]
] + [
    (("requirements", 0, "methodology"), value)
    for value in [[], ["docs/m.md"] * 2, [""], ["x" * 513], [False],
                  [f"docs/m-{i}.md" for i in range(65)]]
] + [
    (path, value)
    for path in [("requirements", 0, "id"), ("steps", 0, "id"), ("steps", 0, "requirement")]
    for value in ["", "Uppercase", "a" * 65, "name\n", 5]
] + [
    (("requirements", 0, "recipe"), value) for value in ["", "_recipe", "R" * 65, "recipe\n", 4]
] + [
    (("steps", 0, "depends_on"), value)
    for value in ["step", ["step-0"] * 2, [""], ["Uppercase"], ["s" * 65], ["step\n"], [None],
                  [f"step-{i}" for i in range(65)]]
])
def test_workflow_structural_refusals_agree(path, value):
    document = template()
    container(document, path[:-1])[path[-1]] = value
    with pytest.raises(ValidationError):
        exported_validator("workflow-template").validate(document)
    with pytest.raises(AssistantError, match="workflow_template_invalid"):
        workflow.parse_template(document, Config())


@pytest.mark.parametrize("mutate,code", [
    (lambda t: t.update(schema_version=1.0), "workflow_template_invalid"),
    (lambda t: t.update(goal=" \n\t"), "workflow_template_invalid"),
    (lambda t: t["requirements"][1].update(id="requirement-0"), "workflow_duplicate_requirement"),
    (lambda t: t["requirements"][1].update(recipe="Recipe-0"), "workflow_duplicate_recipe"),
    (lambda t: t["requirements"][0].update(methodology=["docs/other.md"]),
     "workflow_methodology_reference_invalid"),
    (lambda t: t["methodology"].append("docs/unused.md"), "workflow_methodology_unused"),
    (lambda t: t["steps"][1].update(id="step-0"), "workflow_duplicate_step"),
    (lambda t: t["steps"].pop(), "workflow_step_coverage_invalid"),
    (lambda t: t["steps"][1].update(requirement="requirement-0"), "workflow_step_coverage_invalid"),
    (lambda t: t["steps"][0].update(depends_on=["unknown"]), "workflow_dependency_unknown"),
    (lambda t: t["steps"][0].update(depends_on=["step-1"]), "workflow_dependency_cycle"),
])
def test_workflow_semantic_checks_remain_runtime_checks(mutate, code):
    document = template(2)
    mutate(document)
    exported_validator("workflow-template").validate(document)
    with pytest.raises(AssistantError, match=code):
        workflow.parse_template(document, Config())


@pytest.mark.parametrize("config", [
    replace(Config(), allow_paths=("src/",)),
    replace(Config(), generated_paths=("docs/",)),
    replace(Config(), extra_sensitive_patterns=("Check synthetic source",)),
])
def test_workflow_schema_does_not_replace_scope_or_content_screening(config):
    document = template()
    exported_validator("workflow-template").validate(document)
    with pytest.raises(AssistantError):
        workflow.parse_template(document, config)


@pytest.mark.parametrize("invalid", [False, True])
def test_ci_policy_reference_rejects_a_malformed_nested_template(tmp_path, monkeypatch, invalid):
    document = json.loads(files("finassist").joinpath("resources/github-ci-policy.json").read_text())
    candidate = deepcopy(document)
    if invalid:
        candidate["workflow"]["steps"][0]["depends_on"] = ["bad\n"]
    raw = canonical(candidate)
    monkeypatch.setattr(ci_policy, "read_entry", lambda *args: (raw, "100644"))
    if invalid:
        with pytest.raises(ValidationError):
            exported_validator("ci-policy").validate(candidate)
        with pytest.raises(AssistantError, match="workflow_template_invalid"):
            ci_policy.load_ci_policy(tmp_path, "a" * 40, "docs/ci-policy.json", digest(raw))
    else:
        exported_validator("ci-policy").validate(candidate)
        loaded = ci_policy.load_ci_policy(tmp_path, "a" * 40, "docs/ci-policy.json", digest(raw))
        assert loaded.document == candidate and loaded.sha256 == digest(raw)


def test_export_preserves_the_loader_contract_and_its_raw_identity():
    document = template()
    before = canonical(document)
    original = deepcopy(workflow._TEMPLATE_SCHEMA)
    schema = document_schema("workflow-template")
    assert {k: v for k, v in schema.items() if k not in {"$id", "$schema"}} == original
    schema["properties"]["requirements"]["items"]["properties"].clear()
    assert workflow._TEMPLATE_SCHEMA == original
    workflow.parse_template(document, Config())
    assert canonical(document) == before
