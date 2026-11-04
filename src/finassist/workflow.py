"""Offline workflow contracts and preflight. Plans never authorize execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

import jsonschema

from .config import Config
from .errors import AssistantError
from .scope import read_entry, resolve, review_omissions, verify_packet
from .security import canonical, check_text, digest


def _object(properties: dict) -> dict:
    return {
        "type": "object", "properties": properties, "required": list(properties),
        "additionalProperties": False,
    }


def _array(items: dict, *, minimum: int = 1) -> dict:
    return {"type": "array", "items": items, "minItems": minimum, "maxItems": 64}


_IDENTIFIER = {"type": "string", "pattern": r"^[a-z][a-z0-9_-]{0,63}(?![\s\S])"}
_RECIPE = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}(?![\s\S])"}
_PATH = {"type": "string", "minLength": 1, "maxLength": 512}
_HASH = {"type": "string", "pattern": r"^[0-9a-f]{64}(?![\s\S])"}
_COMMIT = {"type": "string", "pattern": r"^(?:[0-9a-f]{40}|[0-9a-f]{64})(?![\s\S])"}
_TEMPLATE_SCHEMA = _object({
    "schema_version": {"type": "integer", "const": 1},
    "name": _IDENTIFIER,
    "goal": {"type": "string", "minLength": 1, "maxLength": 2000},
    "methodology": {**_array(_PATH), "uniqueItems": True},
    "requirements": _array(_object({
        "id": _IDENTIFIER, "recipe": _RECIPE,
        "methodology": {**_array(_PATH), "uniqueItems": True},
    })),
    "steps": _array(_object({
        "id": _IDENTIFIER, "requirement": _IDENTIFIER,
        "depends_on": {**_array(_IDENTIFIER, minimum=0), "uniqueItems": True},
    })),
})
_PLAN_SCHEMA = _object({
    "schema_version": {"type": "integer", "const": 1},
    "template": _TEMPLATE_SCHEMA,
    "template_hash": _HASH,
    "base": _COMMIT, "head": _COMMIT, "packet_hash": _HASH, "config_hash": _HASH,
    "methodology": _array(_object({
        "path": _PATH, "sha256": _HASH,
        "mode": {"enum": ["100644", "100755"]},
    })),
    "recipes": _array(_object({"recipe": _RECIPE, "argv_hash": _HASH})),
    "plan_hash": _HASH,
})


@dataclass(frozen=True)
class EvidenceRequirement:
    id: str
    recipe: str
    methodology: tuple[str, ...]


@dataclass(frozen=True)
class StepSpec:
    id: str
    requirement: str
    depends_on: tuple[str, ...]


@dataclass(frozen=True)
class WorkflowTemplate:
    schema_version: int
    name: str
    goal: str
    methodology: tuple[str, ...]
    requirements: tuple[EvidenceRequirement, ...]
    steps: tuple[StepSpec, ...]


@dataclass(frozen=True)
class MethodologyBinding:
    path: str
    sha256: str
    mode: str


@dataclass(frozen=True)
class RecipeBinding:
    recipe: str
    argv_hash: str


@dataclass(frozen=True)
class WorkflowPlan:
    schema_version: int
    template: WorkflowTemplate
    template_hash: str
    base: str
    head: str
    packet_hash: str
    config_hash: str
    methodology: tuple[MethodologyBinding, ...]
    recipes: tuple[RecipeBinding, ...]

    def document(self) -> dict:
        """Return JSON-native containers and bind the complete plan, without its hash."""
        import json

        value = json.loads(canonical(asdict(self)))
        return {**value, "plan_hash": digest(canonical(value))}


def _validate(document: dict, schema: dict, code: str) -> None:
    try:
        jsonschema.Draft202012Validator(schema).validate(document)
    except jsonschema.ValidationError as exc:
        raise AssistantError(code) from exc
    # JSON Schema treats 1.0 as an integer; wire versions deliberately do not.
    if type(document["schema_version"]) is not int:
        raise AssistantError(code)


def parse_template(document: dict, config: Config) -> WorkflowTemplate:
    _validate(document, _TEMPLATE_SCHEMA, "workflow_template_invalid")
    check_text(canonical(document).decode(), extra_patterns=config.extra_sensitive_patterns)
    if not document["goal"].strip():
        raise AssistantError("workflow_template_invalid")
    paths = set(document["methodology"])
    for path in paths:
        config.check_path(path)
        if not config.allows(path) or config.generated(path):
            raise AssistantError("workflow_methodology_outside_scope")
    requirements = tuple(
        EvidenceRequirement(item["id"], item["recipe"], tuple(item["methodology"]))
        for item in document["requirements"]
    )
    identifiers = {item.id for item in requirements}
    if len(identifiers) != len(requirements):
        raise AssistantError("workflow_duplicate_requirement")
    if len({item.recipe for item in requirements}) != len(requirements):
        raise AssistantError("workflow_duplicate_recipe")
    if any(not set(item.methodology) <= paths for item in requirements):
        raise AssistantError("workflow_methodology_reference_invalid")
    if set().union(*(set(item.methodology) for item in requirements)) != paths:
        raise AssistantError("workflow_methodology_unused")
    steps = tuple(
        StepSpec(item["id"], item["requirement"], tuple(item["depends_on"]))
        for item in document["steps"]
    )
    step_ids = {item.id for item in steps}
    if len(step_ids) != len(steps):
        raise AssistantError("workflow_duplicate_step")
    if len(steps) != len(requirements) or {item.requirement for item in steps} != identifiers:
        raise AssistantError("workflow_step_coverage_invalid")
    if any(not set(item.depends_on) <= step_ids for item in steps):
        raise AssistantError("workflow_dependency_unknown")
    visited: set[str] = set()
    while len(visited) < len(steps):
        eligible = {item.id for item in steps if set(item.depends_on) <= visited} - visited
        if not eligible:
            raise AssistantError("workflow_dependency_cycle")
        visited |= eligible
    return WorkflowTemplate(
        1, document["name"], document["goal"], tuple(document["methodology"]), requirements, steps
    )


def _recipe_bindings(template: WorkflowTemplate, config: Config) -> tuple[RecipeBinding, ...]:
    names = {item.recipe for item in template.requirements}
    if not names <= set(config.recipes):
        raise AssistantError("workflow_recipe_unconfigured")
    if not set(config.required_recipes) <= names:
        raise AssistantError("workflow_required_recipe_omitted")
    return tuple(RecipeBinding(name, digest(canonical(config.recipes[name]))) for name in sorted(names))


def _methodology_bindings(
    template: WorkflowTemplate, repo: Path, head: str, config: Config
) -> tuple[MethodologyBinding, ...]:
    bindings = []
    for path in template.methodology:
        content, mode = read_entry(repo, head, path, config.file_byte_limit(path), config)
        if content is None:
            raise AssistantError("workflow_methodology_missing")
        try:
            text = content.decode("utf-8")
        except UnicodeError as exc:
            raise AssistantError("workflow_methodology_not_text") from exc
        check_text(text, extra_patterns=config.extra_sensitive_patterns)
        if not text.strip():
            raise AssistantError("workflow_methodology_empty")
        bindings.append(MethodologyBinding(path, digest(content), mode))
    return tuple(bindings)


def build_workflow_plan(template: dict, packet: dict, repo: Path, config: Config) -> dict:
    config.validate()
    verify_packet(packet, config)
    if packet["schema_version"] != 2:
        raise AssistantError("workflow_packet_mode_evidence_missing")
    parsed = parse_template(template, config)
    return WorkflowPlan(
        1, parsed, digest(canonical(template)), packet["base"], packet["head"], packet["packet_hash"],
        digest(canonical(asdict(config))),
        _methodology_bindings(parsed, repo, packet["head"], config), _recipe_bindings(parsed, config),
    ).document()


def verify_workflow_plan(plan: dict, config: Config) -> WorkflowTemplate:
    """Check the wire contract and internal identity before trusting any bindings."""
    _validate(plan, _PLAN_SCHEMA, "workflow_plan_invalid")
    template = parse_template(plan["template"], config)
    if plan["template_hash"] != digest(canonical(plan["template"])) or plan["plan_hash"] != digest(
        canonical({key: value for key, value in plan.items() if key != "plan_hash"})
    ):
        raise AssistantError("workflow_plan_integrity_failed")
    if (
        [item["path"] for item in plan["methodology"]] != list(template.methodology)
        or [item["recipe"] for item in plan["recipes"]] != sorted(item.recipe for item in template.requirements)
    ):
        raise AssistantError("workflow_plan_bindings_invalid")
    return template


def preflight_workflow(plan: dict, packet: dict, repo: Path, config: Config) -> dict:
    """Revalidate current bindings without running recipes, models or candidate code."""
    config.validate()
    template = verify_workflow_plan(plan, config)
    blockers: set[str] = set()
    head = resolve(repo, "HEAD")
    if head != plan["head"]:
        blockers.add("workflow_head_changed")
    if digest(canonical(asdict(config))) != plan["config_hash"]:
        blockers.add("workflow_configuration_changed")
    else:
        verify_packet(packet, config)
        if packet["schema_version"] != 2:
            raise AssistantError("workflow_packet_mode_evidence_missing")
        if any(packet[key] != plan[key] for key in ("base", "head", "packet_hash")):
            blockers.add("workflow_packet_changed")
        if review_omissions(packet):
            blockers.add("workflow_coverage_incomplete")
        if not packet["changed_paths"]:
            blockers.add("workflow_changes_absent")
        recipes = [asdict(item) for item in _recipe_bindings(template, config)]
        if recipes != plan["recipes"]:
            blockers.add("workflow_recipe_changed")
        if head == plan["head"]:
            methodology = [asdict(item) for item in _methodology_bindings(template, repo, head, config)]
            if methodology != plan["methodology"]:
                blockers.add("workflow_methodology_changed")
    if resolve(repo, "HEAD") != head:
        blockers.add("workflow_head_changed")
    return {
        "schema_version": 1, "status": "blocked" if blockers else "preflight-passed",
        "plan_hash": plan["plan_hash"], "head": head, "blocking_reasons": sorted(blockers),
        "required_recipes": sorted(item.recipe for item in template.requirements),
        "execution_authorized": False, "merge_authority": False, "deployment_authority": False,
        "qualification": "Preflight checks identity and coverage only; no recipe or model was executed. "
        "Project methodology, check semantics and permissions still require review.",
    }


def verify_workflow_gate(
    plan: dict, packet: dict, review: dict, checks: list[dict], config: Config,
    head: str, state: Path, repo: Path,
) -> dict:
    """Apply workflow obligations through the existing audited evidence verifier."""
    from .readiness import verify_gate

    preflight = preflight_workflow(plan, packet, repo, config)
    if head != plan["head"] or head != preflight["head"]:
        preflight["blocking_reasons"] = sorted({*preflight["blocking_reasons"], "workflow_head_changed"})
        preflight["status"] = "blocked"
    if preflight["status"] == "blocked":
        return {
            **preflight, "head": head, "workflow_plan_hash": plan["plan_hash"],
            "policy_hash": digest(canonical(asdict(config))),
        }
    report = verify_gate(
        packet, review, checks, config, head, state,
        additional_recipes=tuple(preflight["required_recipes"]),
    )
    provided = {item["receipt"].get("recipe") for item in checks}
    missing = [
        item["id"] for item in plan["template"]["requirements"] if item["recipe"] not in provided
    ]
    report.update(workflow_plan_hash=plan["plan_hash"], workflow_missing_requirements=missing)
    return report
