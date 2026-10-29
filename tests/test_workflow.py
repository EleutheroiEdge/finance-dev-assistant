"""Synthetic workflow contracts, identity invalidation and offline CLI behavior."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from conftest import command
from finassist.cli import main
from finassist.config import Config, save_config
from finassist.errors import AssistantError
from finassist.ledger import Ledger
from finassist.scope import build_packet
from finassist.security import canonical, digest
from finassist.workflow import build_workflow_plan, parse_template, preflight_workflow


@pytest.fixture
def workflow_case(repository):
    repo, base, _head = repository
    (repo / "docs").mkdir()
    (repo / "docs/cash-policy.md").write_text(
        "# Synthetic cash policy\nClosing cash equals opening cash plus deposits minus fees.\n",
        encoding="utf-8",
    )
    command(repo, "add", "docs/cash-policy.md")
    command(repo, "commit", "-m", "Add synthetic governing rule")
    head = command(repo, "rev-parse", "HEAD")
    config = replace(
        Config(), recipes={"unit": ["python", "-m", "pytest"], "cash": ["python", "check_cash.py"]},
        required_recipes=("unit",),
    )
    template = {
        "schema_version": 1, "name": "cash-validation", "goal": "Validate the synthetic cash rule",
        "methodology": ["docs/cash-policy.md"],
        "requirements": [
            {"id": "unit-tests", "recipe": "unit", "methodology": ["docs/cash-policy.md"]},
            {"id": "cash-conservation", "recipe": "cash", "methodology": ["docs/cash-policy.md"]},
        ],
        "steps": [
            {"id": "unit", "requirement": "unit-tests", "depends_on": []},
            {"id": "cash", "requirement": "cash-conservation", "depends_on": ["unit"]},
        ],
    }
    packet = build_packet(repo, base, head, config)
    return repo, config, template, packet


def test_plan_binds_committed_methodology_and_never_runs_candidate_code(workflow_case, monkeypatch):
    repo, config, template, packet = workflow_case

    def refuse(*args, **kwargs):
        pytest.fail("workflow planning must not run checks, call providers or use the network")

    monkeypatch.setattr("finassist.runner.run_recipe", refuse)
    monkeypatch.setattr("finassist.providers.invoke", refuse)
    monkeypatch.setattr("socket.create_connection", refuse)
    plan = build_workflow_plan(template, packet, repo, config)
    # A dirty local document cannot replace the exact committed methodology.
    (repo / "docs/cash-policy.md").write_text("Uncommitted rule", encoding="utf-8")
    report = preflight_workflow(plan, packet, repo, config)
    assert report["status"] == "preflight-passed"
    assert not report["execution_authorized"] and not report["merge_authority"]
    assert report["required_recipes"] == ["cash", "unit"]
    assert plan["methodology"][0]["sha256"] != digest(b"Uncommitted rule")
    assert build_workflow_plan(template, packet, repo, config) == plan


@pytest.mark.parametrize("version", [0, 2, True, 1.0, "1"])
def test_versions_fail_closed(workflow_case, version):
    repo, config, template, packet = workflow_case
    template["schema_version"] = version
    with pytest.raises(AssistantError, match="workflow_template_invalid"):
        build_workflow_plan(template, packet, repo, config)


@pytest.mark.parametrize(
    "mutation,code",
    [
        (lambda t: t.update(allow_network=True), "workflow_template_invalid"),
        (lambda t: t.update(name="cash\n"), "workflow_template_invalid"),
        (lambda t: t["steps"][0].update(argv=["unexpected"]), "workflow_template_invalid"),
        (lambda t: t["requirements"][0].update(required=False), "workflow_template_invalid"),
        (lambda t: t["requirements"].append(deepcopy(t["requirements"][0])), "workflow_duplicate_requirement"),
        (lambda t: t["requirements"][1].update(recipe="unit"), "workflow_duplicate_recipe"),
        (lambda t: t["requirements"][0].update(methodology=["docs/other.md"]),
         "workflow_methodology_reference_invalid"),
        (lambda t: t["methodology"].append("docs/unused.md"), "workflow_methodology_unused"),
        (lambda t: t["steps"][1].update(id="unit"), "workflow_duplicate_step"),
        (lambda t: t["steps"].pop(), "workflow_step_coverage_invalid"),
        (lambda t: t["steps"][1].update(requirement="unit-tests"), "workflow_step_coverage_invalid"),
        (lambda t: t["steps"][0].update(depends_on=["unknown"]), "workflow_dependency_unknown"),
        (lambda t: t["steps"][0].update(depends_on=["cash"]), "workflow_dependency_cycle"),
        (lambda t: t["steps"][0].update(depends_on=["unit"]), "workflow_dependency_cycle"),
        (lambda t: t["requirements"][1].update(recipe="unconfigured"), "workflow_recipe_unconfigured"),
    ],
)
def test_invalid_or_authority_expanding_templates_are_refused(workflow_case, mutation, code):
    repo, config, template, packet = workflow_case
    mutation(template)
    with pytest.raises(AssistantError, match=code):
        build_workflow_plan(template, packet, repo, config)


def test_workflow_cannot_drop_configured_obligations(workflow_case):
    repo, config, template, packet = workflow_case
    template["requirements"] = template["requirements"][1:]
    template["steps"] = [{"id": "cash", "requirement": "cash-conservation", "depends_on": []}]
    with pytest.raises(AssistantError, match="workflow_required_recipe_omitted"):
        build_workflow_plan(template, packet, repo, config)


@pytest.mark.parametrize("path", ["docs/missing.md", "../outside.md", ".env", "other/policy.md"])
def test_missing_or_unsafe_methodology_is_refused(workflow_case, path):
    repo, config, template, packet = workflow_case
    template["methodology"] = [path]
    for item in template["requirements"]:
        item["methodology"] = [path]
    with pytest.raises(AssistantError):
        build_workflow_plan(template, packet, repo, config)


def test_template_uses_defensive_immutable_collections(workflow_case):
    _repo, config, template, _packet = workflow_case
    parsed = parse_template(template, config)
    template["steps"][1]["depends_on"].clear()
    template["requirements"][0]["methodology"].clear()
    assert parsed.steps[1].depends_on == ("unit",)
    assert parsed.requirements[0].methodology == ("docs/cash-policy.md",)


def test_preflight_invalidates_changed_configuration_source_or_packet(workflow_case):
    repo, config, template, packet = workflow_case
    plan = build_workflow_plan(template, packet, repo, config)
    changed = replace(config, recipes={**config.recipes, "cash": ["python", "new_check.py"]})
    assert preflight_workflow(plan, packet, repo, changed)["blocking_reasons"] == [
        "workflow_configuration_changed"
    ]
    # A valid different review scope cannot inherit this plan's completion.
    other = build_packet(repo, packet["head"], packet["head"], config)
    reasons = preflight_workflow(plan, other, repo, config)["blocking_reasons"]
    assert "workflow_packet_changed" in reasons and "workflow_changes_absent" in reasons
    (repo / "docs/cash-policy.md").write_text("Changed committed methodology\n", encoding="utf-8")
    command(repo, "add", "docs/cash-policy.md")
    command(repo, "commit", "-m", "Change governing rule")
    assert "workflow_head_changed" in preflight_workflow(plan, packet, repo, config)["blocking_reasons"]


@pytest.mark.parametrize("target", ["goal", "recipe", "methodology", "schema", "unknown-field"])
def test_tampered_plans_are_not_preflight_success(workflow_case, target):
    repo, config, template, packet = workflow_case
    plan = build_workflow_plan(template, packet, repo, config)
    if target == "goal":
        plan["template"]["goal"] = "Other goal"
    elif target == "recipe":
        plan["recipes"][0]["argv_hash"] = "b" * 64
    elif target == "methodology":
        plan["methodology"][0]["sha256"] = "b" * 64
    elif target == "schema":
        plan["schema_version"] = 2
    else:
        plan["execution_authorized"] = True
    with pytest.raises(AssistantError):
        preflight_workflow(plan, packet, repo, config)


@pytest.mark.parametrize("binding,reason", [("recipes", "workflow_recipe_changed"),
                                           ("methodology", "workflow_methodology_changed")])
def test_self_consistent_but_wrong_bindings_are_checked_against_source(workflow_case, binding, reason):
    repo, config, template, packet = workflow_case
    plan = build_workflow_plan(template, packet, repo, config)
    plan[binding][0]["argv_hash" if binding == "recipes" else "sha256"] = "b" * 64
    plan["plan_hash"] = digest(canonical({key: value for key, value in plan.items() if key != "plan_hash"}))
    assert reason in preflight_workflow(plan, packet, repo, config)["blocking_reasons"]


def test_legacy_packet_remains_inspectable_but_cannot_supply_workflow_mode_evidence(workflow_case):
    from finassist.scope import verify_packet

    repo, config, template, packet = workflow_case
    packet["schema_version"] = 1
    for file in packet["files"]:
        file.pop("before_mode")
        file.pop("after_mode")
    packet["packet_hash"] = digest(canonical({key: value for key, value in packet.items() if key != "packet_hash"}))
    verify_packet(packet, config)
    with pytest.raises(AssistantError, match="workflow_packet_mode_evidence_missing"):
        build_workflow_plan(template, packet, repo, config)


def test_cli_roundtrip_exit_codes_private_outputs_and_metadata_audit(workflow_case, tmp_path, capsys):
    repo, config, template, packet = workflow_case
    paths = {name: tmp_path / (name + ".json") for name in ("config", "template", "packet", "plan")}
    save_config(paths["config"], config)
    for name, value in (("template", template), ("packet", packet)):
        paths[name].write_bytes(canonical(value))
    common = ["--config", str(paths["config"]), "workflow"]
    assert main([*common, "plan", "--repo", str(repo), "--packet", str(paths["packet"]),
                 "--template", str(paths["template"]), "--output", str(paths["plan"])]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "plan-bound"
    preflight = [*common, "preflight", "--repo", str(repo), "--packet", str(paths["packet"]),
                 "--plan", str(paths["plan"])]
    assert main(preflight) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "preflight-passed"
    config2 = replace(config, readiness_max_age_seconds=100)
    save_config(tmp_path / "changed.json", config2)
    preflight[1] = str(tmp_path / "changed.json")
    # Early policy invalidation must not copy an untrusted packet field into audit metadata.
    packet["head"] = "synthetic-unvalidated-payload"
    paths["packet"].write_bytes(canonical(packet))
    assert main(preflight) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
    with Ledger(repo / ".finassist/audit.sqlite") as ledger:
        ledger.verify()
        events = canonical(ledger.events()).decode()
    assert "workflow_plan_bound" in events and "workflow_preflight_evaluated" in events
    assert template["goal"] not in events and "cash-policy.md" not in events
    assert "synthetic-unvalidated-payload" not in events
    packet["head"] = command(repo, "rev-parse", "HEAD")
    paths["packet"].write_bytes(canonical(packet))
    bad = deepcopy(template)
    bad["grant_shell"] = True
    paths["template"].write_bytes(canonical(bad))
    assert main([*common, "plan", "--repo", str(repo), "--packet", str(paths["packet"]),
                 "--template", str(paths["template"]), "--output", str(tmp_path / "refused.json")]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "workflow_template_invalid"
    assert not (tmp_path / "refused.json").exists()
