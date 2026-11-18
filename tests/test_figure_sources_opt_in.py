"""Figure sources are experimental: off unless explicitly opted in, and then every source declares its layout.

A configuration or gate policy that lists a figure source without the opt-in is refused by name, never ignored, so
no one believes a source screens what it does not. Synthetic only."""

from dataclasses import replace
import json

import pytest

from conftest import command
from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration

from finassist.cli import main
from finassist.config import Config, config_hash, config_identity, load_config, save_config
from finassist.config_preflight import config_preflight
from finassist.error_hints import error_fields, hints
from finassist.errors import AssistantError
from finassist.figure_source_entries import OPT_IN, SourceFormat
from finassist.figure_sources import SOURCE_RULE
from finassist.health import config_warnings
from finassist.model_policy import check_draft
from finassist.scope import config_token_guard
from finassist.security import canonical

ONE_COLUMN = "12.345,67\n98.765,43\n"
LAYOUT = {"path": "/synthetic/positions.csv", "delimiter": None, "decimal_mark": ","}


def _config(document: dict):
    return load_config(content=json.dumps(document).encode())


def _source(tmp_path, text=ONE_COLUMN):
    path = tmp_path / "exports" / "positions.csv"
    path.parent.mkdir(exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def _layout(path):
    return {"path": path, "delimiter": None, "decimal_mark": ","}


@pytest.mark.parametrize("sources", [["/synthetic/positions.csv"], [LAYOUT]], ids=["path", "layout"])
def test_a_configuration_listing_sources_without_the_opt_in_is_refused_by_name(sources):
    with pytest.raises(AssistantError, match="^forbidden_token_sources_experimental$"):
        _config({"forbidden_token_sources": sources})
    with pytest.raises(AssistantError, match="^forbidden_token_sources_experimental$"):
        _config({"forbidden_token_sources": sources, OPT_IN: False})


@pytest.mark.parametrize("value", ["true", 1, None, "yes"])
def test_the_opt_in_is_true_and_nothing_else(value):
    with pytest.raises(AssistantError, match="^forbidden_token_sources_experimental$"):
        _config({"forbidden_token_sources": [LAYOUT], OPT_IN: value})


def test_the_refusal_says_experimental_names_the_limit_and_the_exact_setting():
    hint = error_fields("forbidden_token_sources_experimental")["hint"]
    assert "experimental" in hint and "miss" in hint
    assert '"forbidden_token_sources_experimental": true' in hint
    assert "delimiter" in hint and "decimal_mark" in hint
    entry = hints()["forbidden_token_sources_experimental"]
    assert "experimental" in entry["summary"]
    assert "layout" in error_fields("forbidden_token_source_layout_required")["hint"]


@pytest.mark.parametrize("sources", [["/synthetic/positions.csv"], [LAYOUT, "/synthetic/balances.csv"]],
                         ids=["path", "mixed"])
def test_opted_in_every_source_declares_its_layout(sources):
    with pytest.raises(AssistantError, match="^forbidden_token_source_layout_required$"):
        _config({"forbidden_token_sources": sources, OPT_IN: True})


def test_opted_in_with_layouts_the_configuration_loads_and_carries_the_opt_in():
    config = _config({"forbidden_token_sources": [LAYOUT], OPT_IN: True})
    assert config.forbidden_token_sources == (SourceFormat("/synthetic/positions.csv", None, ","),)
    assert config_identity(config)[OPT_IN] is True
    assert config.forbidden_token_rules[OPT_IN] is True


def test_a_configuration_without_sources_keeps_its_hash_and_ignores_nothing():
    assert OPT_IN not in config_identity(Config())
    assert config_hash(Config()) == "9354cf6ac3bf4e49201e9255169f76646236fb76fb960fc2413ab009ba49061c"
    assert not config_warnings(Config())


def test_a_screen_built_in_code_without_the_opt_in_is_refused(tmp_path):
    config = replace(Config(), forbidden_token_sources=(SourceFormat(_source(tmp_path), None, ","),))
    with pytest.raises(AssistantError, match="^forbidden_token_sources_experimental$"):
        config_token_guard(config, tmp_path)


def test_doctor_warns_while_the_reader_is_opted_in(tmp_path, capsys):
    path = tmp_path / "finassist.json"
    save_config(path, _config({"forbidden_token_sources": [LAYOUT], OPT_IN: True}))
    assert main(["--config", str(path), "doctor"]) == 0
    warnings = json.loads(capsys.readouterr().out)["config_warnings"]
    warning = next(row for row in warnings if row["code"] == "forbidden_token_sources_experimental_in_use")
    assert "experimental" in warning["hint"] and "miss" in warning["hint"]


def test_doctor_names_the_refusal_for_a_configuration_listing_sources(tmp_path, capsys):
    path = tmp_path / "finassist.json"
    path.write_text(json.dumps({"forbidden_token_sources": ["/synthetic/positions.csv"]}), encoding="utf-8")
    assert main(["--config", str(path), "doctor"]) == 2
    record = json.loads(capsys.readouterr().err)
    assert record["code"] == "forbidden_token_sources_experimental"
    assert OPT_IN in record["hint"]


def test_a_gate_policy_listing_sources_without_the_opt_in_stops_before_any_request(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[_layout(_source(tmp_path))],
                  forbidden_token_source_rule=SOURCE_RULE, **{OPT_IN: None})
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED"
    assert report["reasons"] == ["forbidden_token_sources_experimental"]
    assert report["spend"]["reserved_usd"] is None


def test_an_opted_in_gate_policy_with_a_bare_path_stops_before_any_request(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[_source(tmp_path)], forbidden_token_source_rule=SOURCE_RULE,
                  **{OPT_IN: True})
    report, calls = run(gate_case)
    assert not calls and report["reasons"] == ["forbidden_token_source_layout_required"]


def test_an_opted_in_gate_policy_with_layouts_screens_and_runs(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[_layout(_source(tmp_path))],
                  forbidden_token_source_rule=SOURCE_RULE, **{OPT_IN: True})
    report, calls = run(gate_case)
    assert calls and not any(reason.startswith(("gate_policy", "forbidden_token")) for reason in report["reasons"])
    repo = gate_case["repo"]
    (repo / "src/cash.py").write_text("def balance(opening, deposits):\n    return 12345.67\n", encoding="utf-8")
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Synthetic candidate with a listed figure")
    gate_case["head"] = command(repo, "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert not calls and "forbidden_token_present" in report["reasons"]


@pytest.mark.parametrize("changes,code", [
    ({}, "forbidden_token_sources_experimental"),
    ({OPT_IN: "true"}, "gate_policy_invalid"),
    ({OPT_IN: True, "forbidden_token_sources": ["~/exports/a.csv"]}, "forbidden_token_source_layout_required"),
])
def test_a_draft_gets_the_gate_s_code(changes, code):
    document = model_policy()
    document["model_review"].update(forbidden_token_sources=[_layout("~/exports/a.csv")],
                                    forbidden_token_source_rule=SOURCE_RULE)
    document["model_review"].update(changes)
    with pytest.raises(AssistantError, match=f"^{code}$"):
        check_draft(document)
    document["model_review"].update({OPT_IN: True, "forbidden_token_sources": [_layout("~/exports/a.csv")]})
    check_draft(document)


def _doctor_policy(gate_case, tmp_path, capsys, **changes):  # noqa: F811
    document = model_policy()
    document["model_review"].update(forbidden_token_source_rule=SOURCE_RULE, **changes)
    policy = tmp_path / "policy.json"
    policy.write_bytes(canonical(document))
    main(["doctor", "--policy-file", str(policy), "--repo", str(gate_case["repo"]), "--base", gate_case["base"],
          "--head", gate_case["head"]])
    return json.loads(capsys.readouterr().out)


def test_doctor_on_a_policy_names_the_refusal_and_reads_no_source(gate_case, tmp_path, capsys):  # noqa: F811
    report = _doctor_policy(gate_case, tmp_path, capsys,
                            forbidden_token_sources=[_layout("/synthetic/absent/positions.csv")])
    blockers = [item for item in report["blockers"] if item["code"] == "forbidden_token_sources_experimental"]
    assert blockers and blockers[0]["field"] == "/model_review/" + OPT_IN and OPT_IN in blockers[0]["hint"]
    assert not any(item["code"].startswith("forbidden_token_source_") for item in report["blockers"])


def test_doctor_on_an_opted_in_policy_warns(gate_case, tmp_path, capsys):  # noqa: F811
    report = _doctor_policy(gate_case, tmp_path, capsys,
                            forbidden_token_sources=[_layout("/synthetic/absent/positions.csv")], **{OPT_IN: True})
    assert not any(item["code"] == "forbidden_token_sources_experimental" for item in report["blockers"])
    warning = next(row for row in report["warnings"] if row["code"] == "forbidden_token_sources_experimental_in_use")
    assert "experimental" in warning["hint"]


def test_init_detect_proposes_no_figure_source(tmp_path, capsys):
    repo = tmp_path / "repository"
    repo.mkdir()
    command(repo, "init", "-q", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    (repo / "src").mkdir()
    (repo / "src/app.py").write_text("def total(a, b):\n    return a + b\n", encoding="utf-8")
    (repo / "tests/fixtures").mkdir(parents=True)
    (repo / "tests/fixtures/positions.csv").write_text("Name;Amount\nSYN-1;12.345,67\n", encoding="utf-8")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic layout")
    assert main(["--audit-dir", str(tmp_path / "audit"), "init", "--detect", "--repo", str(repo)]) == 0
    proposal = json.loads(capsys.readouterr().out)
    drafted = canonical({"config": proposal["config"], "policy": proposal["gate_policy_draft"]}).decode()
    assert "forbidden_token" not in drafted


_ABSENT = _layout("/synthetic/absent/positions.csv")
ROUTE_CASES = {  # name: (policy changes, the one code, the field doctor names)
    "no-rule": ({"forbidden_token_sources": [_ABSENT]}, "gate_policy_source_rule_required",
                "/model_review/forbidden_token_source_rule"),
    "no-rule-opted-in-bare-path": ({"forbidden_token_sources": [_ABSENT["path"]], OPT_IN: True},
                                   "gate_policy_source_rule_required", "/model_review/forbidden_token_source_rule"),
    "not-opted-in": ({"forbidden_token_sources": [_ABSENT], "forbidden_token_source_rule": SOURCE_RULE},
                     "forbidden_token_sources_experimental", "/model_review/" + OPT_IN),
    "opted-in-bare-path": ({"forbidden_token_sources": [_ABSENT["path"]], "forbidden_token_source_rule": SOURCE_RULE,
                            OPT_IN: True}, "forbidden_token_source_layout_required",
                           "/model_review/forbidden_token_sources"),
}


@pytest.mark.parametrize("name", sorted(ROUTE_CASES))
def test_the_draft_check_doctor_and_the_gate_give_one_code(name, gate_case, tmp_path, capsys):  # noqa: F811
    changes, code, field = ROUTE_CASES[name]
    document = model_policy()
    document["model_review"].update(changes)
    with pytest.raises(AssistantError, match=f"^{code}$"):
        check_draft(document)
    policy = tmp_path / "policy.json"
    policy.write_bytes(canonical(document))
    main(["doctor", "--policy-file", str(policy), "--repo", str(gate_case["repo"]), "--base", gate_case["base"],
          "--head", gate_case["head"]])
    blockers = json.loads(capsys.readouterr().out)["blockers"]
    assert [(item["code"], item["field"]) for item in blockers[:1]] == [(code, field)]
    change_policy(gate_case, **{OPT_IN: None, **changes})
    report, calls = run(gate_case)
    assert not calls and report["reasons"] == [code] and report["spend"]["reserved_usd"] is None


def test_the_range_preflight_refuses_an_unopted_screen_and_warns_an_opted_in_one(repository, tmp_path):
    repo, base, head = repository
    unopted = replace(Config(), forbidden_token_sources=(SourceFormat(_source(tmp_path), None, ","),))
    report = config_preflight(repo, base, head, unopted)
    assert report["status"] == "blocked"
    assert [item["code"] for item in report["blockers"]][:1] == ["forbidden_token_sources_experimental"]
    report = config_preflight(repo, base, head, replace(unopted, forbidden_token_sources_experimental=True))
    assert "forbidden_token_sources_experimental_in_use" in [item["code"] for item in report["warnings"]]
    assert report["figure_screen"]["listed"] == 2
