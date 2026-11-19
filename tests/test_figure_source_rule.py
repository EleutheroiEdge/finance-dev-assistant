"""The source rule: which rules decide what a figure source lists is part of a configuration's identity and of a gate
policy's reviewed bytes, so the same settings can never silently mean another list. Synthetic only."""

import json

import pytest

from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration

from finassist.cli import main
from finassist.config import Config, config_hash, config_identity, load_config
from finassist.errors import AssistantError
from finassist.figure_source_entries import OPT_IN
from finassist.figure_sources import SOURCE_RULE
from finassist.model_policy import check_draft
from finassist.security import canonical

SOURCE = "Name;Amount\nA;12.345,67\n"


def _source(tmp_path):
    path = tmp_path / "exports" / "positions.csv"
    path.parent.mkdir(exist_ok=True)
    path.write_text(SOURCE, encoding="utf-8")
    return str(path)


def test_a_configuration_with_sources_carries_the_rule_and_one_without_keeps_its_hash():
    with_sources = load_config(content=b'{"forbidden_token_sources_experimental": true, "forbidden_token_sources": '
                                       b'[{"path": "/synthetic/positions.csv", "delimiter": ";", "decimal_mark": ","}]}')
    assert config_identity(with_sources)["forbidden_token_source_rule"] == SOURCE_RULE == 26
    assert "forbidden_token_source_rule" not in config_identity(Config())
    # The hash of a configuration without sources is the one every earlier release computed.
    assert config_hash(Config()) == "9354cf6ac3bf4e49201e9255169f76646236fb76fb960fc2413ab009ba49061c"


def test_no_setting_can_choose_another_rule():
    with pytest.raises(AssistantError):
        load_config(content=b'{"forbidden_token_sources": ["/synthetic/positions.csv"], '
                            b'"forbidden_token_source_rule": 1}')


@pytest.mark.parametrize("changes", [
    {"sources": True},
    {"sources": True, "forbidden_token_source_rule": 1},
    {"sources": True, "forbidden_token_source_rule": 2},
    {"sources": True, "forbidden_token_source_rule": 3},
    {"sources": True, "forbidden_token_source_rule": 4},
    {"sources": True, "forbidden_token_source_rule": 5},
    {"sources": True, "forbidden_token_source_rule": 6},
    {"sources": True, "forbidden_token_source_rule": 7},
    {"sources": True, "forbidden_token_source_rule": 8},
    {"sources": True, "forbidden_token_source_rule": 9},
    {"sources": True, "forbidden_token_source_rule": 10},
    {"sources": True, "forbidden_token_source_rule": 11},
    {"sources": True, "forbidden_token_source_rule": 12},
    {"sources": True, "forbidden_token_source_rule": 13},
    {"sources": True, "forbidden_token_source_rule": 14},
    {"sources": True, "forbidden_token_source_rule": 15},
    {"sources": True, "forbidden_token_source_rule": 16},
    {"sources": True, "forbidden_token_source_rule": 17},
    {"sources": True, "forbidden_token_source_rule": 18},
    {"sources": True, "forbidden_token_source_rule": 19},
    {"sources": True, "forbidden_token_source_rule": 20},
    {"sources": True, "forbidden_token_source_rule": 21},
    {"sources": True, "forbidden_token_source_rule": 22},
    {"sources": True, "forbidden_token_source_rule": 23},
    {"sources": True, "forbidden_token_source_rule": 24},
    {"sources": True, "forbidden_token_source_rule": 25},
    {"sources": True, "forbidden_token_source_rule": 27},
    {"sources": True, "forbidden_token_source_rule": 28},
    {"sources": True, "forbidden_token_source_rule": True},
    {"sources": True, "forbidden_token_source_rule": 26.0},
    {"sources": True, "forbidden_token_source_rule": "26"},
    {"forbidden_token_source_rule": 26},
], ids=["missing", "old", "retired-2", "retired-3", "retired-4", "retired-5", "retired-6", "retired-7", "retired-8",
        "retired-9", "retired-10", "retired-11", "retired-12", "retired-13", "retired-14", "retired-15", "retired-16",
        "retired-17", "retired-18", "retired-19", "retired-20", "retired-21", "retired-22", "retired-23",
        "retired-24", "retired-25", "list-rule-without-list", "unknown", "bool", "float", "text", "without-sources"])
def test_a_policy_whose_rule_disagrees_with_its_sources_stops_before_any_request(gate_case, tmp_path, changes):  # noqa: F811
    changes = dict(changes)
    if changes.pop("sources", False):
        changes["forbidden_token_sources"] = [_source(tmp_path)]
    change_policy(gate_case, **changes)
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED"
    assert report["reasons"] == ["gate_policy_source_rule_required"]
    assert report["spend"]["reserved_usd"] is None


def test_a_policy_stating_the_rule_with_its_sources_runs(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[{"path": _source(tmp_path), "delimiter": ";", "decimal_mark": ","}],
                  forbidden_token_source_rule=SOURCE_RULE)
    report, calls = run(gate_case)
    assert calls and not any(reason.startswith(("gate_policy", "forbidden_token")) for reason in report["reasons"])


def test_doctor_names_the_rule_and_reads_no_source(gate_case, tmp_path, capsys):  # noqa: F811
    document = model_policy()
    document["model_review"]["forbidden_token_sources"] = ["/synthetic/absent/positions.csv"]
    document["model_review"][OPT_IN] = True  # opted in, so that only the rule is wrong
    policy = tmp_path / "policy.json"
    policy.write_bytes(canonical(document))
    main(["doctor", "--policy-file", str(policy), "--repo", str(gate_case["repo"]), "--base", gate_case["base"],
          "--head", gate_case["head"]])
    report = json.loads(capsys.readouterr().out)
    blockers = [item for item in report["blockers"] if item["code"] == "gate_policy_source_rule_required"]
    assert blockers and blockers[0]["field"] == "/model_review/forbidden_token_source_rule"
    assert blockers[0]["allowed"] == {"const": SOURCE_RULE}
    assert not any(item["code"].startswith("forbidden_token") for item in report["blockers"])


@pytest.mark.parametrize("rule", [None, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                  20, 21, 22, 23, 24, 25, "26", 26.0],
                         ids=["missing", "old", "retired-2", "retired-3", "retired-4", "retired-5", "retired-6",
                              "retired-7", "retired-8", "retired-9", "retired-10", "retired-11", "retired-12",
                              "retired-13", "retired-14", "retired-15", "retired-16", "retired-17", "retired-18",
                              "retired-19", "retired-20", "retired-21", "retired-22", "retired-23", "retired-24",
                              "retired-25", "text", "float"])
def test_a_draft_with_sources_states_the_rule_and_gets_the_gate_s_code(rule):
    # The same code as the gate and doctor give, whichever check would also catch it.
    document = model_policy()
    document["model_review"]["forbidden_token_sources"] = [{"path": "~/exports/a.csv", "delimiter": ";",
                                                            "decimal_mark": ","}]
    document["model_review"]["forbidden_token_sources_experimental"] = True
    if rule is not None:
        document["model_review"]["forbidden_token_source_rule"] = rule
    with pytest.raises(AssistantError, match="^gate_policy_source_rule_required$"):
        check_draft(document)
    document["model_review"]["forbidden_token_source_rule"] = SOURCE_RULE
    check_draft(document)
