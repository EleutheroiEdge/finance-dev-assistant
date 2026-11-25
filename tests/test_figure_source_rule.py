"""The source rule: which rules decide what a figure source lists is part of a configuration's identity and of a gate
policy's reviewed bytes, so the same settings can never silently mean another list. Synthetic only."""

import json

import pytest

from figure_source_cases import layout, write_source
from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration

from finassist.cli import main
from finassist.config import Config, config_hash, config_identity, load_config
from finassist.errors import AssistantError
from finassist.figure_source_entries import OPT_IN
from finassist.figure_sources import ROUND_RULE, SOURCE_RULE
from finassist.model_policy import check_draft
from finassist.security import canonical

# The reader's own tests: figure sources are not available in this release, so they turn them on, as only
# code can.
pytestmark = pytest.mark.usefixtures("sources_available")

SOURCE = "Name;Amount\nA;12.345,67\n"
RULE = "forbidden_token_source_rule"
RETIRED = list(range(2, SOURCE_RULE))  # the rules of builds that read a source in other ways


def _source(tmp_path):
    return layout(write_source(tmp_path, SOURCE), text_columns=["Name"])


def test_a_configuration_with_sources_carries_the_rule_and_one_without_keeps_its_hash():
    with_sources = load_config(content=json.dumps({OPT_IN: True, "forbidden_token_sources": [
        layout("/synthetic/positions.csv")]}).encode())
    assert config_identity(with_sources)[RULE] == SOURCE_RULE == 28
    assert RULE not in config_identity(Config())
    # The hash of a configuration without sources is the one every earlier release computed.
    assert config_hash(Config()) == "9354cf6ac3bf4e49201e9255169f76646236fb76fb960fc2413ab009ba49061c"


def test_no_setting_can_choose_another_rule():
    with pytest.raises(AssistantError):
        load_config(content=json.dumps({"forbidden_token_sources": [layout("/synthetic/positions.csv")], OPT_IN: True,
                                        RULE: 1}).encode())


@pytest.mark.parametrize("changes", [
    {"sources": True}, {"sources": True, RULE: 1}, *[{"sources": True, RULE: rule} for rule in RETIRED],
    {"sources": True, RULE: ROUND_RULE}, {"sources": True, RULE: ROUND_RULE + 1}, {"sources": True, RULE: True},
    {"sources": True, RULE: float(SOURCE_RULE)}, {"sources": True, RULE: str(SOURCE_RULE)}, {RULE: SOURCE_RULE},
], ids=["missing", "old", *[f"retired-{rule}" for rule in RETIRED], "list-rule-without-list", "unknown", "bool",
        "float", "text", "without-sources"])
def test_a_policy_whose_rule_disagrees_with_its_sources_stops_before_any_request(gate_case, tmp_path, changes):  # noqa: F811
    changes = dict(changes)
    if changes.pop("sources", False):
        changes["forbidden_token_sources"] = [_source(tmp_path)]
    change_policy(gate_case, **changes)
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED"
    assert report["reasons"] == ["gate_policy_source_rule_required"]
    assert report["spend"]["reserved_usd"] is None


def test_the_rules_of_the_earlier_readers_are_retired():
    assert RETIRED[-2:] == [26, 27] and (SOURCE_RULE, ROUND_RULE) == (28, 29)


def test_a_policy_stating_the_rule_with_its_sources_runs(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[_source(tmp_path)], forbidden_token_source_rule=SOURCE_RULE)
    report, calls = run(gate_case)
    assert calls and not any(reason.startswith(("gate_policy", "forbidden_token")) for reason in report["reasons"])


def test_doctor_names_the_rule_and_reads_no_source(gate_case, tmp_path, capsys):  # noqa: F811
    document = model_policy()
    document["model_review"]["forbidden_token_sources"] = [layout("/synthetic/absent/positions.csv")]
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


@pytest.mark.parametrize("rule", [None, 1, *RETIRED, str(SOURCE_RULE), float(SOURCE_RULE)],
                         ids=["missing", "old", *[f"retired-{rule}" for rule in RETIRED], "text", "float"])
def test_a_draft_with_sources_states_the_rule_and_gets_the_gate_s_code(rule):
    # The same code as the gate and doctor give, whichever check would also catch it.
    document = model_policy()
    document["model_review"]["forbidden_token_sources"] = [layout("~/exports/a.csv")]
    document["model_review"]["forbidden_token_sources_experimental"] = True
    if rule is not None:
        document["model_review"]["forbidden_token_source_rule"] = rule
    with pytest.raises(AssistantError, match="^gate_policy_source_rule_required$"):
        check_draft(document)
    document["model_review"]["forbidden_token_source_rule"] = SOURCE_RULE
    check_draft(document)
