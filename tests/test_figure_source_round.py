"""Round figures: a source's 347300.00, which the digit minimum leaves out, is listed only when
forbidden_token_round_figures is "list", read by source rule 29 and matched by its exact value. Synthetic only."""

import json

import pytest

from conftest import command
from figure_source_cases import layout, load, refused, write_source
from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration

from finassist.cli import main
from finassist.config import Config, config_hash, config_identity, load_config
from finassist.errors import AssistantError
from finassist.figure_source_entries import OPT_IN
from finassist.figure_sources import ROUND_LIST, ROUND_RULE, SOURCE_RULE, _round_figure
from finassist.forbidden_tokens import load_token_snapshot
from finassist.security import canonical

# The reader's own tests: figure sources are not available in this release, so they turn them on, as only
# code can.
pytestmark = pytest.mark.usefixtures("sources_available")

SOURCE = "Name;Amount\nA;347.300,00\nB;12.345,67\n"
LIST = {"forbidden_token_round_figures": ROUND_LIST}
SKIP = {"forbidden_token_round_figures": "skip"}
REQUIRED = "gate_policy_source_rule_required"
RULE = "forbidden_token_source_rule"
ABSENT = layout("/synthetic/a.csv")


def _entry(tmp_path, text=SOURCE):
    return layout(write_source(tmp_path, text), text_columns=["Name"])


def _snapshot(tmp_path, text=SOURCE, parsed=None, **rules):
    return load(_entry(tmp_path, text), parsed=parsed, **rules)


@pytest.mark.parametrize("whole,fraction,min_digits,expected", [
    ("347300", "", 5, True), ("3473000", "", 5, True), ("100200", "", 5, True),
    ("250000", "", 5, False), ("1250000", "", 5, False), ("12", "", 5, False),
    ("347300", "", 4, False), ("0", "", 5, False), ("20300000", "", 5, False), ("3473", "", 5, False),
], ids=["347300", "3473000", "100200", "two-significant", "three-significant", "small", "already-a-figure", "zero",
        "three-significant-eight-digits", "too-small"])
def test_a_round_figure_is_large_enough_and_has_four_significant_digits(whole, fraction, min_digits, expected):
    assert _round_figure(whole, fraction, min_digits) is expected


@pytest.mark.parametrize("match", ["value", "digits"])
def test_listed_round_figures_are_refused_by_value_and_only_by_value(tmp_path, match):
    listed = _snapshot(tmp_path, forbidden_token_match=match, **LIST)
    assert listed.round_figures == 1
    for spelling in ("347300", "347300.00", "347,300.00", "3.473e5", "-347300"):
        assert refused(spelling, listed), spelling
    for other in ("3473", "3.473", "3473000", "34730"):
        assert not refused(other, listed), other
    assert refused("12345.67", listed)


def test_skipped_round_figures_are_not_listed_as_before(tmp_path):
    for snapshot in (_snapshot(tmp_path), _snapshot(tmp_path, **SKIP)):
        assert snapshot.round_figures == 0 and snapshot.listed == 1
        assert not refused("347300", snapshot) and refused("12345.67", snapshot)


def test_a_source_of_round_figures_only_reads_under_list_and_is_refused_under_skip(tmp_path):
    text = "Name;Amount\nA;347.300,00\nB;1.002.000,00\n"
    assert _snapshot(tmp_path, text, **LIST).round_figures == 2
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _snapshot(tmp_path, text)


def test_a_cached_parse_is_never_reused_under_the_other_setting(tmp_path):
    parsed = {}
    assert _snapshot(tmp_path, parsed=parsed).round_figures == 0
    assert _snapshot(tmp_path, parsed=parsed, **LIST).round_figures == 1
    assert _snapshot(tmp_path, parsed=parsed).round_figures == 0 and len(parsed) == 2


@pytest.mark.parametrize("rules", [
    {"forbidden_token_round_figures": "list"},
    {"forbidden_token_round_figures": "yes", "forbidden_token_sources": [ABSENT]},
    {"forbidden_token_round_figures": True, "forbidden_token_sources": [ABSENT]},
], ids=["list-without-sources", "unknown", "bool"])
def test_a_wrong_round_setting_is_refused_before_any_source_is_read(rules):
    with pytest.raises(AssistantError, match="^forbidden_token_round_figures_invalid$"):
        load_token_snapshot(rules, ())


def test_the_configuration_binds_the_setting_and_its_rule():
    sources = {OPT_IN: True, "forbidden_token_sources": [layout("/synthetic/positions.csv")]}
    skip = load_config(content=json.dumps(sources).encode())
    explicit = load_config(content=json.dumps({**sources, **SKIP}).encode())
    listed = load_config(content=json.dumps({**sources, **LIST}).encode())
    assert config_hash(skip) == config_hash(explicit)  # skip is the default and is left out
    assert config_identity(skip)[RULE] == SOURCE_RULE
    assert config_identity(listed)[RULE] == ROUND_RULE == 29
    assert config_identity(listed)["forbidden_token_round_figures"] == ROUND_LIST
    assert config_hash(listed) != config_hash(skip)
    assert config_hash(Config()) == "9354cf6ac3bf4e49201e9255169f76646236fb76fb960fc2413ab009ba49061c"
    with pytest.raises(AssistantError, match="^forbidden_token_round_figures_invalid$"):
        load_config(content=b'{"forbidden_token_round_figures": "list"}')


_ODD = [rule for rule in range(3, SOURCE_RULE) if rule % 2]
_EVEN = [rule for rule in range(2, SOURCE_RULE) if not rule % 2]


@pytest.mark.parametrize("changes,reason", [
    ({**LIST, RULE: SOURCE_RULE}, REQUIRED), ({**SKIP, RULE: ROUND_RULE}, REQUIRED), ({RULE: ROUND_RULE}, REQUIRED),
    (dict(LIST), REQUIRED), *[({**LIST, RULE: rule}, REQUIRED) for rule in _ODD],
    *[({RULE: rule}, REQUIRED) for rule in _EVEN],
    ({"forbidden_token_round_figures": "yes", RULE: SOURCE_RULE}, "gate_policy_invalid"),
], ids=["list-under-the-skip-rule", "skip-under-the-list-rule", "list-rule-alone", "list-without-rule",
        *[f"list-under-retired-{rule}" for rule in _ODD], *[f"retired-{rule}" for rule in _EVEN], "unknown-setting"])
def test_a_policy_whose_round_setting_and_rule_disagree_stops_before_any_request(gate_case, tmp_path, changes,  # noqa: F811
                                                                              reason):
    change_policy(gate_case, forbidden_token_sources=[_entry(tmp_path)], **changes)
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and report["reasons"] == [reason]
    assert report["spend"]["reserved_usd"] is None


def test_a_round_setting_without_sources_stops_the_gate(gate_case):  # noqa: F811
    change_policy(gate_case, **LIST)
    report, calls = run(gate_case)
    assert not calls and report["reasons"] == ["gate_policy_source_rule_required"]


def test_a_listed_round_figure_in_a_change_stops_the_gate_before_any_request(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[_entry(tmp_path)], **LIST, forbidden_token_source_rule=ROUND_RULE)
    (gate_case["repo"] / "src/cash.py").write_text("RESERVE = 347300  # synthetic\n", encoding="utf-8", newline="\n")
    command(gate_case["repo"], "commit", "-q", "-am", "Synthetic change with a round figure")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and "forbidden_token_present" in report["reasons"]
    assert report["spend"]["reserved_usd"] is None


def test_doctor_names_the_list_rule_for_a_policy_listing_round_figures(gate_case, tmp_path, capsys):  # noqa: F811
    document = model_policy()
    document["model_review"].update(forbidden_token_sources=[layout("/synthetic/absent/positions.csv")],
                                    forbidden_token_source_rule=SOURCE_RULE, **LIST, **{OPT_IN: True})  # only the rule
    policy = tmp_path / "policy.json"
    policy.write_bytes(canonical(document))
    main(["doctor", "--policy-file", str(policy), "--repo", str(gate_case["repo"]), "--base", gate_case["base"],
          "--head", gate_case["head"]])
    report = json.loads(capsys.readouterr().out)
    blocker = next(item for item in report["blockers"] if item["code"] == "gate_policy_source_rule_required")
    assert blocker["allowed"] == {"const": ROUND_RULE}
    assert not any(item["code"].startswith("forbidden_token") for item in report["blockers"])
