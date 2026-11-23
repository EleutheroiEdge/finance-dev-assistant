"""The "Upgrading from 0.10.0" guide section states what this release accepts: its schema identifiers and refusal
codes are read from the code, and its policy steps are run on the published 0.10.0 policy fixture. So the guide
cannot keep naming an identifier after a release changes it, and it cannot describe figure sources as anything but
what they are in this release: not available, and refused whatever else is set. Synthetic only."""

import copy
import json
from pathlib import Path
import re

import pytest

from finassist.config import load_config
from finassist.errors import AssistantError
from finassist.figure_source_entries import OPT_IN
from finassist.figure_sources import ROUND_RULE, SOURCE_RULE, source_rule
from finassist.guides import guide_text
from finassist.model_policy import check_draft

ROOT = Path(__file__).resolve().parent.parent
RESOURCES = ROOT / "src/finassist/resources"
HEADING = "## Upgrading from 0.10.0"
SETTINGS = {"model_review", "schema_version", "forbidden_token_sources", "forbidden_token_source_rule",
            "forbidden_token_round_figures", "forbidden_token_file", "forbidden_token_hashes", "decimal_mark", OPT_IN}


def _section():
    text = (ROOT / "docs/upgrading.md").read_text(encoding="utf-8")
    start = text.index(HEADING)
    following = re.search(r"^## ", text[start + len(HEADING):], re.M)
    return text[start:start + len(HEADING) + following.start()] if following else text[start:]


def _policy():
    return json.loads((ROOT / "examples/upgrade-fixtures/gate-policy-0.10.0.json").read_text(encoding="utf-8"))


def _with(document, **model):
    result = copy.deepcopy(document)
    result["model_review"].update(model)
    return result


_LAYOUT = {"path": "/synthetic/exports/positions.csv", "delimiter": ";", "decimal_mark": ","}


def _refused(document):
    with pytest.raises(AssistantError) as refused:
        check_draft(document)
    return refused.value.code


def _named_codes():
    return set(re.findall(r"`([a-z]+(?:_[a-z0-9]+)+)`", _section())) - (SETTINGS - {OPT_IN})


def test_the_packaged_guide_holds_the_section_unchanged():
    assert guide_text("upgrading") == (ROOT / "docs/upgrading.md").read_text(encoding="utf-8")
    assert _section().count("\n") > 20


def test_the_section_states_no_rule_number_and_no_layout():
    # No policy with sources is accepted in this release, so the section gives neither a rule to state nor a layout.
    assert not re.findall(r'"forbidden_token_source_rule": (\d+)', _section())
    assert '{"path":' not in _section()
    assert source_rule("list") == ROUND_RULE != SOURCE_RULE


def test_the_section_stays_true_once_this_release_is_published():
    # The packaged guide ships in the release it describes, so it never calls 0.10.0 the newest release.
    assert "newest" not in _section() and "latest" not in _section()
    assert "last release published to PyPI before this one" in _section()


def test_the_schema_identifiers_are_this_releases():
    current = {}
    for path in RESOURCES.glob("*.schema.json"):
        identifier = json.loads(path.read_text(encoding="utf-8")).get("$id", "")
        match = re.fullmatch(r"urn:finledgerpoli:schema:([a-z-]+):(\d+)", identifier)
        if match:
            current[match.group(1)] = identifier
    stated = re.findall(r"urn:finledgerpoli:schema:[a-z-]+:\d+", _section())
    assert {"config", "gate-policy", "ci-policy"} <= {name.split(":")[3] for name in stated}
    assert all(identifier == current[identifier.split(":")[3]] for identifier in stated)


def test_every_code_the_section_names_is_a_code_with_a_hint():
    hints = set()
    for path in RESOURCES.glob("hints-*.json"):
        hints |= set(json.loads(path.read_text(encoding="utf-8")))
    named = _named_codes() - set(_policy()["model_review"])
    assert {"gate_policy_source_rule_required", "state_location_moved", "forbidden_token_sources_experimental",
            "forbidden_token_round_figures_invalid", "forbidden_token_present"} <= named
    # Codes only a reader that is on could give are not named.
    assert not named & {"forbidden_token_source_layout_required", "forbidden_token_sources_experimental_in_use",
                        "forbidden_token_source_invalid", "forbidden_token_source_unscreenable"}
    assert named <= hints


def test_the_section_calls_figure_sources_not_available_and_never_complete():
    section = " ".join(_section().split())
    assert "not available in 0.12.0, and no setting turns them on" in section
    assert f'even beside `"{OPT_IN}": true`' in section
    assert "experimental" not in section.replace(OPT_IN, "") and "opt in" not in section
    # "complete" appears only to say the reader is not a complete screen.
    assert section.count("complete") == section.count("not a complete screen") >= 1
    for claim in ("lists every figure", "list every figure", "all figures", "every amount", "screens every"):
        assert claim not in section
    # The figures that must never be sent go in a list that does not depend on the reader.
    assert "`forbidden_token_file` or `forbidden_token_hashes`" in section


def test_the_published_policy_upgrades_unchanged():
    check_draft(_policy())


def test_a_policy_with_sources_follows_the_documented_steps():
    # A development build's policy, as it was or with every setting an earlier guide asked for: refused by the code the
    # section names. Removing the source settings, as step 2 says, is accepted; keeping a rule or the round-figure
    # setting without sources is refused with the code the section names for it.
    settings = {"forbidden_token_sources": [_LAYOUT], OPT_IN: True, "forbidden_token_source_rule": ROUND_RULE,
                "forbidden_token_round_figures": "list"}
    for document in (_with(_policy(), forbidden_token_sources=["/synthetic/exports/positions.csv"]),
                     _with(_policy(), **settings)):
        assert _refused(document) == "forbidden_token_sources_experimental"
    assert "forbidden_token_sources_experimental" in _named_codes()
    removed = _with(_policy(), **settings)
    for name in settings:
        removed["model_review"].pop(name)
    check_draft(removed)
    for kept in ("forbidden_token_source_rule", "forbidden_token_round_figures"):
        assert _refused(_with(removed, **{kept: settings[kept]})) == "gate_policy_source_rule_required"


def test_a_configuration_with_sources_follows_the_documented_steps():
    def load(document):
        return load_config(content=json.dumps(document).encode())

    for sources in ([_LAYOUT], ["~/exports/positions.csv"]):
        for opted in ({}, {OPT_IN: True}):
            with pytest.raises(AssistantError, match="^forbidden_token_sources_experimental$"):
                load({"forbidden_token_sources": sources, **opted})
    with pytest.raises(AssistantError, match="^forbidden_token_round_figures_invalid$"):
        load({"forbidden_token_round_figures": "list"})
    assert "forbidden_token_round_figures_invalid" in _named_codes()


def test_removing_the_sources_is_the_other_documented_path():
    development = _with(_policy(), forbidden_token_sources=["/synthetic/exports/positions.csv"],
                        forbidden_token_source_rule=SOURCE_RULE)
    removed = copy.deepcopy(development)
    for name in ("forbidden_token_sources", "forbidden_token_source_rule"):
        removed["model_review"].pop(name)
    check_draft(removed)
    assert "remove `forbidden_token_sources`" in " ".join(_section().split())


@pytest.mark.parametrize("model", [
    {"forbidden_token_source_rule": SOURCE_RULE},
    {"forbidden_token_source_rule": ROUND_RULE, "forbidden_token_round_figures": "list"},
    {"forbidden_token_round_figures": "skip"},
])
def test_a_rule_without_sources_is_refused(model):
    with pytest.raises(AssistantError) as refused:
        check_draft(_with(_policy(), **model))
    assert refused.value.code == "gate_policy_source_rule_required"


@pytest.mark.usefixtures("sources_available")
@pytest.mark.parametrize("model", [
    {"forbidden_token_sources": [_LAYOUT], "forbidden_token_source_rule": ROUND_RULE, OPT_IN: True},
    {"forbidden_token_sources": [_LAYOUT], "forbidden_token_source_rule": SOURCE_RULE,
     "forbidden_token_round_figures": "list", OPT_IN: True},
])
def test_where_sources_are_available_a_rule_that_disagrees_with_them_is_refused(model):
    with pytest.raises(AssistantError) as refused:
        check_draft(_with(_policy(), **model))
    assert refused.value.code == "gate_policy_source_rule_required"
