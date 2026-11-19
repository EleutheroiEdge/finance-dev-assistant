"""The "Upgrading from 0.10.0" guide section states what this release accepts: its rule numbers, schema identifiers
and refusal codes are read from the code, and its policy steps are run on the published 0.10.0 policy fixture. So the
guide cannot keep naming a rule or an identifier after a release changes it, and it cannot describe figure sources
as anything but the experimental reader they are in this release. Synthetic only."""

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
from finassist.health import config_warnings
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


def _layout():
    # The layout object the section gives, read from the section itself.
    found = re.findall(r'`(\{"path": [^`]+\})`', _section())
    assert len(found) == 1
    return json.loads(found[0])


def _refused(document):
    with pytest.raises(AssistantError) as refused:
        check_draft(document)
    return refused.value.code


def _named_codes():
    return set(re.findall(r"`([a-z]+(?:_[a-z0-9]+)+)`", _section())) - (SETTINGS - {OPT_IN})


def test_the_packaged_guide_holds_the_section_unchanged():
    assert guide_text("upgrading") == (ROOT / "docs/upgrading.md").read_text(encoding="utf-8")
    assert _section().count("\n") > 20


def test_the_rule_numbers_are_this_releases():
    # In the order the steps give them: the rule alone, then the rule that goes with "list".
    stated = [int(number) for number in re.findall(r'"forbidden_token_source_rule": (\d+)', _section())]
    assert stated == [SOURCE_RULE, ROUND_RULE]
    assert source_rule("list") == ROUND_RULE != SOURCE_RULE
    assert (f'"forbidden_token_source_rule": {ROUND_RULE}` together with '
            '`"forbidden_token_round_figures": "list"`') in _section()


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
            "forbidden_token_source_layout_required", "forbidden_token_sources_experimental_in_use"} <= named
    assert named <= hints


def test_the_section_calls_figure_sources_experimental_and_never_complete():
    section = " ".join(_section().split())
    assert "experimental and off unless opted in" in section
    assert f'`"{OPT_IN}": true`' in section
    # "complete" appears only to say the reader is not a complete screen.
    assert section.count("complete") == section.count("not a complete screen") >= 1
    for claim in ("lists every figure", "list every figure", "all figures", "every amount", "screens every"):
        assert claim not in section
    # The figures that must never be sent go in a list that does not depend on the reader.
    assert "`forbidden_token_file` or `forbidden_token_hashes`" in section


def test_the_published_policy_upgrades_unchanged():
    check_draft(_policy())


def test_a_policy_with_sources_follows_the_documented_steps():
    # A development build's policy: bare paths, no opt-in, no rule. Each of the three edits is required, and leaving
    # out any one of them is refused with the code the section names for it.
    edits = {OPT_IN: True, "forbidden_token_sources": [_layout()], "forbidden_token_source_rule": SOURCE_RULE}
    development = _with(_policy(), forbidden_token_sources=["/synthetic/exports/positions.csv"])
    assert _refused(development) in _named_codes()
    without = {OPT_IN: "forbidden_token_sources_experimental",
               "forbidden_token_sources": "forbidden_token_source_layout_required",
               "forbidden_token_source_rule": "gate_policy_source_rule_required"}
    for left_out, code in without.items():
        document = _with(development, **{name: value for name, value in edits.items() if name != left_out})
        assert _refused(document) == code
        assert code in _named_codes()
    check_draft(_with(development, **edits))
    check_draft(_with(development, **{**edits, "forbidden_token_source_rule": ROUND_RULE,
                                      "forbidden_token_round_figures": "list"}))


def test_a_configuration_with_sources_follows_the_documented_steps():
    def load(document):
        return load_config(content=json.dumps(document).encode())

    with pytest.raises(AssistantError, match="^forbidden_token_sources_experimental$"):
        load({"forbidden_token_sources": [_layout()]})
    with pytest.raises(AssistantError, match="^forbidden_token_source_layout_required$"):
        load({"forbidden_token_sources": ["~/exports/positions.csv"], OPT_IN: True})
    config = load({"forbidden_token_sources": [_layout()], OPT_IN: True})
    # doctor warns while the reader is on, with the code the section names.
    assert [w["code"] for w in config_warnings(config)] == ["forbidden_token_sources_experimental_in_use"]


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
    {"forbidden_token_sources": ["/synthetic/exports/positions.csv"], "forbidden_token_source_rule": ROUND_RULE,
     OPT_IN: True},
    {"forbidden_token_sources": ["/synthetic/exports/positions.csv"], "forbidden_token_source_rule": SOURCE_RULE,
     "forbidden_token_round_figures": "list", OPT_IN: True},
])
def test_a_rule_that_disagrees_with_the_policy_is_refused(model):
    with pytest.raises(AssistantError) as refused:
        check_draft(_with(_policy(), **model))
    assert refused.value.code == "gate_policy_source_rule_required"
