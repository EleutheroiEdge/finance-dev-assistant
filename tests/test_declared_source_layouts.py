"""A figure source's entry declares its whole layout: in a configuration, in a gate policy and in the loader, an entry
that is not a whole, readable layout is refused, and a layout is part of the screen's identity.

How a file is read by its layout is tested in tests/test_strict_figure_sources.py. Synthetic exports and paths only.
"""

from dataclasses import replace
import hashlib
import json
import os

from jsonschema import Draft202012Validator
import pytest

from conftest import command
from figure_source_cases import layout, load, refused, write_source
from test_config_figure_screen import _transport
from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration
from test_providers_review import model_config, response

from finassist.config import config_hash, config_identity, load_config, save_config
from finassist.config_preflight import config_preflight
from finassist.errors import AssistantError
from finassist.figure_source_entries import OPT_IN, SOURCE_ENTRY_SCHEMA, SourceFormat
from finassist.figure_sources import SOURCE_RULE
from finassist.forbidden_tokens import load_token_snapshot
from finassist.model_policy import check_draft
from finassist.review import review_packet
from finassist.scope import build_packet, config_token_guard

# The reader's own tests: figure sources are not available in this release, so they turn them on, as only
# code can.
pytestmark = pytest.mark.usefixtures("sources_available")

# Configuration hashes of figure-source settings that name paths only, under an earlier source rule. Such a
# configuration is refused now: a bare path declares no layout, so these hashes name no configuration that loads.
PATH_ONLY_HASHES = {
    '{"forbidden_token_sources": ["/synthetic/positions.csv"]}':
        "3755cf6d5e0ff37bcf017b2a5ffbb0bae8d7025506086176437b0aab70597241",
    '{"forbidden_token_sources": ["/synthetic/positions.csv", "~/synthetic/balances.csv"], '
    '"forbidden_token_match": "digits", "forbidden_token_min_digits": 6}':
        "ce6d146e4e8246e5fb597627ff4da846a6803c433749f05f753dc569ec94156b",
}
ONE_COLUMN = "Betrag\n12.345,67\n98.765,43\n"
PATH = "/synthetic/a.csv"


def _config(*entries):
    return load_config(content=json.dumps({"forbidden_token_sources": list(entries), OPT_IN: True}).encode())


def _without(key):
    entry = layout(PATH)
    del entry[key]
    return entry


INVALID = {
    "no-path": _without("path"), "no-delimiter": _without("delimiter"), "no-decimal-mark": _without("decimal_mark"),
    "no-group-mark": _without("group_mark"), "no-header": _without("header"), "no-text-columns": _without("text_columns"),
    "earlier-layout": {"path": PATH, "delimiter": ";", "decimal_mark": ","},
    "unknown-key": {**layout(PATH), "encoding": "utf-16"},
    "not-a-delimiter": layout(PATH, delimiter="."), "space-delimiter": layout(PATH, delimiter=" "),
    "null-delimiter": layout(PATH, delimiter=None), "empty-delimiter": layout(PATH, delimiter=""),
    "delimiter-not-text": layout(PATH, delimiter=[";"]), "not-a-decimal-mark": layout(PATH, decimal_mark="'"),
    "null-decimal-mark": layout(PATH, decimal_mark=None), "comma-twice": layout(PATH, delimiter=",", decimal_mark=","),
    "decimal-and-group-comma": layout(PATH, decimal_mark=",", group_mark=","),
    "decimal-and-group-point": layout(PATH, decimal_mark=".", group_mark="."),
    "not-a-group-mark": layout(PATH, group_mark="_"), "empty-group-mark": layout(PATH, group_mark=""),
    "group-mark-word": layout(PATH, group_mark="none"), "header-not-a-boolean": layout(PATH, header="true"),
    "header-a-number": layout(PATH, header=1), "columns-not-a-list": {**layout(PATH), "text_columns": "1"},
    "columns-null": {**layout(PATH), "text_columns": None}, "position-zero": layout(PATH, text_columns=[0]),
    "position-negative": layout(PATH, text_columns=[-1]), "position-a-fraction": layout(PATH, text_columns=[1.5]),
    "position-a-boolean": layout(PATH, text_columns=[True]), "position-too-large": layout(PATH, text_columns=[4097]),
    "position-twice": layout(PATH, text_columns=[2, 2]), "name-twice": layout(PATH, text_columns=["Konto", "Konto"]),
    "empty-name": layout(PATH, text_columns=[""]), "name-too-long": layout(PATH, text_columns=["k" * 257]),
    "name-without-a-header": layout(PATH, header=False, text_columns=["Konto"]),
    "nested-column": layout(PATH, text_columns=[[1]]), "too-many-columns": layout(PATH, text_columns=list(range(1, 66))),
    "empty-path": layout(""), "path-not-text": layout(7), "not-an-entry": 7, "null-entry": None, "list-entry": [PATH],
}
VALID = {
    "semicolon": layout(PATH), "comma-quoted-groups": layout(PATH, delimiter=",", decimal_mark=".", group_mark=","),
    "tab-space-groups": layout(PATH, delimiter="\t", group_mark=" "), "bar-apostrophes": layout(PATH, delimiter="|", group_mark="'"),
    "no-groups": layout(PATH, group_mark=None), "no-header": layout(PATH, header=False, text_columns=[1, 3]),
    "names-and-positions": layout(PATH, text_columns=["Konto", 2, "Datum"]),
    "sixty-four-columns": layout(PATH, text_columns=list(range(1, 65))),
}


@pytest.mark.parametrize("name", sorted(INVALID))
def test_an_invalid_entry_is_refused_by_the_loader_the_configuration_a_gate_policy_and_the_schema(name):
    entry = INVALID[name]
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        load_token_snapshot({"forbidden_token_sources": [entry]}, ())
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _config(entry)
    document = model_policy()
    document["model_review"]["forbidden_token_sources"] = [entry]
    document["model_review"].update({"forbidden_token_source_rule": SOURCE_RULE, OPT_IN: True})  # only the entry is wrong
    with pytest.raises(AssistantError, match="^gate_policy_invalid$"):
        check_draft(document)
    assert not Draft202012Validator(SOURCE_ENTRY_SCHEMA).is_valid(entry)


@pytest.mark.parametrize("name", sorted(VALID))
def test_a_whole_layout_is_accepted_by_the_configuration_a_gate_policy_and_the_schema(name):
    entry = VALID[name]
    assert _config(entry).forbidden_token_rules["forbidden_token_sources"] == [
        {**entry, "text_columns": tuple(entry["text_columns"])}]
    document = model_policy()
    document["model_review"]["forbidden_token_sources"] = [entry]
    document["model_review"].update({"forbidden_token_source_rule": SOURCE_RULE, OPT_IN: True})
    check_draft(document)
    assert Draft202012Validator(SOURCE_ENTRY_SCHEMA).is_valid(entry)


def test_a_gate_policy_accepts_layouts_and_refuses_a_bare_path():
    document = model_policy()
    document["model_review"]["forbidden_token_sources"] = [layout("~/exports/b.csv", "\t", ".", ","),
                                                           layout("~/exports/c.csv", ";", ",", None, False)]
    document["model_review"].update({"forbidden_token_source_rule": SOURCE_RULE, OPT_IN: True})
    check_draft(document)
    document["model_review"]["forbidden_token_sources"].append("~/exports/a.csv")
    with pytest.raises(AssistantError, match="^forbidden_token_source_layout_required$"):
        check_draft(document)


def test_a_changed_declaration_is_another_screen_and_review_refuses_the_old_one(repository, tmp_path, monkeypatch):
    source = write_source(tmp_path, "Betrag\n12345,67\n98765,43\n")
    grouped, plain = load(layout(source)), load(layout(source, group_mark=None))
    assert grouped.hashes == plain.hashes and grouped != plain  # the same figures, read under two declarations
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    first = model_config(forbidden_token_sources=(SourceFormat(source, ";", ",", ".", True, ()),), **{OPT_IN: True})
    changed = replace(first, forbidden_token_sources=(SourceFormat(source, ";", ",", None, True, ()),))
    packet = build_packet(repo, base, head, first, token_guard=config_token_guard(first, repo))
    calls = []
    with pytest.raises(AssistantError, match="^forbidden_token_guard_required$"):
        review_packet(packet, changed, tmp_path / "audit.db", network_approved=True,
                      approved_packet_hash=packet["packet_hash"], transport=_transport(calls, response(packet)),
                      token_guard=config_token_guard(first, repo))
    assert not calls and not (tmp_path / "audit.db").exists()


def test_a_file_named_twice_is_refused_whatever_the_layout_or_spelling(tmp_path):
    source = write_source(tmp_path, "Konto;Betrag\nA1;12.345,67\n")
    respelled = os.path.join(os.path.dirname(source), ".", os.path.basename(source))  # any platform's separator
    columns = {"text_columns": [1]}
    assert respelled != source and load(layout(respelled, **columns)).listed == 1
    for entries in ([layout(source, **columns), layout(source, **columns)],
                    [layout(source, **columns), layout(source, group_mark=None, **columns)],
                    [layout(source, **columns), layout(respelled, **columns)]):
        with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
            load(*entries)
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _config(layout(source), layout(source, header=False))


def test_path_entries_are_refused_and_a_layout_is_part_of_the_hash():
    # A path-only configuration was read every way: it is refused now, opted in or not, so its hash names nothing.
    for document in PATH_ONLY_HASHES:
        with pytest.raises(AssistantError, match="^forbidden_token_sources_experimental$"):
            load_config(content=document.encode())
    with pytest.raises(AssistantError, match="^forbidden_token_source_layout_required$"):
        _config("/synthetic/positions.csv")
    declared = _config(layout("/synthetic/positions.csv", text_columns=["Konto", 2]))
    hashes = {config_hash(declared)}
    for change in ({"delimiter": "\t"}, {"decimal_mark": ".", "group_mark": ","}, {"group_mark": None}, {"header": False},
                   {"text_columns": ["Konto"]}, {"text_columns": [2, "Konto"]}, {"text_columns": []}):
        entry = {**layout("/synthetic/positions.csv", text_columns=["Konto", 2]), **change}
        if entry["header"] is False:
            entry["text_columns"] = [2]
        hashes.add(config_hash(_config(entry)))
    assert len(hashes) == 8  # each part of a layout is part of the configuration's identity
    assert declared.forbidden_token_sources == (SourceFormat("/synthetic/positions.csv", ";", ",", ".", True,
                                                             ("Konto", 2)),)
    entry = {"path": "/synthetic/positions.csv", "delimiter": ";", "decimal_mark": ",", "group_mark": ".", "header": True,
             "text_columns": ("Konto", 2)}
    assert list(config_identity(declared)["forbidden_token_sources"]) == [entry]
    assert declared.forbidden_token_rules["forbidden_token_sources"] == [entry]


def test_a_layout_is_kept_when_the_configuration_is_saved_and_loaded(tmp_path):
    config = _config(layout("/synthetic/positions.csv", text_columns=["Konto", 3]),
                     layout("/synthetic/balances.csv", ",", ".", None, False))
    save_config(tmp_path / "finassist.json", config)
    again = load_config(tmp_path / "finassist.json")
    assert again == config and config_hash(again) == config_hash(config)
    assert hash(again.forbidden_token_sources[0]) == hash(config.forbidden_token_sources[0])  # no mutable part


def test_a_gate_policy_with_a_layout_runs_the_review(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[layout(write_source(tmp_path, ONE_COLUMN))],
                  forbidden_token_source_rule=SOURCE_RULE)
    report, calls = run(gate_case)
    assert calls and not any(reason.startswith("forbidden_token") for reason in report["reasons"])


def test_a_gate_policy_with_a_layout_refuses_a_listed_figure_before_any_request(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[layout(write_source(tmp_path, ONE_COLUMN))],
                  forbidden_token_source_rule=SOURCE_RULE)
    repo = gate_case["repo"]
    (repo / "src/cash.py").write_text("def balance(opening, deposits):\n    return 12345.67\n", encoding="utf-8")
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Synthetic candidate with a listed figure")
    gate_case["head"] = command(repo, "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and "forbidden_token_present" in report["reasons"]
    assert report["spend"]["reserved_usd"] is None  # refused before any budget is reserved


def test_doctor_reports_counts_only_for_a_declared_layout(repository, tmp_path):
    repo, base, head = repository
    source = write_source(tmp_path, ONE_COLUMN)
    report = config_preflight(repo, base, head, _config(layout(source)))
    assert report["figure_screen"] == {"configured": True, "listed": 2, "match": "value", "digit_forms": 0}
    text = json.dumps(report)
    secret = (source, "positions.csv", "decimal_mark", "Betrag", "12345.67", "12.345,67",
              hashlib.sha256(ONE_COLUMN.encode()).hexdigest())
    assert all(part not in text for part in secret)
    assert refused("12345.67", load(layout(source)))
