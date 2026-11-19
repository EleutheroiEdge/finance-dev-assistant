"""Figure sources with a declared layout: read with the declared delimiter and decimal mark only, or refused.

Read every way, a file that reads more than one way with different figures is refused. Declaring its layout reads
it, and a declaration that does not fit the file fails closed. Synthetic exports and paths only.
"""

from dataclasses import replace
import hashlib
import json
import os

import pytest

from conftest import command
from test_config_figure_screen import _transport
from test_figure_source_formats import _refused, _source
from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration
from test_providers_review import model_config, response

from finassist.config import config_hash, config_identity, load_config, save_config
from finassist.config_preflight import config_preflight
from finassist.errors import AssistantError
from finassist.figure_source_entries import OPT_IN, SourceFormat
from finassist.figure_sources import SOURCE_RULE
from finassist.forbidden_tokens import load_token_snapshot
from finassist.model_policy import check_draft
from finassist.review import review_packet
from finassist.scope import build_packet, config_token_guard

# The reader's own tests: figure sources are not available in this release, so they turn them on, as only
# code can.
pytestmark = pytest.mark.usefixtures("sources_available")

# Configuration hashes of figure-source settings that name paths only, under source rule 26 (under rule 1 they were
# e300b939...991fa and f2b64430...4ea58). Such a configuration is refused now: figure sources are experimental and
# opted in only with a declared layout, so these hashes name no configuration that loads.
PATH_ONLY_HASHES = {
    '{"forbidden_token_sources": ["/synthetic/positions.csv"]}':
        "3755cf6d5e0ff37bcf017b2a5ffbb0bae8d7025506086176437b0aab70597241",
    '{"forbidden_token_sources": ["/synthetic/positions.csv", "~/synthetic/balances.csv"], '
    '"forbidden_token_match": "digits", "forbidden_token_min_digits": 6}':
        "ce6d146e4e8246e5fb597627ff4da846a6803c433749f05f753dc569ec94156b",
}
ONE_COLUMN = "Betrag\n12.345,67\n98.765,43\n"


def _layout(path, delimiter=";", decimal_mark=","):
    return {"path": path, "delimiter": delimiter, "decimal_mark": decimal_mark}


def _load(*entries, parsed=None):
    return load_token_snapshot({"forbidden_token_sources": list(entries)}, (), parsed)


def _config(*entries):
    return load_config(content=json.dumps({"forbidden_token_sources": list(entries), OPT_IN: True}).encode())


def test_a_declared_layout_reads_a_source_that_reads_more_than_one_way(tmp_path):
    source = _source(tmp_path, ONE_COLUMN)
    with pytest.raises(AssistantError, match="^forbidden_token_source_ambiguous$"):
        _load(source)
    snapshot = _load(_layout(source))
    assert snapshot.listed == 2 and _refused("12345.67", snapshot) and _refused("98.765,43", snapshot)
    assert not _refused("12345", snapshot)  # what the comma reading would have listed


@pytest.mark.parametrize("text,delimiter,decimal_mark,listed,unlisted", [
    ("Konto;Betrag\nA1;1.234.567,89\nB2;12.345\n", ";", ",", ["1234567.89", "12345"], ["12.3450"]),
    ('Account,Amount\nA1,"1,234,567.89"\nB2,12.345\n', ",", ".", ["1234567.89", "12.3450"], ["12345"]),
    ("Konto\tBetrag\nA1\t1 234 567,89\n", "\t", ",", ["1234567.89"], ["1234"]),
    ("Konto|Betrag\nA1|1'234'567.89\n", "|", ".", ["1234567.89"], ["1234"]),
    ("Konto;Betrag;Datum\nA1;.57891;02.01.2026\n", ";", ".", ["0.57891"], ["57891"]),
    ("Konto;Betrag\nA1;-12.345,67 EUR\nB2;(98.765,43)\n", ";", ",", ["12345.67", "98765.43"], []),
    (ONE_COLUMN, None, ",", ["12345.67", "98765.43"], ["12345"]),
], ids=["semicolon-comma", "comma-point-quoted", "tab-space-groups", "bar-apostrophe-groups", "leading-mark-date",
        "signs-and-codes", "one-column"])
def test_a_declared_layout_lists_each_amount_as_its_mark_reads_it(tmp_path, text, delimiter, decimal_mark, listed,
                                                                 unlisted):
    snapshot = _load(_layout(_source(tmp_path, text), delimiter, decimal_mark))
    for amount in listed:
        assert _refused(amount, snapshot), amount
    for amount in unlisted:
        assert not _refused(amount, snapshot), amount


@pytest.mark.parametrize("text,delimiter,decimal_mark", [
    ("Name,Amount\nA,12345.67\n", ";", ","),
    ("Name;Amount\nA;1,234.56\n", ";", ","),
    ("12.345,67;98.765,43\n", ",", "."),
    ("Konto;Betrag\nA1;1234.567\n", ";", ","),
    ("12.345,67;98.765,43\n", None, ","),
], ids=["other-delimiter", "other-mark", "cut-amounts", "bad-groups", "one-column-of-two"])
def test_a_declared_layout_that_does_not_fit_the_file_is_refused(tmp_path, text, delimiter, decimal_mark):
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _load(_layout(_source(tmp_path, text), delimiter, decimal_mark))


@pytest.mark.parametrize("entry", [
    {"path": "/synthetic/a.csv", "delimiter": ";"},
    {"path": "/synthetic/a.csv", "delimiter": ";", "decimal_mark": ",", "header": True},
    {"path": "/synthetic/a.csv", "delimiter": ".", "decimal_mark": ","},
    {"path": "/synthetic/a.csv", "delimiter": ";", "decimal_mark": "'"},
    {"path": "/synthetic/a.csv", "delimiter": ",", "decimal_mark": ","},
    {"path": "", "delimiter": ";", "decimal_mark": ","},
    {"path": 7, "delimiter": ";", "decimal_mark": ","},
    {"path": "/synthetic/a.csv", "delimiter": [";"], "decimal_mark": ","},
    {"path": "/synthetic/a.csv", "delimiter": "", "decimal_mark": ","},
    {"path": "/synthetic/a.csv", "delimiter": None, "decimal_mark": None},
    7,
], ids=["no-mark", "unknown-key", "not-a-delimiter", "not-a-mark", "comma-twice", "empty-path", "path-not-text",
        "delimiter-not-text", "empty-delimiter", "null-mark", "not-an-entry"])
def test_an_invalid_entry_is_refused_by_the_loader_the_configuration_and_a_gate_policy(entry):
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        load_token_snapshot({"forbidden_token_sources": [entry]}, ())
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _config(entry)
    document = model_policy()
    document["model_review"]["forbidden_token_sources"] = [entry]
    document["model_review"].update({"forbidden_token_source_rule": SOURCE_RULE, OPT_IN: True})  # only the entry is wrong
    with pytest.raises(AssistantError, match="^gate_policy_invalid$"):
        check_draft(document)


def test_a_gate_policy_accepts_layouts_and_refuses_a_bare_path():
    document = model_policy()
    document["model_review"]["forbidden_token_sources"] = [_layout("~/exports/b.csv", "\t", "."),
                                                           _layout("~/exports/c.csv", None, ",")]
    document["model_review"].update({"forbidden_token_source_rule": SOURCE_RULE, OPT_IN: True})
    check_draft(document)
    document["model_review"]["forbidden_token_sources"].append("~/exports/a.csv")
    with pytest.raises(AssistantError, match="^forbidden_token_source_layout_required$"):
        check_draft(document)


def test_a_changed_declaration_is_another_screen_and_review_refuses_the_old_one(repository, tmp_path, monkeypatch):
    source = _source(tmp_path, "Betrag\n12345,67\n98765,43\n")
    semicolon, tab = _load(_layout(source, ";", ",")), _load(_layout(source, "\t", ","))
    assert semicolon.hashes == tab.hashes and semicolon != tab  # the same figures, read under two declarations
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    first = model_config(forbidden_token_sources=(SourceFormat(source, ";", ","),), **{OPT_IN: True})
    changed = replace(first, forbidden_token_sources=(SourceFormat(source, "\t", ","),))
    packet = build_packet(repo, base, head, first, token_guard=config_token_guard(first, repo))
    calls = []
    with pytest.raises(AssistantError, match="^forbidden_token_guard_required$"):
        review_packet(packet, changed, tmp_path / "audit.db", network_approved=True,
                      approved_packet_hash=packet["packet_hash"], transport=_transport(calls, response(packet)),
                      token_guard=config_token_guard(first, repo))
    assert not calls and not (tmp_path / "audit.db").exists()


def test_a_file_named_twice_is_refused_whatever_the_form_or_spelling(tmp_path):
    source = _source(tmp_path, "Konto;Betrag\nA1;12.345,67\n")
    respelled = os.path.join(os.path.dirname(source), ".", os.path.basename(source))  # any platform's separator
    assert respelled != source and _load(_layout(respelled)).listed == 1
    for entries in ([source, _layout(source)], [_layout(source), _layout(source, "\t", ",")], [source, respelled],
                    [_layout(source), _layout(respelled)]):
        with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
            _load(*entries)
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _config(source, _layout(source))


def test_path_entries_are_refused_and_a_layout_is_part_of_the_hash():
    # A path-only configuration was read every way: it is refused now, opted in or not, so its hash names nothing.
    for document in PATH_ONLY_HASHES:
        with pytest.raises(AssistantError, match="^forbidden_token_sources_experimental$"):
            load_config(content=document.encode())
    with pytest.raises(AssistantError, match="^forbidden_token_source_layout_required$"):
        _config("/synthetic/positions.csv")
    declared = _config(_layout("/synthetic/positions.csv"))
    other = _config(_layout("/synthetic/positions.csv", "\t", ","))
    assert len({config_hash(declared), config_hash(other)}) == 2
    assert declared.forbidden_token_sources == (SourceFormat("/synthetic/positions.csv", ";", ","),)
    assert list(config_identity(declared)["forbidden_token_sources"]) == [_layout("/synthetic/positions.csv")]
    assert declared.forbidden_token_rules["forbidden_token_sources"] == [_layout("/synthetic/positions.csv")]


def test_a_layout_is_kept_when_the_configuration_is_saved_and_loaded(tmp_path):
    config = _config(_layout("/synthetic/positions.csv"), _layout("/synthetic/balances.csv", None, "."))
    save_config(tmp_path / "finassist.json", config)
    again = load_config(tmp_path / "finassist.json")
    assert again == config and config_hash(again) == config_hash(config)


def test_the_parse_cache_depends_on_the_declared_layout(tmp_path):
    source = _source(tmp_path, "Konto;Betrag\nA1;12.345\n")
    parsed = {}
    automatic = _load(source, parsed=parsed)
    comma = _load(_layout(source, ";", ","), parsed=parsed)
    point = _load(_layout(source, ";", "."), parsed=parsed)
    assert _refused("12345", automatic) and _refused("12.3450", automatic)
    assert _refused("12345", comma) and not _refused("12.3450", comma)
    assert _refused("12.3450", point) and not _refused("12345", point)
    assert len(parsed) == 3


def test_a_gate_policy_with_a_layout_runs_the_review(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[_layout(_source(tmp_path, ONE_COLUMN))],
                  forbidden_token_source_rule=SOURCE_RULE)
    report, calls = run(gate_case)
    assert calls and not any(reason.startswith("forbidden_token") for reason in report["reasons"])


def test_a_gate_policy_with_a_layout_refuses_a_listed_figure_before_any_request(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[_layout(_source(tmp_path, ONE_COLUMN))],
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
    source = _source(tmp_path, ONE_COLUMN)
    report = config_preflight(repo, base, head, _config(_layout(source)))
    assert report["figure_screen"] == {"configured": True, "listed": 2, "match": "value", "digit_forms": 0}
    text = json.dumps(report)
    secret = (source, "positions.csv", "decimal_mark", "Betrag", "12345.67", "12.345,67",
              hashlib.sha256(ONE_COLUMN.encode()).hexdigest())
    assert all(part not in text for part in secret)
