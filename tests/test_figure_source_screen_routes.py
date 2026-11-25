"""A strict figure source through the real screen, end to end, with figure sources turned on as only code can.

An amount in a source stops a change that writes it, in any spelling the screen reads, before any request; an amount
the source does not hold in full stops nothing; and a source with one cell outside its declared grammar stops every
route with its own code, before any request or reservation. Every figure, file and repository here is synthetic.
"""

from dataclasses import replace
import json

import pytest

from conftest import command
from figure_source_cases import layout, write_source
from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration

from finassist.cli import main
from finassist.config import Config, load_config
from finassist.config_preflight import config_preflight
from finassist.errors import AssistantError
from finassist.figure_source_entries import OPT_IN, SourceFormat
from finassist.figure_sources import SOURCE_RULE
from finassist.forbidden_tokens import TokenGuard
from finassist.scope import build_packet, config_token_guard
from finassist.security import canonical, digest

pytestmark = pytest.mark.usefixtures("sources_available")

# A custody-style export: semicolons, decimal commas, grouping points; an account, a date and a note as text.
EXPORT = ("Konto;Datum;Betrag;Kurs;Notiz\n"
          "SYN-0001;02.01.2026;1.234.567,89;48.213,5712;Lot 12 of 40\n"
          'SYN-0002;03.01.2026;(98.765,43 EUR);"-7,5";"Said ""hold""; ref 31.415,92"\n')
TEXT_COLUMNS = ["Konto", "Datum", "Notiz"]
SPELLINGS = ["1234567.89", "1,234,567.89", "1.234.567,89", "1 234 567,89", "1'234'567.89", "(1,234,567.89)",
             "$1,234,567.89", "USD 1234567.89", "-1234567.89", "+1234567.890", "01234567.89", "12,34,567.89",
             "1.23456789e6", "123456789e-2", "1_234_567.89", "1\u00a0234\u00a0567,89", "1\u202f234\u202f567,89",
             "\uff11\uff12\uff13\uff14\uff15\uff16\uff17.\uff18\uff19", "1\\u00a0234\\u00a0567,89", "1&nbsp;234&nbsp;567,89"]
OTHERS = ["234567.89", "567.89", "1234567", "1234567.88", "1234567.8", "123456.789", "31415.92", "31.415,92", "765.43",
          "98765", "7.5", "02.01.2026"]
BROKEN = {  # one cell outside the declared grammar or the declared table, each in an otherwise well-formed export
    "footnote": ("1.234.567,89", "1.234.567,89 1)", "forbidden_token_source_cell_unreadable", (2, 3)),
    "exponent": ("48.213,5712", "4,82135712e4", "forbidden_token_source_cell_unreadable", (2, 4)),
    "undeclared-date-column": ("Betrag;Kurs;Notiz\n", "Betrag;Kurs;Notiz;Valuta\n", "forbidden_token_source_layout_mismatch",
                               (2, None)),
    "invisible-character": ("1.234.567,89", "1.234\u200b.567,89", "forbidden_token_source_hidden_mark", (2, None)),
    "no-break-space": ("(98.765,43 EUR)", "(98.765,43\u00a0EUR)", "forbidden_token_source_hidden_mark", (3, None)),
    "split-quote": ('"-7,5"', ' "-7\n,5"', "forbidden_token_source_malformed_quotes", (3, 4)),
    "equals-quote": ('"-7,5"', '="-7,5"', "forbidden_token_source_malformed_quotes", (3, 4)),
    "other-grouping": ("1.234.567,89", "1,234,567.89", "forbidden_token_source_cell_unreadable", (2, 3)),
}


def _entry(tmp_path, content=EXPORT):
    return layout(write_source(tmp_path, content), text_columns=TEXT_COLUMNS)


def _candidate(case, text):
    repo = case["repo"]
    (repo / "src/cash.py").write_text(text, encoding="utf-8", newline="\n")
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-q", "-m", "Synthetic candidate")
    case["head"] = command(repo, "rev-parse", "HEAD")


@pytest.mark.parametrize("match", ["value", "digits"])
def test_the_guard_lists_each_amount_of_a_strict_source_in_full(tmp_path, match):
    guard = TokenGuard.load({"forbidden_token_sources": [_entry(tmp_path)], OPT_IN: True,
                             "forbidden_token_match": match}, ())
    assert guard.snapshot.source_figures == guard.snapshot.listed == 3  # 1234567.89, 48213.5712 and 98765.43
    packet = {"files": [{"path": "notes.md", "before": None, "after": "nothing listed here: 7.5 and 31.415,92"}]}
    guard.recheck(packet, "synthetic instructions")
    for spelling in SPELLINGS:
        packet["files"][0]["after"] = f"total {spelling} due"
        with pytest.raises(AssistantError, match="^forbidden_token_present$"):
            guard.recheck(packet, "synthetic instructions")
    for other in OTHERS:
        if match == "digits" and other == "123456.789":
            continue  # the same significant digits as a listed figure: digit matching refuses those at any scale
        packet["files"][0]["after"] = f"total {other} due"
        guard.recheck(packet, "synthetic instructions")


@pytest.mark.parametrize("spelling", SPELLINGS[:14], ids=[f"spelling-{index}" for index in range(14)])
def test_a_gate_refuses_a_change_that_writes_a_source_s_amount_before_any_request(gate_case, tmp_path, spelling):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[_entry(tmp_path)], forbidden_token_source_rule=SOURCE_RULE)
    _candidate(gate_case, f'NOTE = "total {spelling} due"\n\n\ndef balance(opening, deposits):\n    return 0\n')
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and report["reasons"] == ["forbidden_token_present"]
    assert report["spend"]["reserved_usd"] is None


def test_a_gate_passes_a_change_that_writes_no_amount_of_the_source_in_full(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[_entry(tmp_path)], forbidden_token_source_rule=SOURCE_RULE)
    _candidate(gate_case, "".join(f'NOTE_{index} = "total {other} due"\n' for index, other in enumerate(OTHERS))
               + "\n\ndef balance(opening, deposits):\n    return 0\n")
    report, calls = run(gate_case)
    assert calls and not any(reason.startswith(("forbidden_token", "gate_policy")) for reason in report["reasons"])


@pytest.mark.parametrize("name", sorted(BROKEN))
def test_a_source_with_a_cell_outside_its_grammar_stops_every_route_by_name(gate_case, repository, tmp_path, capsys,  # noqa: F811
                                                                           name):
    old, new, code, place = BROKEN[name]
    assert EXPORT.count(old) == 1
    entry = _entry(tmp_path, EXPORT.replace(old, new))
    rules = {"forbidden_token_sources": [entry], OPT_IN: True}
    # The guard every route loads: the code, the source's place in the list, a line and a column, and no content.
    with pytest.raises(AssistantError, match=f"^{code}$") as caught:
        TokenGuard.load(rules, ())
    assert caught.value.public_details == {"source": 1, **{key: value for key, value in zip(("line", "column"), place, strict=True)
                                                           if value is not None}}
    # The gate: blocked before any request or reservation, whatever the change holds.
    change_policy(gate_case, forbidden_token_sources=[entry], forbidden_token_source_rule=SOURCE_RULE)
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and report["reasons"] == [code]
    assert report["spend"]["reserved_usd"] is None
    # The configuration routes: the packet is never built, and doctor names the code.
    repo, base, head = repository
    config = replace(Config(), forbidden_token_sources=(SourceFormat(entry["path"], ";", ",", ".", True,
                                                                     tuple(TEXT_COLUMNS)),),
                     forbidden_token_sources_experimental=True)
    with pytest.raises(AssistantError, match=f"^{code}$"):
        build_packet(repo, base, head, config, token_guard=config_token_guard(config, repo))
    preflight = config_preflight(repo, base, head, config)
    assert preflight["status"] == "blocked" and code in [item["code"] for item in preflight["blockers"]]
    # Doctor on the policy file: the same code, and nothing of the file in the report.
    document = model_policy()
    document["model_review"].update(forbidden_token_sources=[entry], forbidden_token_source_rule=SOURCE_RULE,
                                    **{OPT_IN: True})
    policy = tmp_path / "policy.json"
    policy.write_bytes(canonical(document))
    main(["doctor", "--policy-file", str(policy), "--repo", str(gate_case["repo"]), "--base", gate_case["base"],
          "--head", gate_case["head"], "--policy-sha256", digest(canonical(document))])
    shown = capsys.readouterr().out
    assert code in [item["code"] for item in json.loads(shown)["blockers"]]
    assert "1.234" not in shown and "98.765" not in shown and "SYN-0001" not in shown


def test_the_configuration_route_refuses_a_change_that_writes_a_source_s_amount(repository, tmp_path):
    repo, base, _head = repository
    (repo / "src/cash.py").write_text("OPENING = 1_234_567.89  # synthetic\n", encoding="utf-8", newline="\n")
    command(repo, "commit", "-q", "-am", "Synthetic change with a listed figure")
    head = command(repo, "rev-parse", "HEAD")
    config = load_config(content=json.dumps({"forbidden_token_sources": [_entry(tmp_path)], OPT_IN: True}).encode())
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        build_packet(repo, base, head, config, token_guard=config_token_guard(config, repo))
    report = config_preflight(repo, base, head, config)
    assert report["figure_screen"] == {"configured": True, "listed": 3, "match": "value", "digit_forms": 0}
    assert [item["code"] for item in report["blockers"]] == ["forbidden_token_present"]


def test_without_the_code_switch_the_same_settings_are_refused(tmp_path, monkeypatch):
    from finassist import figure_source_entries

    monkeypatch.setattr(figure_source_entries, "SOURCES_AVAILABLE", False)
    with pytest.raises(AssistantError, match="^forbidden_token_sources_experimental$"):
        TokenGuard.load({"forbidden_token_sources": [_entry(tmp_path)], OPT_IN: True}, ())
