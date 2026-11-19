"""A number written with a decimal comma and no digit before it, such as ,57891, in a figure source.

The payload screen reads a leading point and never a leading comma. Listed as 0.57891, such a source would let the
spelling ,57891 through; read another way, it would list 57891. So it is refused in both modes. Synthetic only.
"""

import pytest

from test_figure_source_formats import _refused, _source
from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration

from finassist.errors import AssistantError
from finassist.figure_sources import SOURCE_RULE
from finassist.forbidden_tokens import load_token_snapshot

# The reader's own tests: figure sources are not available in this release, so they turn them on, as only
# code can.
pytestmark = pytest.mark.usefixtures("sources_available")


def _entry(path: str, layout):
    return path if layout is None else {"path": path, "delimiter": layout[0], "decimal_mark": layout[1]}


@pytest.mark.parametrize("text,layout", [
    ("Name;Amount\nA;,57891\n", None),
    ("Name;Amount\nA;,57891\n", (";", ",")),
    ("Amount\n,57891\n0,12345\n", None),
    ("Amount\n,57891\n0,12345\n", (None, ",")),
    ("Name;Amount\nA;EUR ,57891\nB;-,57891\n", None),
    ("Name;Amount\nA;0,12345\nB;(,57891)\n", (";", ",")),
    ('Name,Amount\nA,",57891"\n', None),
    ("Name;Amount\nA;EUR,57891\n", None),
    ("A;EUR,57891\n", None),
    ("A\tUSD,57891\n", None),
    ("A|(EUR,57891)\n", None),
    ("A;EUR,57891 CR\n", (";", ",")),
    ("Name;Amount\nA;Total EUR,57891\n", None),
    ("Name\tAmount\nA\tTotal EUR ,57891\n", None),
    ('Name|Amount\nA|"Balance: ,57891"\n', None),
    ("Name;Amount\nA;Total EUR,57891\n", (";", ",")),
    ("Name;Amount\nA;TotalEUR,57891\n", None),
    ("Name\tAmount\nA\tNote: x,57891\n", None),
    ("Name|Amount\nA|1|\nTotalEUR,57891\n", None),
    ("Name;Amount\nA;TotalEUR,57891\n", (";", ",")),
    ("Amount\n0,12345\nCash dividend,57891\n", None),
    ("Amount\n1.234,56\nTotalEUR,57891\n", None),
    ("Amount\n0,12345\nCash dividend,57891\n", (None, ",")),
    ('Name,Note,Amount\nA,"Fund Trust,52429","1,5"\n', None),
    ("Name;Amount\nA;TotalEUR,57891 units\n", None),
    ("Name;Amount\nA;TotalEUR,57891 units\n", (";", ",")),
    ("Name\tAmount\nA\tRate,57891 units\n", None),
    ("Name|Amount\nA|Total A,57891 net\n", ("|", ",")),
    ('Name,Note,Amount\nA,"Fund Trust,52429 units","1,5"\n', None),
    ("Amount\n0,12345\nCash dividend,57891 units\n", (None, ",")),
    ("Amount\n0,12345\nCash dividend,57891\nNote, see report\n", None),
    ("Amount\n0,12345\nStore, closed\nCash dividend,57891\n", None),
    ("Note\nCash dividend,57891 units\n", (";", ",")),
    ("Note\nCash dividend,57891 units\n", ("\t", ",")),
    ("Note\nCash dividend,57891 units\n", ("|", ",")),
    ("Note\nTotalEUR,57891 units\n", (";", ",")),
    ("347300,00\nCash dividend,57891 units\n", None),
    ("Note 347300 held\nCash dividend,57891 units\n", None),
    ("Cash dividend,57891 units\nNote 347300 held\n", None),
    ("Cash dividend,57891 units (347300 held)\n", None),
], ids=["two-column", "two-column-declared", "one-column-mixed", "one-column-declared", "code-and-sign",
        "brackets-declared", "quoted-in-a-comma-file", "code-touching", "code-touching-headerless",
        "code-touching-tab", "code-touching-bar-brackets", "code-touching-declared", "in-a-label",
        "in-a-label-after-a-space", "in-a-quoted-label", "in-a-label-declared", "glued-to-a-word",
        "glued-to-a-letter-tab", "glued-in-a-footer-bar", "glued-to-a-word-declared", "one-column-glued",
        "one-column-glued-grouped", "one-column-glued-declared", "quoted-in-a-comma-file-glued", "glued-then-a-word",
        "glued-then-a-word-declared", "glued-then-a-word-tab", "word-glued-then-a-word-bar-declared",
        "quoted-glued-then-a-word", "one-column-glued-then-a-word-declared", "one-column-with-a-note-after",
        "one-column-with-a-note-between", "rows-of-one-cell-declared-semicolon", "rows-of-one-cell-declared-tab",
        "rows-of-one-cell-declared-bar", "glued-to-a-code-in-rows-of-one-cell-declared",
        "one-column-glued-under-a-round-figure", "one-column-glued-under-a-round-figure-in-text",
        "one-column-glued-above-a-round-figure-in-text", "glued-beside-a-round-figure-in-one-cell"])
def test_a_leading_decimal_comma_is_refused_read_every_way_and_declared(tmp_path, text, layout):
    with pytest.raises(AssistantError, match="^forbidden_token_source_unscreenable$"):
        load_token_snapshot({"forbidden_token_sources": [_entry(_source(tmp_path, text), layout)]}, ())


@pytest.mark.parametrize("text", ["Note,Amount\nA,12345\n,23456\n", "Note,Amount\n,23456\nA,12345\n"],
                         ids=["empty-cell-last", "empty-cell-first"])
def test_an_empty_first_cell_in_a_comma_file_is_not_a_leading_comma(tmp_path, text):
    snapshot = load_token_snapshot({"forbidden_token_sources": [_source(tmp_path, text)]}, ())
    assert snapshot.listed == 2 and _refused("23456", snapshot) and _refused("12345", snapshot)


def test_a_comma_after_a_word_in_a_split_line_reads_by_the_declared_mark(tmp_path):
    # In a line split on a semicolon the comma in `Total A,57891 units` is no column break, so read every way it may
    # be a decimal comma, and listing 57891 alone would let 0.57891 through: refused. Declared with a decimal point,
    # it is text, and the number is listed.
    source = _source(tmp_path, "Name;Note;Amount\nA;Total A,57891 units;12345.67\n")
    with pytest.raises(AssistantError, match="^forbidden_token_source_unscreenable$"):
        load_token_snapshot({"forbidden_token_sources": [source]}, ())
    snapshot = load_token_snapshot({"forbidden_token_sources": [_entry(source, (";", "."))]}, ())
    assert _refused("12345.67", snapshot) and _refused("57891", snapshot)


def test_a_decimal_comma_glued_to_a_word_in_a_split_line_is_not_glued_on(tmp_path):
    # `Rate9,57891` read on the semicolon is 9.57891, which a comma reading would list as 57891: the two disagree.
    with pytest.raises(AssistantError, match="^forbidden_token_source_ambiguous$"):
        load_token_snapshot({"forbidden_token_sources": [_source(tmp_path, "A;Rate9,57891\n")]}, ())


@pytest.mark.parametrize("text,layout,listed", [
    ("A,12345\nB,23456\n", None, ("12345", "23456")),
    ("Holdings\nA,12345\nB,23456\n", None, ("12345", "23456")),
    ("Qty,Amount\n3,12345\nTotal,23456\n", None, ("12345", "23456")),
    ("Name;Note;Amount\nA;Lot A,57891 units;12345.67\n", (";", "."), ("12345.67", "57891")),
    ("Amount\n12345.67\n23456.78\nCustody ref,47119\n", None, ("12345.67", "23456.78", "47119")),
    ("Cash dividend,57891\nInterest payment,23456\n", None, ("57891", "23456")),
], ids=["headerless", "titled", "headed-numeric", "declared-point", "point-column-with-a-comma-note",
        "headerless-names"])
def test_a_comma_after_a_word_stays_a_column_break_where_nothing_else_reads(tmp_path, text, layout, listed):
    # Where no reading splits the line on another mark, or a declared layout's decimal mark is the point, a comma
    # after a word is a column break, not a decimal comma: the file is read, not refused.
    snapshot = load_token_snapshot({"forbidden_token_sources": [_entry(_source(tmp_path, text), layout)]}, ())
    assert all(_refused(value, snapshot) for value in listed)


def test_digits_that_go_on_as_a_decimal_are_not_a_leading_comma(tmp_path):
    # `,123456.78` is no fraction: a shorter `,12345` must not be cut from it and refused as one.
    source = _source(tmp_path, "Name;Note\nA;Rate ,123456.78 x\n")
    snapshot = load_token_snapshot({"forbidden_token_sources": [source]}, ())
    assert _refused("123456.78", snapshot) and not _refused("0.12345", snapshot)


# A leading decimal comma before an exponent may write a round figure: `,3473e6` is 347300. Listed, the spelling
# `,3473e6` would pass the screen, so where round figures are listed the source is refused; under skip none is
# listed, so it is read.
@pytest.mark.parametrize("text,layout", [
    ("Name;Amount\nA;,3473e6\nB;12345,67\n", (";", ",")),
    ("Name;Amount\nA;EUR -,3473E+06 CR\nB;12345,67\n", (";", ",")),
    ("Name\tAmount\nA\t(,1002e6)\nB\t12345,67\n", ("\t", ",")),
    ("Amount\n,3473e6\n12345,67\n", (None, ",")),
    ("Name;Amount\nA;,3473e6\nB;12345.67\n", (";", ".")),
    ("Name;Note\nA;Total ,3473e6 net\nB;12345,67\n", (";", ",")),
    ("Name|Note\nA|Total EUR,3473e6\nB|12345,67\n", ("|", ",")),
    ("Name;Note\nA;Cash dividend,3473e6 units\nB;12345,67\n", (";", ",")),
    ("Name;Amount\nA;,3473e6\nB;12345,67\n", None),
], ids=["cell", "cell-code-sign-mark", "cell-brackets-tab", "one-column", "cell-point-declared", "in-a-label",
        "after-a-code-bar", "glued-to-a-word", "read-every-way"])
def test_a_leading_decimal_comma_round_figure_is_refused_where_round_figures_are_listed(tmp_path, text, layout):
    entry = _entry(_source(tmp_path, text), layout)
    with pytest.raises(AssistantError, match="^forbidden_token_source_unscreenable$"):
        load_token_snapshot({"forbidden_token_sources": [entry], "forbidden_token_round_figures": "list"}, ())
    if layout is not None:
        assert _refused("12345.67", load_token_snapshot({"forbidden_token_sources": [entry]}, ()))


def test_a_leading_point_is_read_as_the_payload_screen_reads_it(tmp_path):
    source = _source(tmp_path, "Name;Amount\nA;.57891\n")
    for layout in (None, (";", ".")):
        snapshot = load_token_snapshot({"forbidden_token_sources": [_entry(source, layout)]}, ())
        assert _refused(".57891", snapshot) and _refused("0.57891", snapshot) and not _refused("57891", snapshot)


def test_an_unscreenable_source_stops_the_gate_before_any_request(gate_case, tmp_path):  # noqa: F811
    change_policy(gate_case, forbidden_token_sources=[_entry(_source(tmp_path, "Name;Amount\nA;,57891\n"), (";", ","))],
                  forbidden_token_source_rule=SOURCE_RULE)
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED"
    assert report["reasons"] == ["forbidden_token_source_unscreenable"]
    assert report["outcome_class"] == "incomplete" and report["spend"]["reserved_usd"] is None
