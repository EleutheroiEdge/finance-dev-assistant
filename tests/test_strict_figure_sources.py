"""The strict figure-source reader: a source is read by its declared layout only, and refused whole, by name, unless
every cell outside its declared text columns is empty, a label or one amount in full.

These tests call the reader and the loader directly; the routes that reach them are tested where figure sources are
turned on (tests/test_figure_sources_opt_in.py). Every figure, file and name here is synthetic.
"""

import codecs
from pathlib import Path
import random
import subprocess
import sys
import time

import pytest

from conftest import source_path
from figure_source_cases import as_layout, layout, load, refused, write_source

from finassist import figure_sources, forbidden_tokens
from finassist.errors import AssistantError
from finassist.figure_sources import (AmbiguousSource, CellSource, EncodingSource, HiddenMarkSource,
                                      LayoutMismatchSource, MalformedQuotesSource, SourceLayout, SourceRefused,
                                      UnscreenableSource, read_source, source_amounts)

SEMICOLON = SourceLayout(";", ",", ".", True, ("Konto",))
COMMA = SourceLayout(",", ".", None, True, (1,))
EXPORT = "Konto;Betrag;Kurs\nSYN-1;12.345,67;1.234.567,89\nSYN-2;-98.765,43 EUR;(48.213,5712)\n"


def _amounts(text: str | bytes, declared: SourceLayout = SEMICOLON) -> list[tuple[int, int, str]]:
    return source_amounts(text.encode("utf-8") if isinstance(text, str) else text, declared)


def _cell(cell: str, declared: SourceLayout) -> list[str]:
    """What a file of one data cell lists, in a column that is not a text column."""
    return [value for _line, _column, value in _amounts(f"Konto{declared.delimiter}Betrag\nSYN-1{declared.delimiter}"
                                                         f"{cell}\n", declared)]


def test_a_well_formed_export_lists_each_amount_in_full_with_its_place():
    assert _amounts(EXPORT) == [(2, 2, "12345.67"), (2, 3, "1234567.89"), (3, 2, "98765.43"), (3, 3, "48213.5712")]
    values, forms, rounds = read_source(EXPORT.encode(), SEMICOLON, 5)
    assert values == {"12345.67", "1234567.89", "98765.43", "48213.5712"} and not rounds
    assert {"1234567", "123456789", "9876543", "482135712", "4821357"} == forms


@pytest.mark.parametrize("declared,text,listed", [
    (SourceLayout(",", ".", None, True, (1,)), 'Account,Amount\nSYN-1,12345.67\nSYN-2,"98765.43"\n',
     ["12345.67", "98765.43"]),
    (SourceLayout(",", ".", " ", True, (1,)), "Account,Amount\nSYN-1,1 234 567.89\n", ["1234567.89"]),
    (SourceLayout("\t", ",", " ", True, (1,)), "Konto\tBetrag\nSYN-1\t1 234 567,89\n", ["1234567.89"]),
    (SourceLayout("|", ".", "'", True, (1,)), "Konto|Betrag\nSYN-1|1'234'567.89\n", ["1234567.89"]),
    (SourceLayout(";", ".", ",", False, ()), "12,345.67\n98,765.43\n", ["12345.67", "98765.43"]),
    (SourceLayout(";", ",", ".", False, ()), "12.345,67\r\n98.765,43\r\n", ["12345.67", "98765.43"]),
    (SourceLayout(";", ",", ".", True, ("Konto", 3)), "Konto;Betrag;Datum\nSYN-1;12.345,67;02.01.2026\n", ["12345.67"]),
], ids=["comma-no-groups", "comma-space-groups", "tab-space-groups", "bar-apostrophe-groups", "one-column",
        "one-column-crlf", "date-column"])
def test_each_declared_layout_reads_its_own_file(declared, text, listed):
    assert [value for _line, _column, value in _amounts(text, declared)] == listed


@pytest.mark.parametrize("cell,value", [
    ("12.345,67", "12345.67"), ("12345,67", "12345.67"), ("12345", "12345"), ("0012345,670", "12345.67"),
    ("+12.345,67", "12345.67"), ("-12.345,67", "12345.67"), ("(12.345,67)", "12345.67"),
    ("EUR 12.345,67", "12345.67"), ("EUR12.345,67", "12345.67"), ("12.345,67 EUR", "12345.67"),
    ("12.345,67EUR", "12345.67"), ("$12.345,67", "12345.67"), ("$ 12.345,67", "12345.67"),
    ("12.345,67 \u20ac", "12345.67"), ("\u00a312.345,67", "12345.67"), ("-\u00a512.345,67", "12345.67"),
    ("-EUR 12.345,67", "12345.67"), ("(EUR 12.345,67)", "12345.67"), ("(12.345,67 EUR)", "12345.67"),
    ("  12.345,67  ", "12345.67"), ('"12.345,67"', "12345.67"), ('" 12.345,67 "', "12345.67"),
    ("1.234.567.890,12345", "1234567890.12345"), ("0,57891", "0.57891"), ("20261110", "20261110"),
])
def test_one_amount_in_the_declared_grammar_is_read_in_full(cell, value):
    assert _cell(cell, SEMICOLON) == [value]


@pytest.mark.parametrize("cell", ["", " ", "n/a", "-", "EUR", "Buy", "( )", "\u20ac", "open, pending", ".", "+", '""',
                                  '"said ""no"""'])
def test_a_cell_without_a_digit_is_a_label_and_lists_nothing(cell):
    assert _cell(cell, SEMICOLON) == []


@pytest.mark.parametrize("cell", [
    "12,345.67", "1,234.567,89", "12.34,56", "1.2345,67", "1234.567,89", ".57891", ",57891", "12.345,", "12.345,67,89",
    "1.23456789e6", "12345,67e2", "12.345,67%", "12.345,67 %", "12.345,67 1)", "12.345,67 [2]", "12.345,67*",
    "12.345,67 CR", "12.345,67 DR", "12.345,67 H", "12.345,67 Haben", "=12345,67", "12.345,67-", "--12.345,67",
    "+-12.345,67", "(12.345,67", "12.345,67)", "((12.345,67))", "(-12.345,67)", "-(12.345,67)", "EUR 12.345,67 EUR",
    "$12.345,67 EUR", "eur 12.345,67", "EURO 12.345,67", "EU 12.345,67", "EUR  12.345,67", "12.345,67  EUR",
    "EUR -12.345,67", "$-12.345,67", "12 345,67", "12'345,67", "12_345,67", "1 2", "12.345,67 12.345,67",
    "Total 12.345,67", "12.345,67 net", "2026-01-02", "02.01.2026", "14:30", "A1", "0x1F", "1/2", "12.345,67\t",
    "#12", "12.345,67.", "'12345,67", "[12.345,67]", "{12.345,67}", "12.345,6 7", "1 .234,56", "USD",
], ids=lambda cell: repr(cell))
def test_any_other_cell_with_a_digit_refuses_the_whole_file(cell):
    if cell == "USD":  # no digit: a label, read; here only so the list above shows the boundary
        assert _cell(cell, SEMICOLON) == []
        return
    with pytest.raises(SourceRefused) as caught:
        _cell(cell, SEMICOLON)
    assert type(caught.value) in (CellSource, HiddenMarkSource)
    assert (caught.value.line, caught.value.column) == (2, 2) or type(caught.value) is HiddenMarkSource


def test_groups_are_read_only_where_a_group_mark_is_declared_and_only_in_threes():
    ungrouped = SourceLayout(";", ",", None, True, (1,))
    assert _cell("12345,67", ungrouped) == ["12345.67"]
    for cell in ("12.345,67", "12 345,67", "12'345,67"):
        with pytest.raises(CellSource):
            _cell(cell, ungrouped)
    spaced = SourceLayout(";", ",", " ", True, (1,))
    assert _cell("(98 765 432)", spaced) == ["98765432"] and _cell("1 234 567,89 EUR", spaced) == ["1234567.89"]
    for cell in ("98 76 5432", "9 8765 432", "98 765 43", "98  765", "98 765 432 1)", "(98 765 432) 1)"):
        with pytest.raises(CellSource):
            _cell(cell, spaced)


def test_the_declared_marks_decide_what_a_cell_of_three_decimals_is():
    assert _cell("12.345", SEMICOLON) == ["12345"]
    assert _cell("12.345", SourceLayout(";", ".", ",", True, (1,))) == ["12.345"]
    assert _cell("12,345", SourceLayout(";", ".", ",", True, (1,))) == ["12345"]


def test_text_columns_are_given_by_position_or_by_the_exact_header_name():
    text = "Konto;Datum;Betrag;Notiz\nSYN-1;02.01.2026;12.345,67;Lot 12 of 40, ref 98.765,43\n"
    for columns in ((1, 2, 4), ("Konto", "Datum", "Notiz"), ("Notiz", 1, "Datum")):
        assert _amounts(text, SourceLayout(";", ",", ".", True, columns)) == [(2, 3, "12345.67")]
    for columns in ((1, 2), ("Konto", "Datum"), ()):  # a column with a date or a note left undeclared
        with pytest.raises(CellSource):
            _amounts(text, SourceLayout(";", ",", ".", True, columns))


@pytest.mark.parametrize("columns", [(5,), ("Kurs",), ("konto",), ("Konto ",), ("Betrag", "Betrag ")],
                         ids=["past-the-row", "no-such-name", "other-case", "trailing-space", "one-of-two-missing"])
def test_a_text_column_the_first_row_does_not_hold_refuses_the_file(columns):
    with pytest.raises(LayoutMismatchSource) as caught:
        _amounts("Konto;Datum;Betrag;Notiz\nSYN-1;x;12.345,67;y\n", SourceLayout(";", ",", ".", True, columns))
    assert caught.value.line == 1


def test_a_header_name_held_twice_refuses_the_file():
    with pytest.raises(LayoutMismatchSource):
        _amounts("Konto;Betrag;Konto\nSYN-1;12.345,67;x\n", SourceLayout(";", ",", ".", True, ("Konto",)))


def test_the_header_row_is_read_like_every_other_row():
    # Declaring a header only lets a text column be named: a digit in the first row is still read or refused.
    assert _amounts("Konto;12.345,67\nSYN-1;98.765,43\n") == [(1, 2, "12345.67"), (2, 2, "98765.43")]
    with pytest.raises(CellSource) as caught:
        _amounts("Konto;Betrag 2026\nSYN-1;98.765,43\n")
    assert (caught.value.line, caught.value.column) == (1, 2)


@pytest.mark.parametrize("raw,kind", [
    (codecs.BOM_UTF16 + EXPORT.encode("utf-16-le"), EncodingSource),
    (EXPORT.encode("utf-16-le"), EncodingSource),
    (EXPORT.encode("utf-16-be"), EncodingSource),
    (EXPORT.encode("utf-32"), EncodingSource),
    (EXPORT.encode() + b"\x00", EncodingSource),
    (EXPORT.replace("SYN-1", "M\u00fcller").encode("latin-1"), EncodingSource),
    (EXPORT.encode().replace(b"SYN-1", b"SYN\xff1"), EncodingSource),
    (EXPORT.encode().replace(b"SYN-1", b"SYN\xc0\xb11"), EncodingSource),
    (EXPORT.encode().replace(b"SYN-1", b"SYN\xed\xa0\x801"), EncodingSource),
    (codecs.BOM_UTF8 + codecs.BOM_UTF8 + EXPORT.encode(), HiddenMarkSource),
    (EXPORT.encode().replace(b"SYN-2", codecs.BOM_UTF8 + b"SYN-2"), HiddenMarkSource),
], ids=["utf-16", "utf-16-le-bare", "utf-16-be-bare", "utf-32", "nul", "latin-1", "invalid-byte", "overlong",
        "surrogate", "two-marks", "mark-inside"])
def test_bytes_that_are_not_strict_utf8_refuse_the_file(raw, kind):
    with pytest.raises(kind):
        source_amounts(raw, SEMICOLON)


def test_one_byte_order_mark_at_the_very_start_is_read():
    assert _amounts(codecs.BOM_UTF8 + EXPORT.encode()) == _amounts(EXPORT)
    assert _amounts(codecs.BOM_UTF8 + b"12.345,67\n", SourceLayout(";", ",", ".", False, ())) == [(1, 1, "12345.67")]


# Invisible and format characters, controls, separators, spaces and digits outside ASCII, symbols, a private-use
# and an unassigned code point: each refuses the file wherever it stands, in a text column too.
REFUSED_EVERYWHERE = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\xad", "\u200e", "\u202e", "\u2066", "\u061c",
                      "\u180e", "\u2062", "\u2800", "\x01", "\x0b", "\x0c", "\x1e", "\x7f", "\x85", "\u2028", "\u2029",
                      "\xa0", "\u2009", "\u202f", "\u2007", "\u3000", "\u1680", "\uff11", "\u0661", "\u00b2", "\u2167",
                      "\u00bd", "\u2460", "\u00b7", "\uff0e", "\u066b", "\uff0c", "\u2019", "\u2212", "\u00a2", "\u20b9",
                      "\ufffd", "\ue000", "\U000f0000", "\u0378", "\U0001f600", "\t"]


@pytest.mark.parametrize("character", REFUSED_EVERYWHERE, ids=[f"U+{ord(c):04X}" for c in REFUSED_EVERYWHERE])
@pytest.mark.parametrize("shape", ["Konto;Betrag\nSYN-1;98{c}765,43\n", "Konto;Betrag\nSYN{c}-1;98.765,43\n",
                                   "Konto;Betrag\nSYN-1;98.765,43{c}\n", "Kon{c}to;Betrag\nSYN-1;98.765,43\n",
                                   'Konto;Betrag\nSYN-1;"98.765{c},43"\n', "Konto;Betrag\nSYN-1;98.765,43\n{c}"],
                         ids=["in-an-amount", "in-a-text-column", "after-an-amount", "in-the-header", "in-quotes",
                              "after-the-rows"])
def test_a_character_no_source_may_hold_refuses_the_file_wherever_it_stands(character, shape):
    with pytest.raises(HiddenMarkSource):
        _amounts(shape.format(c=character), SourceLayout(";", ",", ".", True, (1,)))


def test_letters_outside_ascii_are_read_in_text_columns_and_nowhere_else():
    text = "Konto;Betrag;W\u00e4hrung\nM\u00fcller \u6771\u4eac e\u0301;12.345,67;\u20ac\n"
    assert _amounts(text, SourceLayout(";", ",", ".", True, (1, 3))) == [(2, 2, "12345.67")]
    with pytest.raises(HiddenMarkSource) as caught:  # the header of column 3, once that column is not text
        _amounts(text, SourceLayout(";", ",", ".", True, (1,)))
    assert (caught.value.line, caught.value.column) == (1, 3)
    with pytest.raises(HiddenMarkSource):
        _amounts("Konto;Betrag\nSYN-1;12.345,67 \u00fc\n")


def test_a_tab_is_read_only_as_the_declared_delimiter():
    tabbed = SourceLayout("\t", ",", ".", True, (1,))
    assert _amounts("Konto\tBetrag\nSYN-1\t12.345,67\n", tabbed) == [(2, 2, "12345.67")]
    with pytest.raises(CellSource):  # a tab inside a quoted cell is that cell's content, and no part of an amount
        _amounts('Konto\tBetrag\nSYN-1\t"12.345\t,67"\n', tabbed)


@pytest.mark.parametrize("text", ["Konto;Betrag\rSYN-1;12.345,67\r", "Konto;Betrag\nSYN-1;12.345\r,67\n",
                                  "Konto;Betrag\r\r\nSYN-1;12.345,67\n", "Konto;Betrag\nSYN-1;12.345,67\r"],
                         ids=["old-line-ends", "inside-a-cell", "doubled", "at-the-end-of-the-file"])
def test_a_carriage_return_that_does_not_end_a_line_refuses_the_file(text):
    with pytest.raises(HiddenMarkSource):
        _amounts(text)


@pytest.mark.parametrize("row", [
    'SYN-1;"98\n765,43"', 'SYN-1; "98\n765,43"', 'SYN-1;="98\n765,43"', 'SYN-1;"98\r\n765,43"', '"SYN\n-1";98.765,43',
    'SYN-1;"98.765,43', 'SYN-1;98.765,43"', 'SYN-1;98"765,43', 'SYN-1; "98.765,43"', 'SYN-1;"98.765,43" ',
    'SYN-1;="98.765,43"', 'SYN-1;"98.765",43"', 'SYN-1;"98.765,43"x', 'SYN-1;""98.765,43""', 'SYN-1;"98"".765,43',
    'SYN"-1;98.765,43', "SYN-1;'98.765,43\"",
], ids=["split", "space-then-split", "equals-then-split", "split-crlf", "split-text-cell", "left-open", "closing-only",
        "inside", "space-before", "space-after", "equals-before", "closed-early", "text-after", "doubled-around",
        "doubled-then-open", "inside-a-text-cell", "apostrophe-then-quote"])
def test_a_quote_that_does_not_open_and_close_one_whole_cell_on_one_line_refuses_the_file(row):
    with pytest.raises(MalformedQuotesSource) as caught:
        _amounts("Konto;Betrag\n" + row + "\nSYN-2;12.345,67\n")
    assert caught.value.line == 2


def test_a_quoted_cell_holds_the_delimiter_and_doubled_quotes_as_content():
    text = 'Konto;Betrag\n"Alpha; Beta ""B""";"12.345,67"\n"";"98.765,43"\n'
    assert _amounts(text) == [(2, 2, "12345.67"), (3, 2, "98765.43")]
    with pytest.raises(CellSource):  # the delimiter inside a quoted amount is content, and no part of an amount
        _amounts('Konto;Betrag\nSYN-1;"12.345;67"\n')


@pytest.mark.parametrize("text,line", [
    ("", 1), ("Konto;Betrag\nSYN-1;12.345,67;x\n", 2), ("Konto;Betrag\nSYN-1\n", 2),
    ("Konto;Betrag\n\nSYN-1;12.345,67\n", 2), ("Konto;Betrag\nSYN-1;12.345,67\n\n", 3),
    ("Report of 2026\nKonto;Betrag\nSYN-1;12.345,67\n", 2), ("Konto;Betrag\nSYN-1;12.345,67\nTotal\n", 3),
    ("Konto;Betrag\nSYN-1;12.345,67;\n", 2),
], ids=["empty", "wider", "narrower", "blank-line", "blank-last-line", "title-line", "total-line", "trailing-delimiter"])
def test_a_file_that_is_not_one_table_of_equal_rows_refuses(text, line):
    with pytest.raises(LayoutMismatchSource) as caught:
        _amounts(text, SourceLayout(";", ",", ".", True, ()))
    assert caught.value.line == line


def test_a_file_cut_by_another_delimiter_than_the_declared_one_is_refused():
    with pytest.raises(CellSource):  # one cell a row: `SYN-1,12345.67` is no amount
        _amounts("Account,Amount\nSYN-1,12345.67\n", SourceLayout(";", ".", None, True, ()))
    with pytest.raises(SourceRefused):
        _amounts("Konto;Betrag\nSYN-1;12.345,67\n", SourceLayout(",", ".", None, True, (1,)))


COMMA_LAYOUTS = [SourceLayout(",", ".", ",", True, (1,)), SourceLayout(",", ".", None, True, (1,)),
                 SourceLayout(",", ".", " ", False, ()), SourceLayout(",", ".", "'", True, (1, 2, 3))]


def test_a_comma_file_reads_grouping_commas_in_quoted_cells():
    text = 'Account,Amount\nSYN-1,"1,234,567.89"\nSYN-2,12345.67\nSYN-3,"(98,765.43)"\n'
    assert _amounts(text, COMMA_LAYOUTS[0]) == [(2, 2, "1234567.89"), (3, 2, "12345.67"), (4, 2, "98765.43")]
    with pytest.raises(CellSource):  # the same file, declared without grouping commas
        _amounts(text, COMMA_LAYOUTS[1])


@pytest.mark.parametrize("declared", COMMA_LAYOUTS, ids=["comma-groups", "no-groups", "space-groups", "all-text"])
@pytest.mark.parametrize("row,column", [
    ("SYN-1,1,234,567.89", 3), ("SYN-1,12,345.67", 3), ("SYN-1,(1,234)", 3), ("SYN-1,-1,234.50", 3), ("SYN-1,$1,234", 3),
    ("SYN-1,USD 12,345", 3), ("SYN-1,EUR7,123 x", 3), ("7,123,456", 2), (" 12,345", 2), ("SYN-1,x,123,456,789", 4),
], ids=["three-groups", "one-group", "bracket", "sign", "currency-sign", "currency-code", "code-glued", "first-cells",
        "space-before", "later-cells"])
def test_a_bare_comma_that_may_group_digits_refuses_a_comma_file_under_any_layout(declared, row, column):
    with pytest.raises(AmbiguousSource) as caught:
        _amounts("Account,Amount,Note\n" + row + "\n", declared)
    assert (caught.value.line, caught.value.column) == (2, column)


@pytest.mark.parametrize("row", ["SYN-1,1234,567.89", "SYN-1,12, 345", 'SYN-1,"12",345', 'SYN-1,12,"345"', "SYN-001,250,x",
                                 "SYN-1,12,3456", "SYN-1,12,34", "SYN-1,12.5,345", "SYN-1,12 ,345", "SYN-1,12 EUR,345"],
                         ids=["four-digits-first", "space-after", "first-quoted", "second-quoted", "identifier-first",
                              "four-digits-next", "two-digits-next", "fraction-first", "space-before-the-comma",
                              "currency-after-first"])
def test_a_comma_between_cells_that_can_not_be_one_grouped_amount_is_a_column_break(row):
    assert _amounts("Account,Amount,Note\n" + row + "\n", SourceLayout(",", ".", None, True, (1,)))


def test_only_a_comma_file_has_the_grouping_comma_check():
    assert _amounts("Account;Lots;Units\nSYN-1;12;345.67\n", SourceLayout(";", ".", ",", True, (1,))) == [
        (2, 2, "12"), (2, 3, "345.67")]


def test_a_last_line_may_end_with_the_file_and_a_last_empty_cell_is_a_cell():
    assert _amounts("Konto;Betrag\nSYN-1;12.345,67") == [(2, 2, "12345.67")]
    assert _amounts("Konto;Betrag;\nSYN-1;12.345,67;\n") == [(2, 2, "12345.67")]


def test_an_amount_of_more_digits_than_the_screen_reads_refuses_the_file():
    longest = "9" * forbidden_tokens.MAX_FIGURE_DIGITS
    assert _cell(longest, SEMICOLON) == [longest]
    for cell in (longest + "9", longest + ",5", "0" + longest):
        with pytest.raises(UnscreenableSource) as caught:
            _cell(cell, SEMICOLON)
        assert (caught.value.line, caught.value.column) == (2, 2)


@pytest.mark.parametrize("declared", [
    SourceLayout(",", ",", None, True, ()), SourceLayout(",", ",", ".", True, ()), SourceLayout(";", ",", ",", True, ()),
    SourceLayout(";", ".", ".", True, ()), SourceLayout(" ", ".", None, True, ()), SourceLayout(";", "'", None, True, ()),
    SourceLayout(";", ".", "_", True, ()), SourceLayout(";", ".", None, "yes", ()), SourceLayout(";", ".", None, True, [1]),
    SourceLayout(";", ".", None, True, (0,)), SourceLayout(";", ".", None, True, (1, 1)),
    SourceLayout(";", ".", None, True, (True,)), SourceLayout(";", ".", None, True, (1.0,)),
    SourceLayout(";", ".", None, True, ("",)), SourceLayout(";", ".", None, False, ("Konto",)),
    SourceLayout(";", ".", None, True, tuple(range(1, 66))), (";", ".", None, True, ()),
], ids=["comma-twice", "comma-twice-with-groups", "one-mark-two-roles", "point-two-roles", "space-delimiter",
        "apostrophe-decimals", "unknown-group-mark", "header-not-a-boolean", "columns-not-a-tuple", "position-zero",
        "position-twice", "boolean-position", "float-position", "empty-name", "name-without-a-header",
        "too-many-columns", "not-a-layout"])
def test_a_layout_with_an_unknown_mark_or_a_mark_of_two_roles_is_no_layout(declared):
    assert not figure_sources.layout_valid(declared)
    with pytest.raises(ValueError) as caught:
        source_amounts(b"12345.67\n", declared)
    assert not isinstance(caught.value, SourceRefused)


def test_an_amount_of_fewer_digits_than_the_minimum_is_read_and_not_listed():
    text = b"Konto;Betrag\nSYN-1;12.345,67\nSYN-2;7,5\nSYN-3;250.000\nSYN-4;347.300,00\n"
    assert read_source(text, SEMICOLON, 5) == ({"12345.67"}, {"1234567"}, set())
    assert read_source(text, SEMICOLON, 5, True) == ({"12345.67"}, {"1234567"}, {"347300"})
    assert read_source(text, SEMICOLON, 8)[0] == set()


def test_more_figures_than_one_snapshot_holds_refuse_the_source(monkeypatch):
    monkeypatch.setattr(figure_sources, "MAX_SOURCE_FIGURES", 3)
    plain = SourceLayout(";", ".", None, False, ())
    assert len(read_source(b"12345.1\n12345.2\n12345.3\n", plain, 5)[0]) == 3
    with pytest.raises(ValueError):
        read_source(b"12345.1\n12345.2\n12345.3\n12345.4\n", plain, 5)


# --- Through the loader: the codes, and what a refusal says. ---

REFUSALS = [
    ("Konto;Betrag\nSYN-1;12.345,67\nSYN-2;98.765,43 1)\n", "forbidden_token_source_cell_unreadable", (3, 2)),
    ("Konto;Betrag\nSYN-1;98\u200b765,43\n", "forbidden_token_source_hidden_mark", (2, None)),
    ("Konto;Betrag\nSYN-1;98.765,43 \u00fc\n", "forbidden_token_source_hidden_mark", (2, 2)),
    ('Konto;Betrag\nSYN-1; "98.765,43"\n', "forbidden_token_source_malformed_quotes", (2, 2)),
    ("Konto;Betrag\nSYN-1;98.765,43;x\n", "forbidden_token_source_layout_mismatch", (2, None)),
    ("Konto;Betrag\nSYN-1;" + "9" * 261 + "\n", "forbidden_token_source_unscreenable", (2, 2)),
    (EXPORT.encode("utf-16"), "forbidden_token_source_encoding", (None, None)),
]


@pytest.mark.parametrize("content,code,place", REFUSALS,
                         ids=[f"{index}-{code.removeprefix('forbidden_token_source_')}"
                              for index, (_content, code, _place) in enumerate(REFUSALS)])
def test_a_refusal_names_its_code_the_source_a_line_and_a_column_and_nothing_of_the_file(tmp_path, content, code,
                                                                                        place):
    good = layout(write_source(tmp_path, EXPORT, "good.csv"), text_columns=["Konto"])
    bad = layout(write_source(tmp_path, content, "bad.csv"), text_columns=["Konto"])
    with pytest.raises(AssistantError, match=f"^{code}$") as caught:
        load(good, bad)
    expected = {"source": 2, **{name: value for name, value in zip(("line", "column"), place, strict=True) if value is not None}}
    assert caught.value.public_details == expected and not caught.value.local_details
    assert str(caught.value) == code  # no path, no cell


def test_a_source_that_lists_no_figure_is_refused(tmp_path):
    for text, columns in (("Konto;Betrag\nSYN-1;7,5\n", ["Konto"]), ("Konto;Betrag\nSYN-1;12.345,67\n", [1, 2]),
                          ("Konto;Betrag\nSYN-1;n/a\n", [1])):
        with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
            load(layout(write_source(tmp_path, text), text_columns=columns))


def test_a_bare_path_is_never_opened(tmp_path, monkeypatch):
    monkeypatch.setattr(forbidden_tokens, "_read_token_file", lambda *_args, **_kwargs: pytest.fail("a file was read"))
    with pytest.raises(AssistantError, match="^forbidden_token_source_layout_required$"):
        load(write_source(tmp_path, EXPORT))


def test_a_loaded_source_refuses_each_amount_in_any_notation_and_nothing_it_does_not_hold(tmp_path):
    source = layout(write_source(tmp_path, EXPORT), text_columns=["Konto"])
    for match in ("value", "digits"):
        snapshot = load(source, forbidden_token_match=match)
        assert snapshot.listed == snapshot.source_figures == 4
        for text in ("12345.67", "12,345.67", "12 345,67", "(1,234,567.89)", "$98,765.43", "48213.5712"):
            assert refused(f"total {text} due", snapshot), (match, text)
        for text in ("12345", "345.67", "765.43", "234567.89", "98765", "213.5712"):
            assert not refused(f"total {text} due", snapshot), (match, text)
    assert refused("48213.57", load(source, **{"forbidden_token_match": "digits"}))
    assert not refused("48213.57", load(source))


def test_the_parse_cache_depends_on_the_layout_the_digit_minimum_and_the_round_setting(tmp_path):
    path = write_source(tmp_path, "Konto;Betrag\nSYN-1;12.345\nSYN-2;347.300\n")
    comma, point = layout(path, text_columns=[1]), layout(path, decimal_mark=".", group_mark=",", text_columns=[1])
    parsed = {}
    by_comma, by_point = load(comma, parsed=parsed), load(point, parsed=parsed)
    assert refused("12345", by_comma) and not refused("12.3450", by_comma)
    assert refused("12.3450", by_point) and not refused("12345", by_point)
    assert by_comma != by_point and len(parsed) == 2
    assert load(comma, parsed=parsed, forbidden_token_min_digits=4).listed == 2 and len(parsed) == 3
    listed = load(comma, parsed=parsed, **{"forbidden_token_round_figures": "list"})
    assert refused("347300", listed) and not refused("347300", by_comma) and len(parsed) == 4
    load(comma, parsed=parsed)
    assert len(parsed) == 4


@pytest.mark.alone
def test_a_thousand_row_export_lists_every_amount_in_time(tmp_path):
    generator = random.Random(20261125)
    amounts = [f"{generator.randrange(10_000, 10**9)}.{generator.randrange(1, 100):02d}".rstrip("0") for _ in range(1000)]
    rows = [f'SYN-{index:04d};2026-01-{index % 28 + 1:02d};"{int(amount.split(".")[0]):,}.{amount.split(".")[1]}";EUR'
            for index, amount in enumerate(amounts)]
    text = "Account;Date;Amount;Currency\n" + "\n".join(rows).replace(",", "'") + "\n"
    declared = layout(write_source(tmp_path, text), decimal_mark=".", group_mark="'", text_columns=["Account", "Date"])
    start = time.perf_counter()
    snapshot = load(declared)
    assert time.perf_counter() - start < 5
    assert snapshot.listed == len(set(amounts))
    assert all(refused(amount, snapshot) for amount in generator.sample(amounts, 40))


@pytest.mark.alone
def test_a_large_file_is_read_in_time():
    row = "SYN-0001;2026-01-02;1.234.567,89;EUR;M\u00fcller;(98.765,43)\n"
    raw = ("Konto;Datum;Betrag;Code;Name;Saldo\n" + row * 125_000).encode()
    assert 7_000_000 < len(raw) <= forbidden_tokens.MAX_SOURCE_BYTES
    start = time.perf_counter()
    assert read_source(raw, SourceLayout(";", ",", ".", True, (1, 2, "Name")), 5)[0] == {"1234567.89", "98765.43"}
    assert time.perf_counter() - start < 20


@pytest.mark.parametrize("module", ["figure_sources", "figure_source_entries", "forbidden_tokens", "config",
                                    "model_policy"])
def test_each_module_can_be_the_first_one_imported(module):
    result = subprocess.run([sys.executable, "-c", f"import finassist.{module}"], capture_output=True, text=True,
                            env=source_path(dict(__import__("os").environ)), cwd=Path(__file__).parent, timeout=120)
    assert result.returncode == 0, result.stderr


def test_the_entry_helper_builds_the_layout_the_reader_takes(tmp_path):
    entry = layout("/synthetic/positions.csv", text_columns=["Konto", 2])
    assert as_layout(entry) == SourceLayout(";", ",", ".", True, ("Konto", 2)) and figure_sources.layout_valid(as_layout(entry))
