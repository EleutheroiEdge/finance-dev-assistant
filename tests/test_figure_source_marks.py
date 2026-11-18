"""Amounts in figure sources written with a mark, and sources saved with a byte-order mark.

A credit or debit mark, a currency code with such a mark, an asterisk or a footnote reference after an amount used
to make the cell read as text, so the amount was not listed. A byte-order mark became part of the first cell, so a
headerless export lost its first amount or was refused. Synthetic exports only.
"""

import pytest

from test_figure_source_formats import _refused, _source

from finassist.forbidden_tokens import load_token_snapshot

BOM = chr(0xFEFF)


def _both(path: str, delimiter: str, decimal_mark: str):
    declared = {"path": path, "delimiter": delimiter, "decimal_mark": decimal_mark}
    return [load_token_snapshot({"forbidden_token_sources": [entry]}, ()) for entry in (path, declared)]


@pytest.mark.parametrize("cell,delimiter,decimal_mark", [
    ("12.345,67 S", ";", ","),
    ("12.345,67 H", ";", ","),
    ("12.345,67 EUR H", ";", ","),
    ("12,345.67 CR", "\t", "."),
    ("12,345.67 DR", "\t", "."),
    ("USD 12,345.67 Cr", "\t", "."),
    ("12,345.67*", "\t", "."),
    ("12,345.67 (e)", "\t", "."),
    ("12,345.67 1)", "\t", "."),
    ("12.345,67 [2]", ";", ","),
], ids=["soll", "haben", "code-and-haben", "credit", "debit", "code-and-credit", "asterisk", "estimate", "footnote",
        "bracket-footnote"])
def test_an_amount_with_a_mark_is_listed_read_every_way_and_declared(tmp_path, cell, delimiter, decimal_mark):
    rows = [f"Konto{delimiter}Betrag", f"SYN-1{delimiter}{cell}", f"SYN-2{delimiter}{cell.replace('12', '98', 1)}"]
    for snapshot in _both(_source(tmp_path, "\n".join(rows) + "\n"), delimiter, decimal_mark):
        assert _refused("12345.67", snapshot) and _refused("98345.67", snapshot), cell


@pytest.mark.parametrize("text,delimiter,decimal_mark,first", [
    (f"{BOM}SYN-1;12.345,67 EUR\nSYN-2;23.456,78 EUR\n", ";", ",", "12345.67"),
    (f"{BOM}USD 12,345.67\tSYN-1\nUSD 23,456.78\tSYN-2\n", "\t", ".", "12345.67"),
    (f"{BOM}12345,67;98765,43\n23456,78;87654,32\n", ";", ",", "12345.67"),
], ids=["code-after", "code-before", "no-code"])
def test_a_headerless_source_with_a_byte_order_mark_lists_its_first_amount(tmp_path, text, delimiter, decimal_mark,
                                                                           first):
    for snapshot in _both(_source(tmp_path, text), delimiter, decimal_mark):
        assert _refused(first, snapshot) and _refused("23456.78", snapshot)


def test_a_figure_file_with_a_byte_order_mark_is_read(tmp_path):
    path = tmp_path / "figures.txt"
    path.write_text(f"{BOM}12345.67\n98765.43\n", encoding="utf-8", newline="\n")
    snapshot = load_token_snapshot({"forbidden_token_file": str(path)}, ())
    assert snapshot.line_count == 2 and _refused("12345.67", snapshot) and _refused("98765.43", snapshot)


def test_text_is_still_text_and_a_footnote_is_not_a_figure(tmp_path):
    rows = ["Account;Description;Value", "SYN-1;Global Equity Fund 2) ;12.345,67", "Total 3);;98.765,43 1)"]
    snapshot = load_token_snapshot({"forbidden_token_sources": [_source(tmp_path, "\n".join(rows) + "\n")]}, ())
    assert snapshot.listed == 2 and _refused("12345.67", snapshot) and _refused("98765.43", snapshot)


def test_one_column_with_comma_groups_reads_two_ways_until_its_layout_is_declared(tmp_path):
    source = _source(tmp_path, "Amount\n12,345.67\n23,456.78\n")
    with pytest.raises(Exception, match="forbidden_token_source_ambiguous"):
        load_token_snapshot({"forbidden_token_sources": [source]}, ())
    declared = load_token_snapshot({"forbidden_token_sources": [{"path": source, "delimiter": None,
                                                                 "decimal_mark": "."}]}, ())
    assert declared.listed == 2 and _refused("12345.67", declared) and not _refused("345.67", declared)
