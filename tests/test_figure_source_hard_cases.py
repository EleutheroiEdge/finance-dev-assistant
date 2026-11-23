"""Figure sources from an adversarial review: amounts a reading dropped, and realistic files it refused.

A comma file that does not quote its amounts cuts `1,234,567.89` into cells, which are listed whole; one that cuts
decimal commas such as `123,45` has rows wider than its header, and is refused. A total can share one cell with its
label; spreadsheets save UTF-16, cp1252, timestamps with milliseconds, footnotes and `="..."` markers. Every amount
must be listed, or the source refused; a file that reads one way must be read. Synthetic exports only.
"""

import pytest

from test_figure_source_formats import _refused, _source

from finassist.errors import AssistantError
from finassist.forbidden_tokens import load_token_snapshot


DIGITS = {"forbidden_token_match": "digits"}


def _snapshot(path: str, **rules):
    return load_token_snapshot({"forbidden_token_sources": [path], **rules}, ())


@pytest.mark.parametrize("text,amounts", [
    ("Account,CCY,Amount\nSYN1,USD,1,234,567.89\nSYN2,USD,2,345,678.91\n", ["1234567.89", "2345678.91"]),
    ("Date,Amount\n2026-01-02,1,234,567.89\n2026-01-03,2,345,678.91\n", ["1234567.89", "2345678.91"]),
    ("Account,CCY,Amount\nSYN1,USD,1,234,560.00\nSYN2,USD,9,876,540.00\nSYN3,USD,12345.67\n",
     ["1234560", "9876540", "12345.67"]),
    ("1,234,567.89,98765.43\n2,345,678.91,87654.32\n", ["1234567.89", "98765.43", "2345678.91", "87654.32"]),
    ("Account,Amount\nSYN1,123,456.78\nSYN2,98765.43\n", ["123456.78", "98765.43"]),
    ("Name,Amount\nA,12345.67\nBalance carried forward 60,927,718.98\n", ["12345.67", "60927718.98"]),
    ("Account;Amount\nA1;1,234,567.89\nB2;12,345.67\n", ["1234567.89", "12345.67"]),
    ("Account,Amount\nSYN1,1,234,567.89e2\n", ["123456789"]),
    ("Account,Amount\nSYN1,1,234,567.89e-2\n", ["12345.6789"]),
    ("Account,Amount\nSYN1,USD1,234,567.89E+2\n", ["123456789"]),
    ("Account,Amount\nSYN1,1,234,567.89e0002\n", ["123456789"]),
    ("Account,Amount\nSYN1,1,234,567.89e-0002\n", ["12345.6789"]),
    ("Account,Amount\nSYN1,USD1,234,567.89E+0002\n", ["123456789"]),
], ids=["grouped-text", "grouped-date", "grouped-round-tail", "grouped-headerless", "one-group", "unquoted-footer",
        "grouped-in-semicolon-file", "exponent", "negative-exponent", "code-and-exponent", "padded-exponent",
        "padded-negative-exponent", "code-and-padded-exponent"])
@pytest.mark.parametrize("match", ["value", "digits"])
def test_an_amount_an_unquoted_comma_file_cut_into_cells_is_listed(tmp_path, text, amounts, match):
    snapshot = _snapshot(_source(tmp_path, text), forbidden_token_match=match)
    for amount in amounts:
        assert _refused(amount, snapshot), amount


@pytest.mark.parametrize("text", [
    "Note,Amount,Fee\nSYN1,12345.67,123,45\nSYN2,98765.43,987,65\n",
    "Date,Amount\n2026-01-02,1.234,56\n2026-01-03,2.345,67\n",
    "Konto;Betrag;Notiz\nA1;12.345,67;Fonds; Anteil\nB2;98.765,43;frei\n",
], ids=["decimal-comma", "decimal-comma-after-date", "semicolon-in-text"])
def test_a_row_wider_than_its_header_is_refused_rather_than_read_short(tmp_path, text):
    # The delimiter stands unquoted inside a cell: `123,45` may be one amount or two cells. Refused, never short.
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _snapshot(_source(tmp_path, text))


@pytest.mark.parametrize("text,total", [
    ("Account,Amount\nSYN1,12345.67\nSYN2,23456.78\nTotal USD 87654.32\n", "87654.32"),
    ("Konto;Betrag\nA1;12.345,67\nB2;23.456,78\nKontostand: 87.654,32 EUR\n", "87654.32"),
    ("Konto;Betrag;Notiz\nA1;12.345,67;Rest 98.765,43 offen\n", "98765.43"),
], ids=["total-row", "german-balance", "note-column"])
def test_a_figure_inside_a_text_cell_is_listed(tmp_path, text, total):
    snapshot = _snapshot(_source(tmp_path, text))
    assert _refused(total, snapshot) and _refused("12345.67", snapshot)


@pytest.mark.parametrize("text", [
    "Date,Amount\n2026-01-02 14:30:45.123,12345.67\n2026-01-03 09:15:16.456,98765.43\n",
    "Date,Amount\n2026-01-02 14:30:45+01:00,12345.67\n2026-01-03 09:15:16+0100,98765.43\n",
    "Date,Amount\n2026-01-02T14:30:45Z,12345.67\n2026-01-03T09:15:16Z,98765.43\n",
    "Konto;Betrag\nA1;12.345,67[1]\nB2;98.765,43 123)\n",
    "Konto;Betrag\nA1;12.345,67 Haben\nB2;98.765,43 Soll\n",
    'Account,Amount\nSYN1,="12345.67"\nSYN2,="98765.43"\n',
], ids=["milliseconds", "time-zone", "utc", "footnotes", "soll-haben-words", "spreadsheet-text-marker"])
def test_a_realistic_file_that_reads_one_way_is_read(tmp_path, text):
    snapshot = _snapshot(_source(tmp_path, text))
    assert _refused("12345.67", snapshot) and _refused("98765.43", snapshot)


@pytest.mark.parametrize("encoding,text", [
    ("utf-16", "Konto\tBetrag\nA1\t12.345,67\nB2\t98.765,43\n"),
    ("cp1252", "Konto;Betrag\nA1;€12.345,67\nB2;98 765,43 €\n"),
], ids=["utf-16", "cp1252"])
def test_a_spreadsheet_encoding_is_read(tmp_path, encoding, text):
    path = tmp_path / "exports" / "positions.csv"
    path.parent.mkdir()
    path.write_bytes(text.encode(encoding))
    snapshot = _snapshot(str(path))
    assert _refused("12345.67", snapshot) and _refused("98765.43", snapshot)


@pytest.mark.parametrize("exponent", ["e200", "e9999"])
def test_a_number_beyond_the_limits_in_a_text_cell_does_not_hide_what_it_holds(tmp_path, exponent):
    # The payload screen reads such a span by its mantissa too, so the source lists that, never nothing.
    snapshot = _snapshot(_source(tmp_path, f"Account;Note\nSYN1;was 1,234,567.89{exponent} then\n"))
    assert _refused("1234567.89", snapshot)


def test_a_leading_decimal_comma_too_short_to_be_a_figure_does_not_refuse_the_source(tmp_path):
    snapshot = _snapshot(_source(tmp_path, "Name;Amount\nA;,5789\nB;12.345,67\n"))
    assert snapshot.listed == 1 and _refused("12345.67", snapshot)


def test_neighbouring_numeric_columns_are_not_fused_into_a_figure(tmp_path):
    # A date column beside a padded reference, and two small integer columns: no number spans their comma.
    snapshot = _snapshot(_source(tmp_path, "Date,Ref,Lots,Units,Value\n20261110,00012345,7,5,12345.67\n"),
                         **DIGITS)
    assert _refused("12345.67", snapshot)
    assert not _refused("20261110", snapshot) and not _refused("7.5", snapshot)
