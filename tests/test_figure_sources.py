"""How a figure source is read: its delimiter, its encoding and Indian digit grouping.

Every amount written into a cell is listed, or the whole source is refused: a source whose readings disagree is
refused as ambiguous, never read in part. Listing more numbers than a cell holds can only refuse more. Every figure,
file and name here is synthetic.
"""

import codecs
import csv
import io
import random

import pytest

from finassist.errors import AssistantError
from finassist import figure_sources, forbidden_tokens
from finassist.forbidden_tokens import TokenSnapshot, load_token_snapshot, screen_source, screen_text

# The two figures every export of the first table below is meant to list.
EXPECTED = {"1234567.89", "48213.57"}
# Other synthetic amounts, with their western notation, for the exports that need their own.
AMOUNTS = {"3141592.65": "3,141,592.65", "8675309.42": "8,675,309.42", "27182.81": "27,182.81",
           "16180.33": "16,180.33"}


# The figures of a source that is read, or REFUSED for one that is refused.
REFUSED = None


def _figures(raw: bytes | str, min_digits: int = 5) -> set[str] | None:
    try:
        return figure_sources._source_figures(raw.encode("utf-8") if isinstance(raw, str) else raw, min_digits)[0]
    except ValueError:  # ambiguous, unscreenable or with no reading left: the whole source is refused
        return REFUSED


def _holds(raw: bytes | str, amounts, min_digits: int = 5) -> bool:
    """Each amount is listed, or the source is refused."""
    figures = _figures(raw, min_digits)
    return figures is REFUSED or set(amounts) <= figures


def _reads(raw: bytes | str, amounts, min_digits: int = 5) -> bool:
    """The source is read, not refused, and each amount is listed: for a source that must be read."""
    figures = _figures(raw, min_digits)
    return figures is not REFUSED and set(amounts) <= figures


def _snapshot(tmp_path, raw: bytes | str, match: str = "value", name: str = "export.txt") -> TokenSnapshot:
    """The snapshot of one source file, loaded the way a configuration or a gate policy loads it."""
    path = tmp_path / name
    path.write_bytes(raw.encode("utf-8") if isinstance(raw, str) else raw)
    return load_token_snapshot({"forbidden_token_sources": [str(path)], "forbidden_token_match": match}, ())


def _refused(text: str, snapshot: TokenSnapshot, path: str | None = None) -> bool:
    try:
        screen_source(text, path, snapshot) if path else screen_text(text, snapshot)
    except AssistantError as exc:
        assert exc.code == "forbidden_token_present", exc.code
        return True
    return False


def _western(value: str) -> str:
    whole, _, fraction = value.partition(".")
    return f"{int(whole):,}" + ("." + fraction if fraction else "")


# --- Exports that were read correctly before: each still lists exactly its two figures -------------

READ_BEFORE = {
    "comma, grouped amounts quoted":
        'account,name,market_value,price\nSYN-0001,"Synthetic Fund A","1,234,567.89",48213.57\n',
    "semicolon, decimal comma":
        "account;name;market_value;price\nSYN-0001;Synthetic Fund A;1234567,89;48213,57\n",
    "semicolon, decimal comma, point groups":
        "account;name;market_value;price\nSYN-0001;Synthetic Fund A;1.234.567,89;48.213,57\n",
    "semicolon, many short decimal-comma cells":
        "account;market_value;price;w1;w2;w3\nSYN-0001;1234567,89;48213,57;7,5;2,25;0,5\n"
        "SYN-0002;1234567,89;48213,57;1,5;3,75;12\n",
    "bar":
        "account|name|market_value|price\nSYN-0001|Synthetic Fund A|1,234,567.89|48213.57\n",
    "UTF-8 with a byte-order mark":
        "\ufeffaccount,market_value,price\nSYN-0001,1234567.89,48213.57\n",
    "a Latin-1 byte in a name column":
        "account,name,market_value,price\nSYN-0001,Synthétique,1234567.89,48213.57\n".encode("latin-1"),
    "French narrow no-break space groups":
        "account;market_value;price\nSYN-0001;1\u202f234\u202f567,89;48\u202f213,57\n",
    "Swiss apostrophe groups":
        "account;market_value;price\nSYN-0001;1'234'567.89;48'213.57\n",
    "Arabic-Indic digits":
        "account,market_value,price\nSYN-0001,١٢٣٤٥٦٧.٨٩,"
        "٤٨٢١٣.٥٧\n",
    "scientific notation":
        "account,market_value,price\nSYN-0001,1.23456789e6,4.821357E+04\n",
}


@pytest.mark.parametrize("name", READ_BEFORE)
def test_an_export_that_was_read_before_lists_the_same_figures(name):
    assert EXPECTED <= _figures(READ_BEFORE[name])


def test_an_export_quoted_from_its_first_cell_is_read_declared_and_refused_read_every_way(tmp_path):
    # Read with `;`, the closing quote of `"SYN-0001"` is followed by `,`: csv would run that cell on past it, so
    # the quoting is not strict under every reading tried. Declared, only `,` is read, and it lists both figures.
    raw = 'account,name,market_value,price\n"SYN-0001","Synthetic Fund A","1,234,567.89","48213.57"\n'.encode()
    with pytest.raises(AssistantError, match="^forbidden_token_source_malformed_quotes$"):
        _snapshot(tmp_path, raw)
    assert EXPECTED <= figure_sources._source_figures(raw, 5, (",", "."))[0]


def test_space_separated_columns_are_read_as_text():
    # No delimiter splits the line, so each line is a text cell, and a text cell lists every number in it.
    assert _reads("account  market_value  price\nSYN-0001  1234567.89  48213.57\n", EXPECTED)


@pytest.mark.parametrize("raw", [
    "account\tmarket_value\nSYN-0001\t1234567.89\n".encode("utf-16-le"),                   # UTF-16 without its mark
    "name,note\nSynthetic,none\n",
])
def test_a_source_with_no_figure_under_any_reading_is_refused(tmp_path, raw):
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _snapshot(tmp_path, raw)


# --- Delimiters ----------------------------------------------------------------------------------

TAB_GROUPED = ("account\tmarket_value\nSYN-0001\t3,141,592.65\nSYN-0002\t8,675,309.42\n"
               "SYN-0003\t27,182.81\nSYN-0004\t16,180.33\n")
TAB_GROUPED_SAME_WIDTH = "account\tmarket_value\nSYN-0001\t3,141,592.65\nSYN-0002\t8,675,309.42\n"


@pytest.mark.parametrize("text, amounts", [
    (TAB_GROUPED, ("3141592.65", "8675309.42", "27182.81", "16180.33")),
    (TAB_GROUPED_SAME_WIDTH, ("3141592.65", "8675309.42")),
])
def test_tab_separated_rows_with_unquoted_grouped_amounts_list_the_amounts(text, amounts):
    # The pieces between the grouping commas may be listed as well; the amounts must be.
    assert _holds(text, amounts)


def _decimal_comma_table() -> tuple[str, set[str]]:
    """Semicolon rows of decimal-comma amounts, with more commas than semicolons, and some whole numbers."""
    generator = random.Random(20261114)
    rows, amounts = ["market_value;price;cost"], set()
    for number in range(12):
        cells = []
        for column in range(3):
            whole = generator.randrange(1_000_000, 9_999_999)
            cents = generator.randrange(11, 99)
            if number % 6 == 5 and column == 0:  # A whole number: this row has one comma fewer.
                cells.append(str(whole))
                amounts.add(str(whole))
            else:
                cells.append(f"{whole},{cents}")
                amounts.add(f"{whole}.{cents}".rstrip("0"))
        rows.append(";".join(cells))
    return "\n".join(rows) + "\n", amounts


def test_a_semicolon_table_with_decimal_commas_lists_its_amounts_not_the_pieces_between_commas():
    text, amounts = _decimal_comma_table()
    assert text.count(",") > text.count(";")
    figures = _figures(text)
    assert amounts <= figures


def test_a_file_with_lines_before_its_table_still_lists_the_table():
    # No delimiter makes a table of so short a file, so every reading is used.
    text = ("Synthetic statement\nPrepared for a test\n\naccount,name,market_value\n"
            'SYN-0001,Synthetic Fund A,"3,141,592.65"\nSYN-0002,Synthetic Fund B,27182.81\n')
    assert _holds(text, {"3141592.65", "27182.81"})


@pytest.mark.parametrize("text", [
    "3,141,592.65\n8,675,309.42\n",          # every line splits into the same three pieces
    '"3,141,592.65"\n"8,675,309.42"\n',
    "value\n3141592.65\n8675309.42\n",
    "3141592.65\r8675309.42\r",              # lines that end with a carriage return only
])
def test_a_single_column_of_amounts_is_listed_however_it_is_grouped(text):
    assert _holds(text, {"3141592.65", "8675309.42"})


def test_a_figure_in_the_first_cell_after_a_byte_order_mark_is_listed():
    assert _holds(codecs.BOM_UTF8 + b"3141592.65,27182.81\n8675309.42,16180.33\n", AMOUNTS)


# --- Whatever the commonest-delimiter rule listed ---------------------------------------------------

def _commonest_delimiter_figures(raw: bytes, min_digits: int = 5) -> set[str]:
    """The figures listed when one delimiter was chosen as the commonest in the first lines."""
    text = raw.decode("utf-8", errors="replace")
    delimiter = max(",;\t|", key=text[:8192].count)
    values = set()
    for row in csv.reader(io.StringIO(text, newline=""), delimiter=delimiter):
        for cell in row:
            for whole, fraction in figure_sources._cell_readings(cell):
                if forbidden_tokens._digit_forms(whole, fraction, min_digits) and (
                        fraction or not forbidden_tokens._is_date(whole.lstrip("0"))):
                    values.add(whole + ("." + fraction if fraction else ""))
    return values


def _generated_table(generator: random.Random) -> tuple[str, str, set[str]]:
    """(text, delimiter, the amounts written into it) for one small table, as a spreadsheet writes it."""
    delimiter = generator.choice(",;\t|")
    columns, amounts = generator.randrange(1, 6), set()

    def cell() -> str:
        kind = generator.randrange(6)
        if kind == 0:
            return generator.choice(["Synthetic Fund", "SYN-A", "note, with a comma", "a|b", "x;y", ""])
        if kind == 1:
            return generator.choice(["2026-11-14", "20261114", "7.5", "250", "12"])
        whole = generator.randrange(10_000, 10 ** generator.randrange(5, 10))
        fraction = "".join(generator.choice("0123456789") for _ in range(generator.randrange(0, 4)))
        canonical = str(whole) + ("." + fraction.rstrip("0") if fraction.rstrip("0") else "")
        if len(canonical.replace(".", "").strip("0")) < 5 or ("." not in canonical and forbidden_tokens._is_date(canonical)):
            return str(whole)  # Too few digits, or a day: not an amount this test follows.
        amounts.add(canonical)
        plain = str(whole) + ("." + fraction if fraction else "")
        grouped = f"{whole:,}" + ("." + fraction if fraction else "")
        if kind == 2 or not fraction:
            return generator.choice([plain, grouped, "$" + grouped, "(" + grouped + ")"])
        if kind == 3:
            return f"{whole:,}".replace(",", ".") + "," + fraction  # 1.234.567,89
        if kind == 4:
            return str(whole) + "," + fraction                       # 1234567,89
        return generator.choice([plain, "USD " + grouped])

    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=delimiter, lineterminator=generator.choice(["\n", "\r\n"]))
    writer.writerow(["column%d" % number for number in range(columns)])
    for _ in range(generator.randrange(2, 25)):
        writer.writerow([cell() for _ in range(columns)])
    return output.getvalue(), delimiter, amounts


def test_every_amount_a_table_holds_is_listed_or_the_table_refused():
    generator = random.Random(20261114)
    # 900 tables: a table quoted from a line's first cell is refused read every way (a closing quote followed by a
    # delimiter of another reading), about half of them, so 600 no longer held 400 that are read.
    tables = [_generated_table(generator) for _ in range(900)]
    read, refused, gained = 0, 0, 0
    for text, delimiter, amounts in tables:
        raw = text.encode("utf-8")
        before, after = _commonest_delimiter_figures(raw), _figures(raw)
        if after is REFUSED:
            refused += 1
            continue
        # Every amount written into a cell is listed, whichever delimiter the table uses.
        assert amounts <= after, (delimiter, sorted(amounts - after))
        read += 1
        gained += bool(amounts - before)
    # The set holds enough of each kind to mean something: many tables are read, and many hold an amount the
    # commonest delimiter alone would have missed.
    assert read >= 400 and gained >= 100, (read, refused, gained)


def test_a_table_the_commonest_delimiter_read_whole_keeps_every_figure():
    generator = random.Random(20261115)
    checked = 0
    for _ in range(600):
        text, _delimiter, _amounts = _generated_table(generator)
        chosen = max(",;\t|", key=text[:8192].count)
        widths = {len(row) for row in csv.reader(io.StringIO(text, newline=""), delimiter=chosen) if row}
        if len(widths) != 1:
            continue
        checked += 1
        figures = _figures(text)
        assert figures is REFUSED or _commonest_delimiter_figures(text.encode("utf-8")) <= figures
    assert checked > 300


# --- Indian grouping -----------------------------------------------------------------------------

INDIAN = 'account,market_value,price\nSYN-0001,"31,41,592.65",27182.81\nSYN-0002,"₹ 86,75,309.42","1,61,803"\n'


def test_a_quoted_cell_in_indian_grouping_is_listed():
    assert _holds(INDIAN, {"3141592.65", "27182.81", "8675309.42", "161803"})
    assert _holds("value\n12,34,56,789\n1,00,000.5\n", {"123456789", "100000.5"}, min_digits=4)


@pytest.mark.parametrize("cell", ["31,41,59,2.65", "314,15,92.65", "31,415,92.65", "3,1,41,592.65", "31,41,5926.5"])
def test_a_cell_that_is_not_grouped_as_any_notation_is_not_a_figure(cell):
    # No reading leaves such a cell whole, so the source is refused: never read as 3141592.65.
    figures = _figures('value\n27182.81\n"%s"\n' % cell)
    assert figures is REFUSED or "3141592.65" not in figures


@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("text", [
    "31,41,592.65", "total 31,41,592.65 due", "(31,41,592.65)", "₹31,41,592.65", "INR 31,41,592.65 only",
    "x = (31,41,592.65)", '{"market_value": "31,41,592.65"}', "0031,41,592.650",
])
def test_a_listed_figure_written_in_indian_grouping_is_refused(tmp_path, match, text):
    snapshot = _snapshot(tmp_path, "value\n3141592.65\n", match)
    assert _refused(text, snapshot) and _refused(text, snapshot, "notes.md") and _refused(text, snapshot, "cash.py")


def test_a_long_whole_number_in_indian_grouping_is_refused(tmp_path):
    snapshot = _snapshot(tmp_path, "value\n1234567891234\n")
    assert _refused("12,34,56,78,91,234", snapshot)
    assert not _refused("id 1,23,45,67,89,12,34 x", snapshot)  # The last group has two digits.


@pytest.mark.parametrize("text", [
    "31, 41, 592.65", "f(31, 41, 592.65)",   # separate arguments
    "31,41,59,2.65", "314,15,92.65",          # not groups of two before one group of three
    "31,41,592,65", "31.41.592,65",           # another separator after the last group, or groups joined by points
    "[3, 14, 15, 92, 65]", "31,41,593.65",
])
def test_indian_grouping_reads_nothing_that_is_not_grouped_that_way(tmp_path, text):
    # Matching by value: with digits, a row of digits is matched whatever joins it.
    snapshot = _snapshot(tmp_path, "value\n3141592.65\n")
    assert not _refused(text, snapshot)
    # The same holds for the western groups of the same figure.
    assert _refused("3,141,592.65", snapshot) and not _refused("3, 141, 592.65", snapshot)


def _wholes(text: str) -> set[str]:
    return {whole for whole, _fraction, exponent, _first, _last in forbidden_tokens._readings(text)
            if exponent is not None}


def test_indian_grouping_over_reads_code_no_more_than_western_grouping_does():
    # Arguments written with a space, versions and times are never joined, in either grouping.
    spaced = "call(1, 22, 333)\nrgb(12, 34, 567)\nversion = '10.12.345'\nwhen = '10:12:345'\nrange(12,34)\n"
    assert not {"122333", "1234567", "1012345", "1234"} & _wholes(spaced)
    # A list written without spaces is read as one number in either grouping, on purpose.
    assert "3224224" in _wholes("shape = [3,224,224]") and "322333" in _wholes("shape = [3,22,333]")
    # Only a row that ends in a group of three is read: `12,34` and `12,34,56` are not numbers.
    assert not {"1234", "123456"} & _wholes("pair = (12,34)\ntriple = (12,34,56)\n")


def test_a_long_row_of_two_digit_groups_is_read_in_bounded_work(tmp_path):
    snapshot = _snapshot(tmp_path, "value\n3141592.65\n")
    row =",".join(["12"] * 30_000)
    readings = sum(1 for _reading in forbidden_tokens._readings(row + ",345 and " + row + ",31,41,592.65"))
    assert readings < 40 * 60_000
    assert _refused(row + ",31,41,592.65", snapshot) and not _refused(row + ",345", snapshot)
    figure = "1," + ",".join(["23"] * 50) + ",456"  # 104 digits: a figure that starts its row is read whole.
    assert _refused(figure, _snapshot(tmp_path, "value\n%s\n" % figure.replace(",", ""), name="long.txt"))


# --- UTF-16 --------------------------------------------------------------------------------------

@pytest.mark.parametrize("encoded", [
    TAB_GROUPED.encode("utf-16"),
    codecs.BOM_UTF16_LE + TAB_GROUPED.encode("utf-16-le"),
    codecs.BOM_UTF16_BE + TAB_GROUPED.encode("utf-16-be"),
    codecs.BOM_UTF16_LE + TAB_GROUPED.replace("\n", "\r\n").encode("utf-16-le"),
])
def test_utf16_text_with_a_byte_order_mark_is_read(encoded):
    assert _reads(encoded, AMOUNTS)


def test_broken_utf16_is_read_as_far_as_it_goes_and_never_crashes():
    encoded = codecs.BOM_UTF16_LE + "value\n3141592.65\n".encode("utf-16-le") + b"\x00\xd8\x41"
    assert _reads(encoded, {"3141592.65"})
    for empty in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE + b"\x00"):
        assert _figures(empty) in (set(), REFUSED)


# --- Through the loading path: each source refuses its figures in ordinary notation -----------------

LOADED = {
    "tab, grouped": (TAB_GROUPED, AMOUNTS),
    "tab, grouped, UTF-16": (TAB_GROUPED.encode("utf-16"), AMOUNTS),
    "indian": (INDIAN, ("3141592.65", "8675309.42", "27182.81", "161803")),
    "single column": ("3,141,592.65\n8,675,309.42\n", ("3141592.65", "8675309.42")),
    "after a byte-order mark": (codecs.BOM_UTF8 + b"3141592.65,27182.81\n", ("3141592.65", "27182.81")),
    **{name: (raw, EXPECTED) for name, raw in READ_BEFORE.items()},
}


@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("name", LOADED)
def test_a_loaded_source_refuses_each_of_its_figures_in_western_notation(tmp_path, name, match):
    raw, amounts = LOADED[name]
    try:
        snapshot = _snapshot(tmp_path, raw, match)
    except AssistantError as error:
        # One column of `3,141,592.65` also reads as three cells: refused as ambiguous unless its layout is declared.
        assert error.code == "forbidden_token_source_ambiguous" and name == "single column", (name, error.code)
        return
    for amount in amounts:
        for text in (_western(amount), "total %s due" % _western(amount), "OPENING = %s  # synthetic" % amount):
            assert _refused(text, snapshot), (name, match, amount)
            assert _refused(text, snapshot, "notes.md")
    assert not _refused("total 5,550,123.45 due", snapshot)


@pytest.mark.parametrize("match", ["value", "digits"])
def test_a_loaded_decimal_comma_table_refuses_its_amounts(tmp_path, match):
    text, amounts = _decimal_comma_table()
    snapshot = _snapshot(tmp_path, text, match)
    assert snapshot.source_figures == len(amounts)
    for amount in sorted(amounts):
        assert _refused("total %s due" % _western(amount), snapshot), amount


def test_a_source_over_the_size_limit_is_still_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(forbidden_tokens, "MAX_SOURCE_BYTES", 64)
    assert _snapshot(tmp_path, "value\n3141592.65\n", name="small.txt").source_figures == 1
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _snapshot(tmp_path, "value\n" + "3141592.65\n" * 8, name="large.txt")


def test_a_table_that_holds_every_delimiter_lists_only_its_amounts():
    rows = ["SYN-%05d\t%s\tnote, with a comma; a bar | and more" % (number, f"{1_000_000 + 7 * number:,}.25")
            for number in range(3_000)]
    assert _reads("account\tmarket_value\tnote\n" + "\n".join(rows) + "\n",
                  {"%d.25" % (1_000_000 + 7 * number) for number in range(3_000)})
