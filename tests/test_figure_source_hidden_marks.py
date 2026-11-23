"""A figure source with a mark that hides part of a figure is refused, `forbidden_token_source_hidden_mark` (source
rules 26 and 27); grouping spaces of every locale the screen reads still list the whole figure. Synthetic only."""
import pytest

from finassist.errors import AssistantError
from finassist.forbidden_tokens import load_token_snapshot, screen_text

# Zero-width and joiner marks, bidirectional controls, variation selectors, tag characters, soft hyphen, fillers,
# controls, a byte-order mark inside the text, separators and spaces that group nothing.
MARKS = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\xad", "\u200e", "\u200f", "\u061c", "\u202a",
         "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\ufe0f", "\ufe00",
         "\U000e0100", "\U000e0041", "\U000e007f", "\u180e", "\u2062", "\u034f", "\u3164", "\u2800", "\x00", "\x0b",
         "\x0c", "\x1e", "\x85", "\u2028", "\u2029", "\u2008", "\u2002", "\u3000", "\u1680"]
SHAPES = ["Account,Amount\nSYN-1,98{m}765.43\n", "Note\nTotal 98{m}765.43 due\n", "Account,Total 98{m}765.43\nSYN-1,x\n",
          'Account,Amount\nSYN-1,"98{m}765.43"\n', "Account\tAmount\nSYN-1\t98{m}765.43\n",
          "Account,Amount\nSYN-1,98765{m}.43\n", "Konto;Betrag\nSYN-1;98.765{m},43\n"]
BREAKS = [('Note,Qty\n"Total 1,234,\n567.89",1\n', "1234567.89"), ('Note;Qty\n"Total 1 234\n567,89";1\n', "1234567.89"),
          ('Note,Qty\n"Total 12345\n.67",1\n', "12345.67"), ('Account,Amount\nSYN-1,"1,234,\n567.89"\n', "1234567.89"),
          ('Note,Qty\r\n"Total 1,234,\r\n567.89",1\r\n', "1234567.89"), ('A\tB\nx\t"98765\n.43"\n', "98765.43"),
          ('A|B\nx|"98 765\n,43"\n', "98765.43")]
# Grouping spaces and apostrophes the screen reads in a payload: read whole, exactly as before.
SEPARATORS = ["\xa0", "\u2009", "\u202f", "\u2007", " ", "'", "\u2019"]


def _load(tmp_path, raw: bytes, match="value"):
    path = tmp_path / "source.csv"
    path.write_bytes(raw)
    return load_token_snapshot({"forbidden_token_sources": [str(path)], "forbidden_token_match": match}, ())


def _refuses(snapshot, value):
    try:
        screen_text(f"total {value} today", snapshot)
    except AssistantError as exc:
        return exc.code == "forbidden_token_present"
    return False


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("mark", MARKS, ids=[f"U+{ord(m):04X}" for m in MARKS])
def test_a_mark_inside_a_figure_refuses_the_source(tmp_path, mark, shape, encoding):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, shape.format(m=mark).encode(encoding))


@pytest.mark.parametrize("text,value", BREAKS)
def test_a_line_break_inside_a_quoted_figure_refuses_the_source(tmp_path, text, value):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode("utf-8"))


@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
@pytest.mark.parametrize("separator", SEPARATORS, ids=[f"U+{ord(s):04X}" for s in SEPARATORS])
def test_grouping_spaces_still_list_the_whole_figure(tmp_path, separator, encoding, match):
    for text in (f"Konto;Betrag\nSYN-1;1{separator}234{separator}567,89\n",
                 f'Account,Amount\nSYN-1,"1{separator}234{separator}567.89"\n',
                 f"Note\nTotal 1{separator}234{separator}567.89 due\n"):
        assert _refuses(_load(tmp_path, text.encode(encoding), match), "1234567.89"), text


@pytest.mark.parametrize("mark", ["\u200b", "\u200e", "\ufeff", "\xad"])
def test_a_mark_beside_a_figure_but_not_inside_it_is_read(tmp_path, mark):
    snapshot = _load(tmp_path, f"Account;Amount\nSYN-A;{mark}98765.43{mark}\nSYN-B;x{mark}y\n".encode())
    assert _refuses(snapshot, "98765.43")
    # After a comma, read every way, the mark may follow a decimal comma under another reading: refused.
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, f"Account,Amount\nSYN-A,{mark}98765.43\n".encode())


def test_a_quoted_note_over_two_lines_is_read(tmp_path):
    snapshot = _load(tmp_path, b'Account,Note,Amount\nSYN-1,"first line\nsecond line",98765.43\n'
                               b'SYN-2,"ends 12\nnext word",12345.67\n')
    assert _refuses(snapshot, "98765.43") and _refuses(snapshot, "12345.67")


# Marks on both sides of a separator, bidirectional isolates around number groups, marks beside a quoted line break,
# fullwidth and Arabic separators across one, and NUL padding: each hides part of a figure.
MORE = ["Account,Amount\nSYN-1,98\u200b,\u200b765.43\n", "Account,Amount\nSYN-1,98765\u200b.\u200b43\n",
        "Account;Amount\nSYN-1;\u206698\u2069.\u2066765,43\u2069\n", 'Note,Qty\n"Total 98\u00ad\n765.43",1\n',
        'Note,Qty\n"Total 1,234,\u200b\n567.89",1\n', 'Note,Qty\n"Total 98\n\u200b765.43",1\n',
        'Note;Qty\n"Total 1\uff0c234\uff0c\n567\uff0e89";1\n', 'Note,Qty\n"Total 12345\n\uff0e67",1\n',
        "Account,Amount\nSYN-1,98\x00765.43\n" + "\x00" * 15, "Account,Amount\nSYN-1,98\u200b \u200b765.43\n"]


@pytest.mark.parametrize("text", MORE)
def test_marks_on_either_side_of_a_separator_or_a_break_refuse_the_source(tmp_path, text):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode("utf-8"))


def _load_declared(tmp_path, raw: bytes, delimiter, decimal_mark):
    path = tmp_path / "declared.csv"
    path.write_bytes(raw)
    entry = {"path": str(path), "delimiter": delimiter, "decimal_mark": decimal_mark}
    return load_token_snapshot({"forbidden_token_sources": [entry]}, ())


def test_a_quote_another_reading_opens_refuses_read_every_way_and_reads_declared(tmp_path):
    raw = b'Id,Note,Amount\n1,"see ref;""",98765.43\n2,normal,12345.67\n'
    with pytest.raises(AssistantError, match="^forbidden_token_source_malformed_quotes$"):
        _load(tmp_path, raw)  # read with `;`, its `;"""` opens a field never closed
    snapshot = _load_declared(tmp_path, raw, ",", ".")
    assert _refuses(snapshot, "98765.43") and _refuses(snapshot, "12345.67")


def test_a_declared_tab_file_with_a_comma_and_a_quote_in_a_text_cell_is_read(tmp_path):
    raw = b'Account\tAmount\tNote\nSYN-1\t98765.43\tsaid,"ship 12\nSYN-2\t34567.89\tok\n'
    snapshot = _load_declared(tmp_path, raw, "\t", ".")
    assert _refuses(snapshot, "98765.43") and _refuses(snapshot, "34567.89")


def test_utf16_without_a_byte_order_mark_is_still_refused_as_invalid(tmp_path):
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _load(tmp_path, "Account,Amount\nSYN-1,98765.43\n".encode("utf-16-le"))


LONGER = ['Note,Qty\n"Total 1,234,\n\t567.89",1\n', 'Account,Amount\nSYN-1,"98\t765.43"\n',
          "Account,Amount\nSYN-1,\u0669\u0668\u200b\u0667\u0666\u0665\u066b\u0664\u0663\n",
          "Account,Amount\nSYN-1,\uff19\uff18\u200b\uff17\uff16\uff15.\uff14\uff13\n",
          'Note;Qty\n"Total \u0661\u066c\u0662\u0663\n\u0664\u0665\u0666\u066b\u0667\u0668";1\n',
          'Note,Qty\n"Total 1,234,\n' + " " * 65 + '567.89",1\n', "Account,Amount\nSYN-1,98" + "\u200b" * 130 + "765.43\n",
          'Positions, Jan 2026\nAccount\tNote\tAmount\nSYN-1\t"Total 1,234,\n567.89"\t10000.00\n']


@pytest.mark.parametrize("text", LONGER)
def test_long_runs_tabs_in_quotes_and_other_digits_refuse_the_source(tmp_path, text):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode("utf-8"))


@pytest.mark.parametrize("raw", [b"Account,Amount\nSYN-1,98\x00765.43\n" + b"\x00" * 481,
                                 b"Account,Amount\nSYN-1,98\x00765.43\n" + b" \x00" * 150])
def test_nul_padding_never_hides_a_nul_inside_a_figure(tmp_path, raw):
    with pytest.raises(AssistantError, match="^forbidden_token_source_(hidden_mark|invalid)$"):
        _load(tmp_path, raw)


@pytest.mark.parametrize("raw", [b'Positions Report\nAccount\tAmount\tNote\n1001\t98765.43\tsaid,"ship 12\n'
                                 b"2001\t34567.89\tok\n"])
def test_a_title_line_above_a_tab_table_still_reads(tmp_path, raw):
    snapshot = _load_declared(tmp_path, raw, "\t", ".")  # read every way, its `,"` opens a quote never closed
    assert _refuses(snapshot, "98765.43") and _refuses(snapshot, "34567.89")


# Quoting that can't be read strictly, with every delimiter the readings try: refused, never read in part.
MALFORMED = [b'Note,Qty\n"Total 1,234,\n567.89" ,1\n', b'Note,Qty\n"Total 1,234,\n567.89" USD,1\n',
             b'Account,Amount\nSYN-1,"98\t765.43" \n', b'Note,Qty\n"Total 1,234,\n567.89\n',
             b'Account,Amount\nSYN-1,10000.00\nSYN-2,"1,234,\n567.89\n', b'A;B\nx;"98765,43"y;1\n',
             b'A|B\r\nx|"1 234\r\n567,89" |1\r\n']
# Quoted fields split by a lone carriage return: the hidden-mark refusal.
LONE_CR = [b'Note,Qty\r"Total 1,234,\r567.89",1\r', b'Account,Amount\rSYN-1,"1,234,\r567.89"\rSYN-2,10000.00\r']


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
@pytest.mark.parametrize("raw", MALFORMED)
def test_quoting_that_cannot_be_read_strictly_refuses_the_source(tmp_path, raw, encoding):
    with pytest.raises(AssistantError, match="^forbidden_token_source_malformed_quotes$"):
        _load(tmp_path, raw.decode().encode(encoding))


@pytest.mark.parametrize("raw", LONE_CR)
def test_a_figure_split_by_a_lone_carriage_return_in_quotes_refuses_the_source(tmp_path, raw):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, raw)


@pytest.mark.parametrize("eol", ["\n", "\r\n", "\r"])
@pytest.mark.parametrize("delimiter", [",", ";", "\t", "|"])
def test_well_formed_quoting_is_still_read_in_every_dialect(tmp_path, delimiter, eol):
    d = delimiter
    text = (f'"Account"{d}"Note"{d}"Amount"{eol}SYN-1{d}"say ""hi"""{d}"98765.43"{eol}'
            f'SYN-2{d}""{d}12345.67{eol}"SYN-3"{d}"two{eol}lines"{d}"34567.89"{eol}')
    for encoding in ("utf-8", "utf-16"):
        snapshot = _load_declared(tmp_path, text.encode(encoding), d, ".")
        assert all(_refuses(snapshot, value) for value in ("98765.43", "12345.67", "34567.89"))
        # Read every way, the file is refused: under another reading a closing quote is followed by `d`, not by
        # that reading's own delimiter, and csv would run the cell on past it. Declaring the layout reads it.
        with pytest.raises(AssistantError, match="^forbidden_token_source_malformed_quotes$"):
            _load(tmp_path, text.encode(encoding))


def test_a_quote_inside_an_unquoted_cell_is_a_character_of_it(tmp_path):
    snapshot = _load(tmp_path, b'Account,Note,Amount\nSYN-1,6" pipe,98765.43\nSYN-2,ok,12345.67\n')
    assert _refuses(snapshot, "98765.43") and _refuses(snapshot, "12345.67")


def test_a_declared_layout_reads_a_file_another_reading_would_refuse(tmp_path):
    raw = b'Account\tNote\tAmount\nSYN-1\tsize,"large\t98765.43\nSYN-2\tok\t12345.67\n'
    with pytest.raises(AssistantError, match="^forbidden_token_source_malformed_quotes$"):
        _load(tmp_path, raw)
    snapshot = _load_declared(tmp_path, raw, "\t", ".")
    assert _refuses(snapshot, "98765.43") and _refuses(snapshot, "12345.67")


# One delimiter's quote opens inside a cell another reading leaves unquoted, and a split figure follows.
OUT_OF_STEP = [b'Account,Flag,Note,Amount\nSYN-1,a;"b,"\nTotal 1,234,\n567.89",10000.00\n',
               b'Account,Flag,Note,Amount\nSYN-1,a;"b,";Total 98\t765.43",10000.00\n',
               b'Konto;Flag;Betrag\nSYN-1;1,"see;""",Summe 1.234.\n567,89";10000,00\n']


@pytest.mark.parametrize("raw", OUT_OF_STEP)
def test_readings_out_of_step_about_a_quote_refuse_the_source(tmp_path, raw):
    with pytest.raises(AssistantError, match="^forbidden_token_source_(malformed_quotes|hidden_mark)$"):
        _load(tmp_path, raw)


PAIRS = [(first, second) for first in (",", ";", "\t", "|") for second in (",", ";", "\t", "|") if first != second]


@pytest.mark.parametrize("inner,outer", PAIRS)
def test_a_quote_after_another_delimiter_then_a_multiline_field_refuses(tmp_path, inner, outer):
    d = outer
    text = f'Account{d}Flag{d}Note{d}Amount\nSYN-1{d}a{inner}"b{d}"\nTotal 1 234\n567.89"{d}10000.00\n'
    with pytest.raises(AssistantError, match="^forbidden_token_source_(malformed_quotes|hidden_mark)$"):
        _load(tmp_path, text.encode())
    try:
        snapshot = _load_declared(tmp_path, text.encode(), d, ".")
    except AssistantError as exc:
        assert exc.code.startswith("forbidden_token_source_")
    else:
        assert _refuses(snapshot, "1234567.89")


# A closing quote followed by a delimiter of another reading: that reading's csv runs the cell on past the quote, so
# `SYN-1,"1,234"<TAB>567.89` would list 567.89 alone. Only the reading's own delimiter, a line end or the end of the
# text may follow a closing quote; anything else refuses the source, read every way or declared.
DELIMITERS = (",", ";", "\t", "|")
ENDS = {"lf": "\n", "crlf": "\r\n", "cr": "\r", "eof": ""}
AFTER_QUOTE = [(own, other, end, inside, where) for own in DELIMITERS for other in DELIMITERS if other != own
               for end in ENDS for inside in ("", " ", "\n ") for where in ("cell", "line")]


def _after_quote(own, other, end, inside, where):
    eol = ENDS[end] or "\n"
    first = "SYN-1" + own if where == "cell" else ""
    return f'Account{own}Amount{eol}{first}"Total 1 234{inside}"{other}567.89{ENDS[end]}'


@pytest.mark.parametrize("own,other,end,inside,where", AFTER_QUOTE,
                         ids=["-".join((repr(o)[1:-1], repr(t)[1:-1], e, repr(i)[1:-1] or "none", w))
                              for o, t, e, i, w in AFTER_QUOTE])
def test_another_readings_delimiter_after_a_closing_quote_refuses_the_source(tmp_path, own, other, end, inside, where):
    raw = _after_quote(own, other, end, inside, where).encode()
    with pytest.raises(AssistantError, match="^forbidden_token_source_malformed_quotes$"):
        _load(tmp_path, raw)
    with pytest.raises(AssistantError, match="^forbidden_token_source_malformed_quotes$"):
        _load_declared(tmp_path, raw, own, ".")


@pytest.mark.parametrize("raw", [b'Account,Amount\nSYN-1,"1,234"\t567.89\n',
                                 b'Account;Amount\nSYN-1;"Total 1,234\n ",567.89\n',
                                 b'Account;Amount\n"Total 1,234\n ",567.89;10000.00\n',
                                 'Account;Amount\nSYN-1;"98\u200b",765.43\n'.encode(),
                                 'Account;Amount\n"98\u200b",765.43;10000.00\n'.encode()])
def test_the_reviewed_after_quote_examples_refuse_the_source(tmp_path, raw):
    with pytest.raises(AssistantError, match="^forbidden_token_source_malformed_quotes$"):
        _load(tmp_path, raw)
    delimiter = ";" if b";" in raw.split(b"\n")[0] else ","
    with pytest.raises(AssistantError, match="^forbidden_token_source_malformed_quotes$"):
        _load_declared(tmp_path, raw, delimiter, ".")


# Declared with another delimiter, a tab is a character of its cell: between two digits it hides as inside quotes.
TAB_IN_CELL = [("Account|Amount\r\nSYN-1|71\xad\t\u316471800.29\n", "|", "."),
               ("Account,Amount\rSYN-1,885 600 60\t\u31640.76,10000.00\r", ",", "."),
               ("Konto;Betrag\nSYN-1;98\t765,43\n", ";", ","), ("Amount\n98\t765.43\n", None, ".")]


@pytest.mark.parametrize("text,delimiter,mark", TAB_IN_CELL)
def test_a_tab_between_digits_of_a_declared_non_tab_layout_refuses_the_source(tmp_path, text, delimiter, mark):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load_declared(tmp_path, text.encode(), delimiter, mark)


def test_a_declared_tab_layout_still_reads_its_columns(tmp_path):
    snapshot = _load_declared(tmp_path, b"Account\tAmount\tPrice\nSYN-1\t98765.43\t12345.67\n", "\t", ".")
    assert _refuses(snapshot, "98765.43") and _refuses(snapshot, "12345.67")


# Beside an exponent mark or its sign, and after a decimal mark that starts a number: inside the number, so hidden.
NUMBER_PARTS = ["Account,Amount\nSYN-A,1.2345\u200be6\n", 'Account,Amount\nSYN-A,"1.2345\ne6"\n',
                "Account,Amount\nSYN-A,12.34e\u200b5\nSYN-B,99999.00\n", "Account,Amount\nSYN-A,12.34\u200be5\nSYN-B,99999.00\n",
                "Account,Amount\nSYN-A,12.34e+\u200b5\nSYN-B,99999.00\n", "Account,Amount\nSYN-A,12.34e\u200b+5\nSYN-B,99999.00\n",
                "Account,Amount\nSYN-A,3.473\u200be5\nSYN-B,99999.00\n", "Account,Amount\nSYN-A,.\u200b57891\n",
                "Note\nTotal .\u200b57891 due\n", 'Account,Amount\nSYN-1,".\n57891"\n', "Account;Amount\nSYN-A;,\u200b57891\n",
                'Account;Amount\nSYN-1;",\n57891"\n', "Account,Amount\nSYN-A,(.\u200b57891)\n"]


@pytest.mark.parametrize("text", NUMBER_PARTS)
def test_a_mark_beside_an_exponent_or_after_a_leading_decimal_mark_refuses_the_source(tmp_path, text):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode())


def test_an_exponent_and_a_leading_point_without_a_mark_are_still_read(tmp_path):
    snapshot = _load(tmp_path, b"Account,Amount,Rate\nSYN-A,1.2345e6,.57891\nSYN-B,98765.43,x\n")
    assert _refuses(snapshot, "1234500") and _refuses(snapshot, "0.57891") and _refuses(snapshot, "98765.43")


@pytest.mark.parametrize("raw", [b'Note\nsize,"large\n98765.43\n', b'Note\n1,"see ref;"""\n98765.43\n'])
def test_a_declared_one_column_source_checks_quotes_against_line_ends_only(tmp_path, raw):
    assert _refuses(_load_declared(tmp_path, raw, None, "."), "98765.43")


# Marks on both sides of a decimal mark that starts a number, or a filler before it: the walk takes the whole run.
LEADING_RUNS = ["Account,Amount\nSYN-A,\u200b.\u200b57891\n", "Note\nTotal \u200b.\u200b57891 due\n",
                "Account,Amount\nSYN-A,-\u200b.\u200b57891\n", 'Account,Amount\nSYN-1,"\n.\n57891"\n',
                "Account;Amount\nSYN-A;\u200b,\u200b57891\n", "Account,Amount\nSYN-A,\u3164.\u200b57891\n",
                "Account,Amount\nSYN-A,\u3164.57891\n", "Note\nTotal \uffa0.57891 due\n"]


@pytest.mark.parametrize("text", LEADING_RUNS)
def test_marks_around_a_leading_decimal_mark_refuse_the_source(tmp_path, text):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode())


# A visible letter before a decimal mark that starts a number: the readings still take `.57891` there.
AFTER_LETTERS = [("Account,Amount\nSYN-A,\u5143.\u200b57891\n", ","), ('Account,Amount\nSYN-A,"\u5143.\n57891"\n', ","),
                 ("Account;Amount\nSYN-A;\u5143,\u200b57891\n", ";"), ("Account,Amount\nSYN-A,USD.\u200b57891\n", ","),
                 ("Account;Amount\nSYN-A;USD,\u200b57891\n", ";"), ("Account,Amount\nSYN-A,x.\u200b57891\n", ","),
                 ('Account;Amount\nSYN-A;"USD,\n57891"\n', ";")]


@pytest.mark.parametrize("text,delimiter", AFTER_LETTERS)
def test_a_mark_after_a_leading_decimal_mark_after_a_letter_refuses_the_source(tmp_path, text, delimiter):
    for load in (lambda: _load(tmp_path, text.encode()), lambda: _load_declared(tmp_path, text.encode(), delimiter, ".")):
        with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
            load()
