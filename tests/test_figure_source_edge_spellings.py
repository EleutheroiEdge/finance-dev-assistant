"""Spellings a figure source reader once listed in part or not at all (source rules 26 and 27). Synthetic only.

A bracketed amount grouped by spaces, whose last group reads like a footnote `432)`; an amount whose eight digits
name a day, written with groups, cents, a sign or a code; a file that mixes UTF-8 with bytes that are not UTF-8, or
holds a byte Windows-1252 does not define; a visible look-alike of a grouping or decimal mark between two digits; a
currency sign, bracket or percent sign beside a mark inside a number; and a dash as an exponent's sign. Each is
listed whole or refused by name, never listed in part.
"""
import codecs

import pytest

from finassist.errors import AssistantError
from finassist.figure_sources import _source_figures
from finassist.forbidden_tokens import load_token_snapshot, screen_text

SPACES = [" ", "\xa0", " ", " ", " "]
LAYOUTS = [None, (";", "."), (";", ",")]


def _load(tmp_path, raw: bytes, layout=None, match="value"):
    path = tmp_path / "source.csv"
    path.write_bytes(raw)
    entry = str(path) if layout is None else {"path": str(path), "delimiter": layout[0], "decimal_mark": layout[1]}
    return load_token_snapshot({"forbidden_token_sources": [entry], "forbidden_token_match": match}, ())


def _refuses(snapshot, value):
    try:
        screen_text(f"total {value} today", snapshot)
    except AssistantError as exc:
        return exc.code == "forbidden_token_present"
    return False


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize("space", SPACES, ids=[f"U+{ord(s):04X}" for s in SPACES])
def test_a_bracketed_amount_grouped_by_spaces_is_listed_whole(space, layout):
    other = "12345.67" if layout is None or layout[1] == "." else "12345,67"
    for cell, value in ((f"(98{space}765{space}432)", "98765432"), (f"(17{space}114)", "17114"),
                        (f"Total loss (98{space}765{space}432)", "98765432"), (f"(1{space}234{space}567) 1)", "1234567")):
        values = _source_figures(f"Account;Amount\nSYN-1;{cell}\nSYN-2;{other}\n".encode(), 5, layout)[0]
        assert value in values, (cell, layout)


@pytest.mark.parametrize("layout", [None, (",", "."), (None, ".")])
def test_a_bracketed_amount_is_listed_whole_in_a_comma_file_and_one_column(layout):
    text = ("(98 765 432)\n12345.67\n" if layout == (None, ".")
            else "Account,Amount,CCY\nSYN-1,(98 765 432),EUR\nSYN-2,12345.67,EUR\n")
    assert "98765432" in _source_figures(text.encode(), 5, layout)[0]


def test_a_footnote_after_an_amount_is_still_left_out():
    values = _source_figures(b"Account;Amount\nSYN-1;12345.67 1)\nSYN-2;98765.43 [2]\n", 5)[0]
    assert {"12345.67", "98765.43"} <= values


DATED = [("20,170,520.00", None, "20170520"), ("USD 19,991,231", None, "19991231"), ("20170520.00", None, "20170520"),
         ("(20170520)", None, "20170520"), ("-20170520", None, "20170520"), ("20 170 520", None, "20170520"),
         ("20.170.520,00 EUR", (";", ","), "20170520"), ("20170520,50", (";", ","), "20170520.5"),
         ("Total USD 20170520", None, "20170520"), ("Total 20,170,520.00 net", None, "20170520"),
         ("EUR 20170520 H", None, "20170520"), ("2017052e1", None, "20170520")]


@pytest.mark.parametrize("cell,layout,value", DATED)
def test_an_amount_whose_digits_name_a_day_is_a_figure_once_written_as_an_amount(tmp_path, cell, layout, value):
    other = "12.345,67" if layout and layout[1] == "," else "12345.67"
    raw = f"Account;Amount\nSYN-1;{cell}\nSYN-2;{other}\n".encode()
    assert value in _source_figures(raw, 5, layout)[0]
    assert _refuses(_load(tmp_path, raw, layout), value)


@pytest.mark.parametrize("layout", LAYOUTS)
def test_a_bare_date_of_eight_digits_is_still_not_a_figure(layout):
    other = "12.345,67" if layout and layout[1] == "," else "12345.67"
    for cell in ("20170520", '"20170520"', "Value date 20170520"):
        values = _source_figures(f"Account;Booked;Amount\nSYN-1;{cell};{other}\n".encode(), 5, layout)[0]
        assert "20170520" not in values and values, cell


MIXED = [b"Konto;Betrag;Notiz\nSYN-1;98\xc2\xa0765,43;x\nSYN-2;12345,67;M\xfcller\n",
         b"Konto;Betrag;Notiz\nSYN-1;98\xe2\x80\x99765.43;x\nSYN-2;12345.67;M\xfcller\n",
         "Account;Amount;Note\nSYN-1;９８７６５.43;x\nSYN-2;12345.67;".encode() + b"caf\xe9\n",
         b"\xef\xbb\xbfAccount;Amount\nSYN-1;98765.43\nSYN-2;12345.67;M\xfcller\n"]
UNDEFINED = [b"Account;Amount\nSYN-1;EUR 98" + bytes([byte]) + b"765.43\nSYN-2;12345.67\n"
             for byte in (0x81, 0x8D, 0x8F, 0x90, 0x9D)] + [b"Account;Amount;Note\nSYN-1;98765.43;\x81\n"]


@pytest.mark.parametrize("layout", [None, (";", ","), (";", ".")])
@pytest.mark.parametrize("raw", MIXED + UNDEFINED)
def test_a_file_that_mixes_encodings_or_holds_an_undefined_byte_is_refused_by_name(tmp_path, raw, layout):
    with pytest.raises(AssistantError, match="^forbidden_token_source_encoding$"):
        _load(tmp_path, raw, layout)


def test_a_windows_export_is_still_read():
    raw = "Konto;Betrag;Notiz\nSYN-1;98\xa0765,43;M\xfcller €\nSYN-2;1.234.567,89;Gr\xfc\xdfe\n".encode("cp1252")
    for layout in (None, (";", ",")):
        assert {"98765.43", "1234567.89"} <= _source_figures(raw, 5, layout)[0], layout


@pytest.mark.parametrize("codec", ["utf-32-le", "utf-32-be", "utf-16-le", "utf-16-be"])
def test_a_file_marked_utf_16_or_utf_32_is_read(codec):
    bom = {"utf-32-le": codecs.BOM_UTF32_LE, "utf-32-be": codecs.BOM_UTF32_BE, "utf-16-le": codecs.BOM_UTF16_LE,
           "utf-16-be": codecs.BOM_UTF16_BE}[codec]
    raw = bom + "Account;Amount\nSYN-1;98 765,43\n".encode(codec)
    assert "98765.43" in _source_figures(raw, 5, None)[0]


@pytest.mark.parametrize("raw", [b"Account;Amount\nSYN-1;98\xef\xbf\xbd765.43\n",
                                 codecs.BOM_UTF16_LE + "Account;Amount\nSYN-1;98".encode("utf-16-le") + b"\x00\xd8"
                                 + "765.43\n".encode("utf-16-le")])
def test_a_replacement_character_between_digits_is_a_hidden_mark(tmp_path, raw):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, raw)


# Look-alikes of a grouping or decimal mark that no reading takes for one: a middle dot, a low quote, small,
# ideographic and Arabic commas, primes, accents, a fullwidth apostrophe, modifier letters, a one-dot leader, a dot
# above, a Greek ano teleia and a bullet operator.
LOOK_ALIKES = ["·", "‚", "﹐", "﹑", "、", "،", "′", "‵", "´", "`", "＇",
               "ʼ", "ʹ", "ʻ", "ˈ", "ʽ", "․", "˙", "·", "∙", "ˌ",
               "ꞌ", "՝", "⸴"]
SHAPES = ["Account;Amount\nSYN-1;EUR 98{c}765.43\nSYN-2;12345.67\n", "Account;Amount\nSYN-1;98{c}765{c}432.10\n",
          "Account;Note\nSYN-1;Total 98{c}765.43 net\n", "Account;Amount\nSYN-1;GBP 98765{c}43\n",
          'Account,Amount\nSYN-1,"USD 98{c}765.43"\n', "USD 98{c}765{c}432.10\n12345.67\n",
          "Konto;Betrag\nSYN-1;98{c}765,43 EUR\n", "Account;Amount\nSYN-1;98,{c}765.43\n"]


@pytest.mark.parametrize("layout", [None, (";", "."), (";", ",")])
@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("character", LOOK_ALIKES, ids=[f"U+{ord(c):04X}" for c in LOOK_ALIKES])
def test_a_look_alike_of_a_mark_between_digits_refuses_the_source(tmp_path, character, shape, layout):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, shape.format(c=character).encode(), layout)


@pytest.mark.parametrize("text", ["Account;Amount\nSYN-1;EUR 98٬765.43\n", "Account;Amount\nSYN-1;98٫765,43\n",
                                  "Account;Amount\nSYN-1;98，765,43\n", "Account;Amount\nSYN-1;98.765．43\n"])
def test_one_number_that_writes_two_characters_of_one_mark_is_refused(tmp_path, text):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode())


# A look-alike counts wherever a hidden mark would: beside a grouping or hidden space, a quoted line break or tab, an
# exponent mark or its sign, or right before the digits it may start; and two marks of one class anywhere in a number.
BESIDE = [("Account;Amount\nSYN-1;EUR 98\u00b7\u2008765.43\n", None), ("Account;Note\nSYN-1;Total 98\u02bc\u3000765.43\n", None),
          ('Account,Amount\nSYN-1,"Total 98\u201a\n765.43"\n', None), ('Account,Amount\nSYN-1,"EUR 1\u02bc234\u02bc\n567.89"\n', None),
          ('Account,Amount\nSYN-1,"EUR 98\u00b7\t765.43"\n', None), ("Account;Amount\nSYN-1;EUR 98\u00b7\t765.43\n", (";", ".")),
          ("Account;Amount\nSYN-1;EUR 98\u00b7\xa0765.43\n", None), ("Account;Amount\nSYN-1;EUR 98\u060c\u202f765.43\n", None), ("Account;Amount\nSYN-1;EUR 1.2345\u00b7e6\n", None),
          ("Account;Amount\nSYN-1;EUR 12.34e\u02bc5\nSYN-2;99999.00\n", None),
          ("Account;Amount\nSYN-1;EUR 12.34e+\u00b75\nSYN-2;99999.00\n", None),
          ("Account;Amount\nSYN-1;USD.\u00b757891\n", None), ("Account;Amount\nSYN-1;USD,\u00b757891\n", None),
          ("Account;Amount\nSYN-1;1\u066c234 567.89\n", None), ("Account;Amount\nSYN-1;98\u066c.765\n", None)]


@pytest.mark.parametrize("declare", [False, True])
@pytest.mark.parametrize("text,layout", BESIDE)
def test_a_look_alike_beside_a_space_a_break_an_exponent_or_before_digits_refuses_the_source(tmp_path, text, layout,
                                                                                            declare):
    if layout and not declare:
        pytest.skip("an unquoted tab read every way is the tab reading's column break, the stated residual")
    layout = layout or ((";", ".") if text.startswith("Account;") else (",", "."))
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode(), layout if declare else None)


@pytest.mark.parametrize("layout", [None, (";", "."), (";", ",")])
@pytest.mark.parametrize("text", ["Account;Amount\nSYN-1;USD\u00b757891\n", "Account;Note\nSYN-1;Total \u00b757891\n",
                                  "Account;Note\nSYN-1;Total \u202457891\n", "Account;Amount\nSYN-1;USD\u201a57891\n",
                                  "Account;Amount\nSYN-1;\u02bc57891\n", "Account;Note\nSYN-1;Ref \u00a757891\n"])
def test_a_look_alike_right_before_digits_lists_their_fraction_too(text, layout):
    values = _source_figures(text.encode(), 5, layout)[0]
    assert {"57891", "0.57891"} <= values, (text, layout)


@pytest.mark.parametrize("character", ["\u201a", "\u060c", "\u00b7", "\u2192", "\u00a7", "`"])
def test_a_look_alike_beside_an_ascii_space_parts_numbers_as_a_comma_and_space_does(character):
    for shape in ("Account;Note\nSYN-1;Total 98{c} 765.43\n", "Account;Note\nSYN-1;Total 98 {c}765.43\n",
                  "Account;Note\nSYN-1;Total 98 {c} 765.43\n"):
        values = _source_figures(shape.format(c=character).encode(), 5, None)[0]
        assert "765.43" in values and values - {"0.76543"} == _source_figures(shape.format(c=",").encode(), 5, None)[0] - {
            "0.76543"}, (shape, character)


# Full-width brackets and percent signs are not cell edges: such a cell is refused as a fragment, as at 73de845.
@pytest.mark.parametrize("cell", ["\u20ac75 929 683 CR", "\u00a312,345.67", "\u20b998,765.43", "\u00a5-12,345.67"])
def test_a_sign_beside_an_amount_after_a_comma_is_read_as_before(tmp_path, cell):
    text = f"Account,Kind,Amount,Note\nSYN-1,Cash,{cell},98765\nSYN-2,Cash,12345.67,x\n"
    for layout in (None, (",", ".")):
        assert "12345.67" in _source_figures(text.encode(), 5, layout)[0], layout
    # With a digit beyond the comma, read every way the comma may be a decimal mark inside the number, as in
    # `98,<euro>765.43`, so the source is refused; declared, the comma is a column break and it reads as before.
    text = text.replace("Cash,", "Bond 2031,", 1)
    assert "12345.67" in _source_figures(text.encode(), 5, (",", "."))[0]
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode())


# A sign is a mark when no letter, space or delimiter stands beside it: a decimal or grouping mark, an exponent mark
# or its sign, or the grave accent do not part it from the number, as in `EUR 98765\u20ac.43` or `1.2345\u20ace6`.
SIGNS = ["\u20ac", "\u00a3", "\uff08", "\uff09", "\u066a", "\u2030"]
INSIDE = ["Account;Amount\nSYN-1;EUR 98765{s}.43\n", "Account;Amount\nSYN-1;EUR 98765.{s}43\n",
          "Account;Amount\nSYN-1;EUR 98765{s},43\n", "Account;Amount\nSYN-1;EUR 98,{s}765.43\n",
          "Account;Amount\nSYN-1;EUR 98{s},765.43\n", "Account;Amount\nSYN-1;EUR 98'{s}765.43\n",
          "Account;Amount\nSYN-1;EUR 98{s}'765.43\n", "Account;Amount\nSYN-1;EUR 98`{s}765.43\n",
          "Account;Amount\nSYN-1;EUR 1.2345{s}e6\n", "Account;Amount\nSYN-1;EUR 1.2345e{s}6\nSYN-2;99999.00\n",
          "Account;Amount\nSYN-1;EUR 12.34e+{s}5\nSYN-2;99999.00\n", "Account;Amount\nSYN-1;EUR 12.34E{s}-5\n",
          'Account,Amount\nSYN-1,"EUR 98765{s},43"\n', 'Account,Amount\nSYN-1,"EUR 98,{s}765.43"\n',
          "Account;Note\nSYN-1;Total.{s}57891\n"]


@pytest.mark.parametrize("declare", [None, ".", ","])
@pytest.mark.parametrize("shape", INSIDE)
@pytest.mark.parametrize("sign", SIGNS, ids=[f"U+{ord(s):04X}" for s in SIGNS])
def test_a_sign_beside_a_mark_inside_a_number_refuses_the_source(tmp_path, sign, shape, declare):
    if declare == "," and shape.startswith("Account,"):
        pytest.skip("a comma file with decimal commas can't be declared")
    layout = None if declare is None else ((";" if shape.startswith("Account;") else ","), declare)
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, shape.format(s=sign).encode(), layout)


# An ASCII space parts numbers only when what stands on the look-alike's other side does not hide too: a hidden
# mark, a quoted line break or tab, or a sign. And a look-alike beside another mark before digits refuses the source.
PAIRED = ["Account;Note\nSYN-1;Total {c}\u200b57891\n", "Account;Note\nSYN-1;Total {c}\u00ad57891\n",
          "Account;Note\nSYN-1;Total {c}\u2008 57891\n", "Account;Note\nSYN-1;Total 98 {c}\u2060765.43\n",
          "Account;Note\nSYN-1;Total 98\u200b{c} 765.43\n", 'Account,Note\nSYN-1,"Total {c}\n57891"\n',
          'Account,Note\nSYN-1,"Total {c}\t57891"\n', 'Account,Note\nSYN-1,"Total 98\r\n{c} 765.43"\n',
          "Account;Note\nSYN-1;Total {c}\u20ac57891\n", "Account;Note\nSYN-1;Total{c}\u20ac57891\n",
          "Account;Note\nSYN-1;Total 98 {c}\uff08765.43\n"]


@pytest.mark.parametrize("declare", [False, True])
@pytest.mark.parametrize("shape", PAIRED)
@pytest.mark.parametrize("character", ["\u00b7", "\u201a", "\u060c", "`", "\u02bc", "\u2192"])
def test_a_look_alike_beside_a_space_and_a_hidden_mark_break_or_sign_refuses_the_source(tmp_path, character,
                                                                                        shape, declare):
    layout = ((";" if shape.startswith("Account;") else ","), ".") if declare else None
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, shape.format(c=character).encode(), layout)


# A dash or minus sign parts two numbers, except as an exponent's sign, with only marks between it and the exponent
# mark, or beside a hidden mark: `1.2345e\u22126` is one number.
@pytest.mark.parametrize("declare", [False, True])
@pytest.mark.parametrize("shape", ["EUR 1.2345e{d}6", "EUR 1.2345E{d}6", "EUR 1.2345e\u200b{d}6",
                                   "EUR 1.2345e\u20ac{d}6", "EUR 1.2345{d}e6", "Fund 2015{d}\u200b2020",
                                   "Fund 2015\u2060{d}2020"])
@pytest.mark.parametrize("dash", ["\u2212", "\u2013", "\u2010", "\ufe63", "\uff0d", "\u00d7", "\u2044"])
def test_a_dash_as_an_exponents_sign_or_beside_a_hidden_mark_refuses_the_source(tmp_path, dash, shape, declare):
    text = f"Account;Amount\nSYN-1;{shape.format(d=dash)}\nSYN-2;99999.00\n"
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode(), (";", ".") if declare else None)


@pytest.mark.parametrize("text", ["Account;Amount\nSYN-1;EUR 5\u20ac50000\n", "Account;Amount\nSYN-1;98\uff08765.43\n"])
def test_a_sign_directly_between_digits_refuses_the_source(tmp_path, text):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode())


# The review of 53f2f86: look-alikes and signs beside hidden marks, other spaces, tabs or quoted breaks.
AROUND = ['Account,Amount\nSYN-1,"Total 98\u00a0\u201a\n765.43"\n', 'Account,Amount\nSYN-1,"Total 98\n\u201a\n765.43"\n',
          "Account;Note\nSYN-1;Total 98\u2008\u00b7\u2008765.43\n", 'Account,Amount\nSYN-1,"Total 98\t\u00b7\t765.43"\n',
          "Account;Note\nSYN-1;Total 98\u00a0\u00b7\u00a0765.43\n", "Account;Amount\nSYN-1;EUR 98\u200b\u20ac765.43\n",
          'Account,Amount\nSYN-1,"EUR 98\u20ac\n765.43"\n', "Account;Amount\nSYN-1;USD\u00b7\u200b57891\n",
          'Account,Amount\nSYN-1,"USD\u00b7\n57891"\n']


@pytest.mark.parametrize("declare", [False, True])
@pytest.mark.parametrize("text", AROUND)
def test_a_look_alike_or_sign_beside_a_hidden_mark_or_break_refuses_the_source(tmp_path, text, declare):
    layout = (";", ".") if text.startswith("Account;") else (",", ".")
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode(), layout if declare else None)


@pytest.mark.parametrize("layout", [None, (";", ".")])
@pytest.mark.parametrize("text,value", [("Account;Amount\nSYN-1;USD\u00b712345e3\n", "123.45"),
                                        ("Account;Amount\nSYN-1;USD\u00b712345e-2\nSYN-2;99999.00\n", "0.0012345"),
                                        ("Account;Note\nSYN-1;Total USD      20170520\nSYN-2;12345.67\n", "20170520"),
                                        ("Account;Note\nSYN-1;Saldo 20170520 Soll\nSYN-2;12345.67\n", "20170520"),
                                        ("Account;Note\nSYN-1;Saldo 20170520 H\nSYN-2;12345.67\n", "20170520")])
def test_an_exponent_after_a_leading_look_alike_and_a_marked_date_shape_are_listed(text, value, layout):
    assert value in _source_figures(text.encode(), 5, layout)[0], (text, layout)


def test_a_currency_sign_or_a_bullet_and_space_before_an_amount_is_read_as_before():
    text = "Account;Note;Amount\nSYN-1;\u2022 12345 units;\u20ac98765.43\nSYN-2;Fee;\u00a512345.67\n"
    assert {"98765.43", "12345.67"} <= _source_figures(text.encode(), 5, None)[0]


def test_separators_that_part_numbers_and_arabic_and_fullwidth_amounts_are_read_as_before():
    text = ("Account;Note;Amount\nSYN-1;Fund 2015–2020;98765.43\nSYN-2;Size 3×4 and 1⁄2;"
            "٩٨٬٧٦٥٫٤٣\nSYN-3;Rate 10−5;１２，３"
            "４５．６７\nSYN-4;Lot 12-34567 at 10:30;1,234,567.89\n")
    values = _source_figures(text.encode(), 5, None)[0]
    assert {"98765.43", "1234567.89", "12345.67"} <= values


# The review of 7a930cf: a filler, a modifier letter or an exponent beyond the comma does not part a sign; a look-alike
# before digits beside a grouping space refuses; spaced dashes, and a sign after a tab, a line end or a non-ASCII
# letter, read as before; a code with a sign, or a credit or debit mark, before eight digits marks an amount.
@pytest.mark.parametrize("declare", [False, True])
@pytest.mark.parametrize("text", ["Account;Amount\nSYN-1;EUR 98\u3164,\u20ac765.43\n",
                                  "Account;Amount\nSYN-1;EUR 98\u02bc,\u20ac765.43\n",
                                  "Account;Amount\nSYN-1;EUR 1.2345\u20ac,e6\n",
                                  "Account;Amount\nSYN-1;USD\u00b7\u200957891\n",
                                  "Account;Amount\nSYN-1;USD\u00b7\xa057891\n"])
def test_a_sign_or_look_alike_beside_a_filler_comma_exponent_or_space_refuses_the_source(tmp_path, text, declare):
    with pytest.raises(AssistantError, match="^forbidden_token_source_hidden_mark$"):
        _load(tmp_path, text.encode(), (";", ".") if declare else None)


@pytest.mark.parametrize("text,layouts", [
    ("Account;Note;Amount\nSYN-1;Fund 2015 \u2013 2020;98765.43\n", [None, (";", ".")]),
    ("Account;Note;Amount\nSYN-1;Size 3 \u00d7 4 and 1 \u2044 2;98765.43\n", [None, (";", ".")]),
    ("Account;Note;Amount\nSYN-1;Rate 10\u00a0\u2212\u00a05;98765.43\n", [None, (";", ".")]),
    ("Account\tAmount\nSYN-1\t\u20ac.57891\n", [None, ("\t", ".")]), ("Amount\n\u20ac.57891\n", [None, (None, ".")]),
    ("Account,Amount\n,\u20ac98765.43\nSYN-2,12345.67\n", [None, (",", ".")]),
    ("Account;Amount\nSYN-1;Caf\u00e9\u20ac.57891\n", [None, (";", ".")]),
    ("Account,Kind,Amount\nSYN-1,Fee,\u20ac98765.43\nSYN-2,Fee,12345.67\n", [None, (",", ".")])])
def test_spaced_dashes_and_a_sign_after_a_tab_line_end_or_letter_read_as_before(text, layouts):
    for layout in layouts:
        assert _source_figures(text.encode(), 5, layout)[0], (text, layout)


@pytest.mark.parametrize("layout", [None, (";", ".")])
@pytest.mark.parametrize("text,value", [("Account;Note\nSYN-1;Total EUR-20170520\nSYN-2;12345.67\n", "20170520"),
                                        ("Account;Note\nSYN-1;Total USD+20170520\nSYN-2;12345.67\n", "20170520"),
                                        ("Account;Note\nSYN-1;Saldo Haben 20170520\nSYN-2;12345.67\n", "20170520"),
                                        ("Account;Note\nSYN-1;Credit 20170520 due\nSYN-2;12345.67\n", "20170520")])
def test_a_date_shape_after_a_code_with_a_sign_or_a_credit_or_debit_mark_is_listed(text, value, layout):
    assert value in _source_figures(text.encode(), 5, layout)[0], (text, layout)
