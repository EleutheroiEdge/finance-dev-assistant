"""File shapes from which an earlier figure-source reader listed only part of a figure, fed to the strict reader.

Each file below holds the figures stated beside it, and the earlier reader listed a part of one of them, or nothing,
without refusing the file: an invisible character or a look-alike mark inside a number, odd quoting, a bracketed
amount grouped by spaces, a quoted amount split across lines, a space or an `=` before a quote, an amount a comma
file cut into cells, a footnote or a text mark after an amount, an encoding other than UTF-8, UTF-16 with bytes
dropped. The strict reader, under every layout a configuration can declare, must refuse the file, list nothing, or
list exactly the figures it holds: never a part of one. The figures are stated here, never taken from the reader.
Synthetic only.
"""

import codecs
import itertools

import pytest

from figure_source_cases import layout, load, refused, write_source

from finassist.errors import AssistantError
from finassist.figure_sources import (DECIMAL_MARKS, DELIMITERS, GROUP_MARKS, SourceLayout, SourceRefused, layout_valid,
                                      read_source)

# Zero-width and joiner marks, bidirectional controls, variation selectors, tag characters, soft hyphen, fillers,
# controls, a byte-order mark inside the text, separators and spaces that group nothing.
MARKS = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\xad", "\u200e", "\u200f", "\u061c", "\u202a",
         "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\ufe0f", "\ufe00",
         "\U000e0100", "\U000e0041", "\U000e007f", "\u180e", "\u2062", "\u034f", "\u3164", "\u2800", "\x00", "\x0b",
         "\x0c", "\x1e", "\x85", "\u2028", "\u2029", "\u2008", "\u2002", "\u3000", "\u1680"]
MARKED = ["Account,Amount\nSYN-1,98{m}765.43\n", "Note\nTotal 98{m}765.43 due\n", "Account,Total 98{m}765.43\nSYN-1,x\n",
          'Account,Amount\nSYN-1,"98{m}765.43"\n', "Account\tAmount\nSYN-1\t98{m}765.43\n",
          "Account,Amount\nSYN-1,98765{m}.43\n", "Konto;Betrag\nSYN-1;98.765{m},43\n", "Konto;Betrag\nSYN-1;98{m}765,43\n",
          "Konto;Betrag\nSYN-1;{m}98765,43{m}\n", "Betrag\n98{m}765,43\n"]
# Spaces that group digits in some locale, and the apostrophes: only the ASCII ones are read, as declared.
SEPARATORS = ["\xa0", "\u2009", "\u202f", "\u2007", " ", "'", "\u2019"]
# Visible look-alikes of a grouping or decimal mark, and signs that are no part of a number.
LOOK_ALIKES = ["\u00b7", "\uff0e", "\u066b", "\u066c", "\uff0c", "\u2024", "\u02d9", "\u201a", "\u2212", "\u2013", "$",
               "%", "(", ")", "*", "_", "/", ":", "e", "E", "x"]

_SAME = "Konto;Betrag\nSYN-2;12345,67\n"  # a second, ordinary row in the same layout, where one is needed


def _cases():
    """(name, bytes, the figures the file holds)."""
    for encoding in ("utf-8", "utf-16"):
        for index, shape in enumerate(MARKED):
            for mark in MARKS:
                yield f"mark-{index}-U+{ord(mark):04X}-{encoding}", shape.format(m=mark).encode(encoding), {"98765.43"}
    for index, shape in enumerate(MARKED[:8]):
        for mark in LOOK_ALIKES:
            yield f"look-alike-{index}-{ord(mark):04X}", shape.format(m=mark).encode(), {"98765.43"}
    spaced = [("Konto;Betrag\nSYN-1;1{s}234{s}567,89\n", {"1234567.89"}),
              ('Account,Amount\nSYN-1,"1{s}234{s}567.89"\n', {"1234567.89"}),
              ("Note\nTotal 1{s}234{s}567.89 due\n", {"1234567.89"}),
              ("Account;Amount\nSYN-1;(98{s}765{s}432)\nSYN-2;12345.67\n", {"98765432", "12345.67"}),
              ("Account;Amount\nSYN-1;(17{s}114)\nSYN-2;12345.67\n", {"17114", "12345.67"}),
              ("Account;Amount\nSYN-1;Total loss (98{s}765{s}432)\nSYN-2;12345.67\n", {"98765432", "12345.67"}),
              ("Account;Amount\nSYN-1;(1{s}234{s}567) 1)\nSYN-2;12345.67\n", {"1234567", "12345.67"}),
              ("Account,Amount,CCY\nSYN-1,(98{s}765{s}432),EUR\nSYN-2,12345.67,EUR\n", {"98765432", "12345.67"}),
              ("(98{s}765{s}432)\n12345.67\n", {"98765432", "12345.67"})]
    for separator in SEPARATORS:
        for index, (text, figures) in enumerate(spaced):
            yield f"separator-{index}-U+{ord(separator):04X}", text.format(s=separator).encode(), figures
    breaks = [('Note,Qty\n"Total 1,234,\n567.89",1\n', "1234567.89"), ('Note;Qty\n"Total 1 234\n567,89";1\n', "1234567.89"),
              ('Note,Qty\n"Total 12345\n.67",1\n', "12345.67"), ('Account,Amount\nSYN-1,"1,234,\n567.89"\n', "1234567.89"),
              ('Note,Qty\r\n"Total 1,234,\r\n567.89",1\r\n', "1234567.89"), ('A\tB\nx\t"98765\n.43"\n', "98765.43"),
              ('A|B\nx|"98 765\n,43"\n', "98765.43"), ('Name; Amount\nSYN-1; "98\n765,43"\n', "98765.43"),
              ('Name;Amount\nSYN-1;"98\n765,43"\n', "98765.43"), ('Name;Amount\nSYN-1;="98\n765,43"\n', "98765.43"),
              ('Name;Amount\nSYN-1;= "98\n765,43"\n', "98765.43"), ('Name;Amount\nSYN-1;"98\r\n765,43"\n', "98765.43"),
              ('Name;Amount\nSYN-1;"98765\n,43"\n', "98765.43"), ('Name;Amount\nSYN-1;"98.\n765,43"\n', "98765.43"),
              ('Name;Amount\nSYN-1;"98\n765,43"\nSYN-2;12345,67\n', "98765.43"),
              ('Note,Qty\n"Total 98\u00ad\n765.43",1\n', "98765.43"), ('Note,Qty\n"Total 1,234,\u200b\n567.89",1\n', "1234567.89"),
              ('Note,Qty\n"Total 98\n\u200b765.43",1\n', "98765.43"),
              ('Note;Qty\n"Total 1\uff0c234\uff0c\n567\uff0e89";1\n', "1234567.89"),
              ('Note,Qty\n"Total 12345\n\uff0e67",1\n', "12345.67"), ('Note,Qty\n"Total 1,234,\n\t567.89",1\n', "1234567.89"),
              ('Note,Qty\n"Total 1,234,\n' + " " * 65 + '567.89",1\n', "1234567.89"),
              ('Positions, Jan 2026\nAccount\tNote\tAmount\nSYN-1\t"Total 1,234,\n567.89"\t10000.00\n', "1234567.89")]
    for index, (text, figure) in enumerate(breaks):
        yield f"break-{index}", text.encode(), {figure} | ({"12345.67"} if "SYN-2" in text else set())
    marks = ["Account,Amount\nSYN-1,98\u200b,\u200b765.43\n", "Account,Amount\nSYN-1,98765\u200b.\u200b43\n",
             "Account;Amount\nSYN-1;\u206698\u2069.\u2066765,43\u2069\n",
             "Account,Amount\nSYN-1,98\x00765.43\n" + "\x00" * 15, "Account,Amount\nSYN-1,98\u200b \u200b765.43\n",
             'Account,Amount\nSYN-1,"98\t765.43"\n', "Account,Amount\nSYN-1,98" + "\u200b" * 130 + "765.43\n",
             "Account,Amount\nSYN-1,98\x00765.43\n" + "\x00" * 481, "Account,Amount\nSYN-1,98\x00765.43\n" + " \x00" * 150,
             "Account;Amount\nSYN-1;98\ufffd765.43\n", "Account;Amount\nSYN-1;98\x1a765.43\n"]
    for index, text in enumerate(marks):
        yield f"marks-{index}", text.encode(), {"98765.43"}
    digits = ["Account,Amount\nSYN-1,\u0669\u0668\u200b\u0667\u0666\u0665\u066b\u0664\u0663\n",
              "Account,Amount\nSYN-1,\uff19\uff18\u200b\uff17\uff16\uff15.\uff14\uff13\n",
              "Account;Amount\nSYN-1;\uff19\uff18\uff17\uff16\uff15.43\n", "Account;Amount\nSYN-1;98\uff1765.43\n",
              "Account;Amount\nSYN-1;98765.4\u00b3\n", 'Note;Qty\n"Total \u0661\u066c\u0662\u0663\n\u0664\u0665\u0666\u066b\u0667\u0668";1\n']
    for index, text in enumerate(digits):
        yield f"digits-{index}", text.encode(), {"98765.43", "1234567.8", "1234.5678"}
    quoting = [('Id,Note,Amount\n1,"see ref;""",98765.43\n2,normal,12345.67\n', {"98765.43", "12345.67"}),
               ('Account,Amount\nSYN1,="12345.67"\nSYN2,="98765.43"\n', {"12345.67", "98765.43"}),
               ('Account\tAmount\tNote\nSYN-1\t98765.43\tsaid,"ship 12\nSYN-2\t34567.89\tok\n', {"98765.43", "34567.89"}),
               ('Positions Report\nAccount\tAmount\tNote\n1001\t98765.43\tsaid,"ship 12\n', {"98765.43"}),
               ('"Account","Amount"\n"SYN-1","98765.43"\n"SYN-2","12345.67"\n', {"98765.43", "12345.67"}),
               ('Account,Amount\nSYN-1,"98765".43\n', {"98765.43"}), ('Account,Amount\nSYN-1,98"765".43\n', {"98765.43"}),
               ('Account,Amount\nSYN-1,"98""765.43"\n', {"98765.43"}), ("Account,Amount\nSYN-1,'98765.43'\n", {"98765.43"}),
               ('Account,Amount\nSYN-1, "98765.43"\n', {"98765.43"}), ('Account,Amount\nSYN-1,"98765.43" \n', {"98765.43"}),
               ('Account;Amount\nSYN-1;"98";765.43"\n', {"98765.43"})]
    for index, (text, figures) in enumerate(quoting):
        yield f"quoting-{index}", text.encode(), figures
    cut = [("Account,CCY,Amount\nSYN1,USD,1,234,567.89\nSYN2,USD,2,345,678.91\n", {"1234567.89", "2345678.91"}),
           ("Date,Amount\n2026-01-02,1,234,567.89\n2026-01-03,2,345,678.91\n", {"1234567.89", "2345678.91"}),
           ("Account,CCY,Amount\nSYN1,USD,1,234,560.00\nSYN2,USD,9,876,540.00\nSYN3,USD,12345.67\n",
            {"1234560", "9876540", "12345.67"}),
           ("1,234,567.89,98765.43\n2,345,678.91,87654.32\n", {"1234567.89", "98765.43", "2345678.91", "87654.32"}),
           ("Account,Amount\nSYN1,123,456.78\nSYN2,98765.43\n", {"123456.78", "98765.43"}),
           ("Name,Amount\nA,12345.67\nBalance carried forward 60,927,718.98\n", {"12345.67", "60927718.98"}),
           ("Account;Amount\nA1;1,234,567.89\nB2;12,345.67\n", {"1234567.89", "12345.67"}),
           ("Account,Quantity,Cost\nSYN-1,12,345,678.90\nSYN-2,7,123,456.78\n", {"12345678.9", "7123456.78", "345678.9",
                                                                              "123456.78"}),
           ("SYN-1,12,345,678.90\nSYN-2,71,234,567.80\n", {"12345678.9", "71234567.8"}),
           ("Account,Amount\nSYN1,1,234,567.89e2\n", {"123456789"}), ("Account,Amount\nSYN1,USD1,234,567.89E+2\n", {"123456789"}),
           ("Account,Amount\nSYN-1,(1,234,567.89)\nSYN-2,-2,345,678.91\n", {"1234567.89", "2345678.91"}),
           ("Account,Amount\nSYN-1,$1,234,567.89\nSYN-2,USD 2,345,678.91\n", {"1234567.89", "2345678.91"})]
    for index, (text, figures) in enumerate(cut):
        yield f"cut-{index}", text.encode(), figures
    edges = [("Konto;Betrag\nSYN-1;12.345,67 S\n" + _SAME[13:], {"12345.67"}), ("Konto;Betrag\nSYN-1;12.345,67 EUR H\n", {"12345.67"}),
             ("Konto\tBetrag\nSYN-1\t12,345.67 CR\n", {"12345.67"}), ("Konto\tBetrag\nSYN-1\tUSD 12,345.67 Cr\n", {"12345.67"}),
             ("Konto\tBetrag\nSYN-1\t12,345.67*\n", {"12345.67"}), ("Konto\tBetrag\nSYN-1\t12,345.67 (e)\n", {"12345.67"}),
             ("Konto\tBetrag\nSYN-1\t12,345.67 1)\n", {"12345.67"}), ("Konto;Betrag\nSYN-1;12.345,67 [2]\n", {"12345.67"}),
             ("Konto;Betrag\nA1;12.345,67[1]\nB2;98.765,43 123)\n", {"12345.67", "98765.43"}),
             ("Konto;Betrag\nA1;12.345,67 Haben\nB2;98.765,43 Soll\n", {"12345.67", "98765.43"}),
             ("Konto;Betrag;Notiz\nA1;12.345,67;Rest 98.765,43 offen\n", {"12345.67", "98765.43"}),
             ("Konto;Betrag\nA1;12.345,67\nKontostand: 87.654,32 EUR\n", {"12345.67", "87654.32"}),
             ("Name;Amount\nA;,57891\nB;12.345,67\n", {"0.57891", "12345.67"}), ("Name;Amount\nA;.57891\nB;12345.67\n", {"0.57891", "12345.67"}),
             # One column with a leading decimal comma is refused; as two cells parted by a comma it holds 57891, whole.
             ("Total EUR,57891\n", {"57891"}), ("Cash dividend,57891 units\n0,12345\n", {"0.57891", "0.12345"}),
             ("value\n48213.57\n1.23456789e6\n9.0513E+02\n6729102500e-3\n", {"48213.57", "1234567.89", "905.13", "6729102.5"}),
             ("Account;Amount\nSYN-1;1234567.89e\u20132\n", {"12345.6789"}), ("Account;Amount\nSYN-1;98,$765.43\n", {"98765.43"}),
             ("Account;Amount\nSYN-1;12,34,567.89\n", {"1234567.89"}), ('account,value\nSYN-1,"31,41,592.65"\n', {"3141592.65"}),
             ("Account;Amount\nSYN-1;20,170,520.00\nSYN-2;USD 19,991,231\n", {"20170520", "19991231"}),
             ("Account;Amount\nSYN-1;(20170520)\nSYN-2;-20170520\nSYN-3;20170520.00\n", {"20170520"}),
             ("Account;Amount\nSYN-1;20.170.520,00 EUR\nSYN-2;20170520,50\n", {"20170520", "20170520.5"}),
             ("Konto;Betrag;Notiz\nA1;12.345,67;Fonds; Anteil\nB2;98.765,43;frei\n", {"12345.67", "98765.43"}),
             ("Note,Amount,Fee\nSYN1,12345.67,123,45\nSYN2,98765.43,987,65\n", {"12345.67", "98765.43", "123.45", "987.65"})]
    for index, (text, figures) in enumerate(edges):
        yield f"edge-{index}", text.encode(), figures
    rows = "Account;Amount\nSYN-1;3141592.65\nSYN-2;2718281.83\n"
    encoded = [
        (b"Konto;Betrag;Notiz\nSYN-1;98\xc2\xa0765,43;x\nSYN-2;12345,67;M\xfcller\n", {"98765.43", "12345.67"}),
        (b"Konto;Betrag;Notiz\nSYN-1;98\xe2\x80\x99765.43;x\nSYN-2;12345.67;M\xfcller\n", {"98765.43", "12345.67"}),
        (b"\xef\xbb\xbfAccount;Amount\nSYN-1;98765.43\nSYN-2;12345.67;M\xfcller\n", {"98765.43", "12345.67"}),
        *[(b"Account;Amount\nSYN-1;EUR 98" + bytes([byte]) + b"765.43\nSYN-2;12345.67\n", {"98765.43", "12345.67"})
          for byte in (0x81, 0x8D, 0x8F, 0x90, 0x9D, 0xA0, 0xB7, 0xFF)],
        ("Konto;Betrag;Notiz\nSYN-1;98\xa0765,43;M\xfcller \u20ac\nSYN-2;1.234.567,89;Gr\xfc\xdfe\n".encode("cp1252"),
         {"98765.43", "1234567.89"}),
        ("Konto\tBetrag\nA1\t12.345,67\nB2\t98.765,43\n".encode("utf-16"), {"12345.67", "98765.43"}),
        (codecs.BOM_UTF16_LE + "Account;Amount\nSYN-1;98".encode("utf-16-le") + b"\x00\xd8"
         + "765.43\n".encode("utf-16-le"), {"98765.43"}),
        (codecs.BOM_UTF16_LE + rows.encode("utf-16-le")[:-1], {"3141592.65", "2718281.83"}),
        (codecs.BOM_UTF16_LE + rows.encode("utf-16-le")[:-2], {"3141592.65", "2718281.83"}),
        (rows.encode("utf-16-le"), {"3141592.65", "2718281.83"}),
        (codecs.BOM_UTF32_LE + rows.encode("utf-32-le"), {"3141592.65", "2718281.83"}),
        (codecs.BOM_UTF8 + rows.encode(), {"3141592.65", "2718281.83"}),
    ]
    for index, (raw, figures) in enumerate(encoded):
        yield f"encoded-{index}", raw, figures
    # UTF-16 with two bytes dropped, at every place: the digits after the cut shift by a byte.
    whole = codecs.BOM_UTF16_LE + rows.encode("utf-16-le")
    for at in range(2, len(whole) - 1):
        yield f"utf-16-dropped-{at}", whole[:at] + whole[at + 2:], {"3141592.65", "2718281.83"}
        yield f"utf-16-dropped-one-{at}", whole[:at] + whole[at + 1:], {"3141592.65", "2718281.83"}


CASES = list(_cases())
LAYOUTS = [declared for declared in (
    SourceLayout(delimiter, decimal_mark, group_mark, header, columns)
    for delimiter, decimal_mark, group_mark, header, columns in itertools.product(
        DELIMITERS, DECIMAL_MARKS, GROUP_MARKS, (True, False), ((), (1,), (1, 3))))
    if layout_valid(declared)]


def _outcome(raw: bytes, declared: SourceLayout, figures: set, match_rounds: bool = True):
    """None when the file is refused or lists nothing; else what it lists beyond, or instead of, its figures."""
    try:
        listed, _forms, rounds = read_source(raw, declared, 5, match_rounds)
    except SourceRefused:
        return None
    return (listed | rounds) - figures or None


def test_the_cases_and_layouts_are_the_ones_meant():
    assert len(CASES) > 1300 and len({name for name, _raw, _figures in CASES}) == len(CASES)
    # Every delimiter, mark, header and text-column choice, less those with a decimal comma in a comma file or one
    # mark for decimals and groups.
    assert len(LAYOUTS) == (4 * 2 * 5 - 5 - 8 + 1) * 2 * 3
    assert all(figures for _name, _raw, figures in CASES)


def test_no_known_shape_is_listed_in_part_under_any_layout():
    wrong = [(name, tuple(declared), sorted(extra)) for name, raw, figures in CASES for declared in LAYOUTS
             if (extra := _outcome(raw, declared, figures)) is not None]
    assert not wrong, (len(wrong), wrong[:20])


def test_a_known_shape_read_with_no_text_column_lists_every_figure_it_holds():
    # With a text column declared, a figure inside that column is left out, as declared; with none, nothing is.
    short = [(name, tuple(declared), sorted(listed)) for name, raw, figures in CASES for declared in LAYOUTS
             if not declared.text_columns and (listed := _listed(raw, declared)) and listed != figures]
    assert not short, (len(short), short[:20])


def test_some_layout_reads_the_well_formed_cases_whole():
    # The checks above are not passed by refusing everything: a file that is its layout's is read, with all it holds.
    read = {name for name, raw, figures in CASES for declared in LAYOUTS if _listed(raw, declared) == figures}
    assert {"separator-0-U+0020", "separator-0-U+0027", "separator-7-U+0020", "separator-8-U+0027", "quoting-0",
            "quoting-4", "encoded-18", "edge-21", "edge-22", "edge-23", "cut-6"} <= read, sorted(read)
    assert len(read) == 20, sorted(read)  # the rest are refused, or list less than all, under every layout


def _listed(raw: bytes, declared: SourceLayout):
    try:
        listed, _forms, rounds = read_source(raw, declared, 5, True)
    except SourceRefused:
        return None
    return listed | rounds


@pytest.mark.parametrize("text,declared,code", [
    ('Name; Amount\nSYN-1; "98\n765,43"\n', dict(text_columns=[1]), "forbidden_token_source_malformed_quotes"),
    ('Name;Amount\nSYN-1;="98\n765,43"\n', dict(text_columns=[1]), "forbidden_token_source_malformed_quotes"),
    ("Name;Amount\nSYN-1;98\u200b765,43\n", dict(text_columns=[1]), "forbidden_token_source_hidden_mark"),
    ("Name;Amount\nSYN-1;(98 765 432) 1)\n", dict(group_mark=" ", text_columns=[1]), "forbidden_token_source_cell_unreadable"),
    ("Account,Amount\nSYN-1,1,234,567.89\n", dict(delimiter=",", decimal_mark=".", group_mark=",", text_columns=[1]),
     "forbidden_token_source_ambiguous"),
    ("3141592.65\n".encode("utf-16"), dict(decimal_mark=".", group_mark=None, header=False),
     "forbidden_token_source_encoding"),
], ids=["space-before-a-split-quote", "equals-before-a-split-quote", "invisible-character", "bracketed-footnote",
        "comma-cut", "utf-16"])
def test_the_loader_refuses_each_kind_by_its_own_name(tmp_path, text, declared, code):
    with pytest.raises(AssistantError, match=f"^{code}$"):
        load(layout(write_source(tmp_path, text), **declared))


def test_the_same_shapes_written_whole_are_listed_whole(tmp_path):
    spaced = load(layout(write_source(tmp_path, "Name;Amount\nSYN-1;(98 765 432)\nSYN-2;1 234 567,89\n"), group_mark=" ",
                         text_columns=[1]))
    assert spaced.listed == 2 and refused("98765432", spaced) and refused("1,234,567.89", spaced)
    assert not refused("765432", spaced) and not refused("567.89", spaced) and not refused("98765", spaced)
    quoted = load(layout(write_source(tmp_path, 'Account,Amount\nSYN-1,"1,234,567.89"\nSYN-2,"(98,765.43)"\n', "b.csv"),
                         delimiter=",", decimal_mark=".", group_mark=",", text_columns=["Account"]))
    assert quoted.listed == 2 and refused("1234567.89", quoted) and refused("98 765,43", quoted)
    assert not refused("234567.89", quoted) and not refused("567.89", quoted) and not refused("765.43", quoted)


def test_without_the_grouping_comma_check_a_cut_file_with_no_header_would_be_listed_in_part(monkeypatch):
    # `1,234,567.89,98765.43` on every line: each row has four cells, so no row is wider than another, and each cell
    # is an amount of its own. Only the check on a comma that may group digits refuses it.
    from finassist import figure_sources

    name, raw, figures = next(case for case in CASES if case[0] == "cut-3")
    assert raw.startswith(b"1,234,567.89,98765.43\n")
    declared = SourceLayout(",", ".", None, False, ())
    assert _listed(raw, declared) is None
    monkeypatch.setattr(figure_sources, "_check_cut_groups", lambda cells, bare, number: None)
    assert _listed(raw, declared) - figures == {"567.89", "678.91"}
