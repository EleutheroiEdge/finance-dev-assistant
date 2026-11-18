"""Figure sources in the layouts custody exports come in: seeded synthetic files, read offline.

Each file is built from values chosen first, so the figures a correct reading must list are known
without reading the file: the oracle never parses. A value is a figure when it has at least
--min-digits significant digits, unless it is a whole number of eight digits that names a day from
1900 to 2100 written bare, with no group, decimals, sign or code, as the product documents.

The files are holdings, tax lots, realized gains, account lists, two-column name and amount lists and
one-column files, in turn, with short names or identifiers beside the amounts, with every
delimiter, both decimal marks, five kinds of grouping, quoting, headers, totals in their own cell
or beside a label, report lines, byte-order marks, signs, currency signs and codes, credit and debit
marks, footnotes, spreadsheet text markers, timestamps, and UTF-16 and cp1252 files. Some files
quote nothing, so a cell may hold the delimiter: such a file may be refused, never read short. One
such file is left out, as documented: a comma file with no header that writes decimal commas
unquoted, which can't be told from one with more columns.

Every file is screened twice: named by its path, which is read every way, and with its true layout
declared. A miss, an expected figure the screen does not list while it accepts the file, is the
failure this measures: a confidential amount would pass without a word. Listing more than the file
holds, such as both readings of `12.345` or the number in an identifier like `ABC-12345`, can only
refuse more, so extras are counted, not failed. Each accepted file is also screened for a few of
its own figures written as the file writes them. Some files write a fraction with no zero before
the decimal mark: `.57891` is read as the payload screen reads it, but `,57891` is not something the
screen can recognize in a payload, so a file holding it must be refused as unscreenable in both
modes, and accepting it fails. Otherwise, read every way, only a one-column file may be refused,
and only as ambiguous: such a file can truly read two ways, and declaring its layout reads it, or a
file that writes a quote, as malformed quotes: a cell quoted for its own delimiter, as `"SYN-1",`, is
closed by a character another reading does not stop at, so that reading's quoting is not strict. Such
refusals are counted as "quoted for one delimiter". Declared, no file is refused for its quoting. Any
other refusal is unexpected.

Exit status: 0 when no file misses a figure in either mode, no unscreenable file is accepted and no
refusal is unexpected; 1 otherwise. Only counts and shape names are printed, never a value. Every
value is made up.

Two profiles extend the corpus; neither changes the default one, since their draws are made only when they are
set. --round-amounts writes round amounts such as 347,300.00, and some files of nothing else. --cut-cell-amounts
writes tax-lot costs and holding prices of 2 to 8 comma groups right after a short quantity, most with a three-digit
first group, some with zero groups or a sign, and puts half of those files in comma columns with point decimals and
comma groups, mostly unquoted: there the quantity and the amount are cut into cells that may hold several amounts.
--match digits screens with digit matching, and every expected figure must then be refused as a payload writes it.
--hidden-marks writes, in about half the files, an invisible mark (a zero-width or joiner mark, a direction mark, a
variation selector or tag character, a soft hyphen, a control character, a space that groups nothing) between two
digits of one figure, beside its exponent mark or sign or after a decimal mark that starts it, one of its figures
again split by a line break inside a quoted field, or a quoted figure
followed by text after its closing quote or never closed, or a figure split by a closing quote and another
reading's delimiter (`"Total 1 234"<TAB>567.89`; every delimiter pair, with or without a space or a line break
before the quote, at a line's start or after the delimiter, ending in LF, CRLF, a lone CR or the end of the
file); such a file must be refused, as hidden_mark or malformed_quotes, in both modes. In some other files it
writes such a mark inside a word, which changes nothing.
--edge-spellings appends, to about half the files with no such mark, one row in a shape a reader once listed in part
or not at all: a bracketed amount grouped by spaces, its last group like a footnote, as `(98 765 432)`, or an amount
whose eight digits name a day written as an amount, as `20,170,520.00` or `USD 19991231`, which must be listed whole;
a visible look-alike of a grouping or decimal mark between two digits, as `EUR 98<middle dot>765.43`, a currency
sign, bracket or percent sign beside a decimal or grouping mark or an exponent mark, as `EUR 98765<euro>.43`, a
look-alike between an ASCII space and a hidden mark, a quoted break or a sign, a dash as an exponent's sign or beside
a hidden mark (figure_source_edge_marks.py), or a byte Windows-1252 does not define, which must refuse the file as
hidden_mark or encoding; a UTF-16 file cut short inside its last row, which must refuse the file as encoding;
a byte that is not UTF-8 in a note, which must refuse a file holding UTF-8 characters as encoding and leave any other read as before; or a dash or
times sign between numbers, which changes nothing.
Each run prints its settings and the generator's digest above the corpus fingerprint.

    python scripts/figure_source_corpus.py --files 480 --seed 20261114
    python scripts/figure_source_corpus.py --automatic-only   # a release without declared layouts
    python scripts/figure_source_corpus.py --cut-cell-amounts --round-figures list --match digits
    python scripts/figure_source_corpus.py --hidden-marks
    python scripts/figure_source_corpus.py --edge-spellings
"""

from __future__ import annotations

import argparse
import collections
import csv
from dataclasses import dataclass, field, replace
from datetime import date, timedelta
from decimal import Decimal
import hashlib
import io
from pathlib import Path
import random
import tempfile

from finassist.errors import AssistantError
from finassist.forbidden_tokens import load_token_snapshot, screen_text

from figure_source_edge_marks import look_alike_row  # beside this script, as python puts its folder on the path

TAB = chr(9)
DELIMITERS = (",", ";", TAB, "|", None)  # None: one column, each line a cell
NAMES = {",": "comma", ";": "semicolon", TAB: "tab", "|": "bar", None: "one-column"}
# Characters that group the whole part in threes, besides the other decimal mark.
GROUPS = {"none": "", "mark": None, "space": " ", "nbsp": chr(0xA0), "narrow": chr(0x202F), "apostrophe": "'"}
DATES = ("%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y", "%Y/%m/%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.123",
         "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S+01:00")
WORDS = ("Global", "Equity", "Bond", "Index", "Growth", "Income", "Treasury", "Municipal", "Value", "Fund", "Trust")
KINDS = ("holdings", "tax-lots", "realized", "accounts", "two-column", "one-column")
# Marks some exports write after an amount: credit and debit, the German Soll and Haben, and footnotes.
MARKERS = {"credit-debit": (" CR", " DR", " Cr"), "soll-haben": (" S", " H", " Soll", " Haben"),
           "footnote": ("*", " (e)", " 1)", "[1]", " 123)")}
QUOTING = {"minimal": csv.QUOTE_MINIMAL, "all": csv.QUOTE_ALL, "none": None}  # none: a malformed file
# Marks that show as nothing, or as a space that groups no digits, and so hide part of a figure they stand inside.
HIDDEN = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u200e", "\u200f", "\u061c", "\u202a",
          "\u202e", "\u2066", "\u2069", "\ufe0f", "\U000e0041", "\u180e", "\u2062", "\u034f", "\u3164", "\x00",
          "\x0b", "\x85", "\u2028", "\u2008", "\u3000")
UNDEFINED = (0x81, 0x8D, 0x8F, 0x90, 0x9D)  # bytes Windows-1252 does not define
GENERATOR = Path(__file__)
EDGE_MARKS = GENERATOR.with_name("figure_source_edge_marks.py")  # the generator's digest covers both


@dataclass(frozen=True)
class Style:
    delimiter: str | None
    mark: str
    group: str
    quoting: str
    header: bool
    footer: str
    eol: str
    bom: bool
    dates: str
    negative: str
    currency: str
    marker: str = "none"  # a credit or debit mark, or a footnote, after some amounts
    bare_fraction: bool = False  # `,57891` or `.57891`: no zero before the decimal mark
    spreadsheet_text: bool = False  # numbers written `="12345.67"`, as a spreadsheet keeps them text
    encoding: str = "utf-8"
    exponent: bool = False  # some amounts written as a mantissa and `e2`, as `12,345.6789e2`

    @property
    def malformed(self) -> bool:
        """A file whose cells may hold its own delimiter unquoted: it may be refused, never read short."""
        return self.quoting == "none"

    @property
    def group_character(self) -> str:
        if self.group == "mark":
            return "," if self.mark == "." else "."
        return GROUPS[self.group]

    @property
    def shape(self) -> str:
        return f"{NAMES[self.delimiter]}/{self.mark}-decimal/{self.group}-groups"


@dataclass
class Export:
    kind: str
    style: Style
    text: str = ""
    figures: set[str] = field(default_factory=set)
    spellings: dict[str, str] = field(default_factory=dict)  # canonical value: as the file writes it
    unscreenable: bool = False  # it writes a number with a decimal comma and no digit before it
    rounds: set[str] = field(default_factory=set)  # round figures, listed only under "list"
    long_cut: bool = False  # it writes an amount of more than seven comma groups, which may refuse it
    round_spellings: dict[str, str] = field(default_factory=dict)
    hidden: bool = False  # a mark inside a figure, or a line break inside a quoted one: it must be refused
    tail: bytes = b""  # bytes written after the text, as they stand (--edge-spellings)
    stray: bool = False  # the tail holds a byte that is not UTF-8: refused when the text writes UTF-8 characters
    refusal: str = ""  # the code the file must be refused with (--edge-spellings)


def canonical(value: Decimal) -> str:
    whole, _, fraction = format(abs(value), "f").partition(".")
    whole, fraction = whole.lstrip("0") or "0", fraction.rstrip("0")
    return whole + ("." + fraction if fraction else "")


def is_figure(value: str, min_digits: int, bare: bool = True) -> bool:
    """bare: written as one run of digits with nothing that marks an amount, so that eight of them may be a date."""
    whole, _, fraction = value.partition(".")
    if len((whole + fraction).strip("0")) < min_digits:
        return False
    if bare and not fraction and len(whole) == 8:
        try:
            return not (1900 <= int(whole[:4]) <= 2100 and date(int(whole[:4]), int(whole[4:6]), int(whole[6:])))
        except ValueError:
            return True
    return True


def is_round(value: str, min_digits: int, bare: bool = True) -> bool:
    """A round figure: not a figure, at least min_digits digits before the point and 4 significant digits."""
    whole, _, fraction = value.partition(".")
    return (not is_figure(value, min_digits, bare) and len(whole.lstrip("0")) >= min_digits
            and len((whole.lstrip("0") + fraction).strip("0")) >= 4)


def fraction_figure(rng: random.Random) -> str:
    """Five fraction digits that are a figure: the last is not 0, so `,46830` (0.4683, four digits) never stands in."""
    return f"{rng.randrange(1_000, 10_000)}{rng.randrange(1, 10)}"


class Writer:
    """Cells of one export: text, dates and numbers, each number recorded with the figure it is."""

    def __init__(self, export: Export, rng: random.Random, min_digits: int, round_amounts: bool = False):
        self.export, self.rng, self.min_digits = export, rng, min_digits
        self.round_amounts, self.round_only = round_amounts, False

    def number(self, value: Decimal, places: int) -> str:
        style = self.export.style
        value = value.quantize(Decimal(1).scaleb(-places))
        written, suffix = value, ""
        if style.exponent and style.mark == "." and places == 2 and abs(value) >= 100_000 and self.rng.random() < 0.3:
            # `12,345.6789e2` is 1234567.89, and so is `123,456,789e-2`; zero padding never changes an exponent
            written, suffix = ((value.scaleb(-2), self.rng.choice(("e2", "E2", "e+2", "e02", "e0002", "E+0002")))
                               if self.rng.random() < 0.7 else
                               (value.scaleb(2), self.rng.choice(("e-2", "e-02", "E-0002"))))
        whole, _, fraction = format(abs(written), "f").partition(".")
        group = style.group_character
        if group and len(whole) > 3:
            head = len(whole) % 3 or 3
            whole = whole[:head] + "".join(group + whole[i:i + 3] for i in range(head, len(whole), 3))
            # as documented, an amount a comma could cut into more than seven cells refuses the file
            self.export.long_cut |= group == "," and whole.count(",") >= 7
        text = whole + (style.mark + fraction if fraction else "") + suffix
        if style.bare_fraction and whole == "0" and fraction:
            text = text[1:]  # the payload screen reads `.57891`, never `,57891`
            self.export.unscreenable |= style.mark == "," and is_figure(canonical(value), self.min_digits)
        if value < 0:
            text = {"minus": "-" + text, "brackets": "(" + text + ")", "trailing": text + "-"}[style.negative]
        text = {"none": text, "symbol": "$" + text, "code-after": text + " EUR", "code-before": "USD " + text,
                "code-tight": "EUR" + text}[style.currency]
        if style.spreadsheet_text and self.rng.random() < 0.5:
            text = f'="{text}"'  # a spreadsheet keeps the plain number as text, never one with a mark
        elif places == 2 and style.marker != "none" and self.rng.random() < 0.5:
            text += self.rng.choice(MARKERS[style.marker])
        bare = text.removeprefix('="').removesuffix('"').isdigit()  # eight such digits may be a date
        if is_figure(canonical(value), self.min_digits, bare):
            self.export.figures.add(canonical(value))
            self.export.spellings.setdefault(canonical(value), text)
        elif is_round(canonical(value), self.min_digits, bare):
            self.export.rounds.add(canonical(value))
            self.export.round_spellings.setdefault(canonical(value), text)
        return text

    def amount(self, low: int, high: int, places: int = 2, signed: bool = False) -> tuple[Decimal, str]:
        if self.round_amounts and (self.round_only or self.rng.random() < 0.15):
            # a round amount, as 347,300.00 or 1,002,000.00: four significant digits, a large magnitude
            value = Decimal(self.rng.randrange(1001, 10_000)).scaleb(self.rng.randrange(2, 4))
            if signed and self.rng.random() < 0.4:
                value = -value
            return value, self.number(value, places)
        value = Decimal(self.rng.randrange(low * 10 ** places, high * 10 ** places)).scaleb(-places)
        if signed and self.rng.random() < 0.4:
            value = -value
        return value, self.number(value, places)

    def day(self) -> str:
        return (date(2015, 1, 1) + timedelta(days=self.rng.randrange(4000))).strftime(
            self.export.style.dates).replace("00:00:00", "10:30:00")

    def account(self) -> str:
        choice = self.rng.random()
        if choice < 0.35:
            return f"SYN-{self.rng.randrange(10 ** 5):05d}"
        if choice < 0.65:
            return f"Account {chr(65 + self.rng.randrange(26))}"  # a short name, with no digit to give a split away
        return self.number(Decimal(self.rng.randrange(10 ** 8, 10 ** 10)), 0)  # an account number is a figure too

    def description(self) -> str:
        words = self.rng.sample(WORDS, 3)
        if self.rng.random() < 0.3:
            words.insert(1, f"{self.rng.randrange(1, 9)}.{self.rng.randrange(10, 99)}%")
        text = " ".join(words)
        style = self.export.style
        if style.bare_fraction and style.mark == "," and self.rng.random() < 0.3:
            # a figure in a label with no zero before its decimal comma, apart or glued to the word: unscreenable, as
            # a number cell would be
            text += (self.rng.choice((" Rate ,", " EUR,", ": ,", "EUR,", ",")) + fraction_figure(self.rng)
                     + self.rng.choice(("", "", " units", " net")))  # a word after it changes nothing
            self.export.unscreenable = True
        if self.export.style.delimiter is not None and self.rng.random() < 0.3:
            text = text.replace(" ", self.rng.choice((", ", "; ", " | ", "\n")), 1)  # quoted by the writer
        return text


def cut_cell_amount(cells: Writer, rng: random.Random, signed: bool) -> str:
    """An amount of 2 to 8 comma groups, most with a three-digit first group, so that written right after a short
    quantity in an unquoted comma file the two run on: `12,345,678.90` may hold 12 and 345,678.90."""
    groups = rng.choice((2, 2, 3, 3, 4, 5, 6, 7, 8))
    head = rng.randrange(100, 1000) if rng.random() < 0.85 else rng.randrange(1, 100)
    rest = [0 if rng.random() < 0.2 else rng.randrange(1000) for _ in range(groups - 1)]
    places = rng.choice((2, 4))
    value = sum((Decimal(group) * 1000 ** power for power, group in enumerate(reversed([head, *rest]))), Decimal(0))
    value += Decimal(rng.randrange(10 ** places)).scaleb(-places)
    return cells.number(-value if signed and rng.random() < 0.3 else value, places)


def build(kind: str, style: Style, rng: random.Random, min_digits: int, round_amounts: bool = False,
          cut_cells: bool = False) -> Export:
    if cut_cells and kind in ("tax-lots", "holdings") and rng.random() < 0.5:
        # the layout that cuts an amount after a short number: comma columns, point decimals, comma groups
        style = replace(style, delimiter=",", mark=".", group="mark",
                        quoting=rng.choice(("none", "none", "minimal", "all")), exponent=style.exponent or rng.random() < 0.3)
    export = Export(kind, style)
    cells = Writer(export, rng, min_digits, round_amounts)
    if round_amounts and kind in ("two-column", "one-column") and rng.random() < 0.15:
        cells.round_only = True  # a file of round amounts only
    rows: list[list[str]] = []
    total = Decimal(0)
    rows_wanted = rng.randrange(3, 40)
    if kind == "holdings":
        header = ["Account", "Symbol", "Description", "Quantity", "Price", "Market value", "Cost basis", "Gain",
                  "Weight"]
        for _ in range(rows_wanted):
            quantity = (Decimal(rng.randrange(1, 5000)) if rng.random() < 0.7
                        else Decimal(rng.randrange(1000, 999_999)).scaleb(-3))
            price = Decimal(rng.randrange(100, 9_999_999)).scaleb(-4)
            value, cost = (quantity * price).quantize(Decimal("0.01")), Decimal(rng.randrange(100_00, 9_000_000_00)).scaleb(-2)
            total += value
            account, symbol, description = cells.account(), rng.choice(("ABC", "XYZW", "QRS.B")), cells.description()
            quantity_text = cells.number(quantity, 3 if quantity % 1 else 0)  # drawn in the order they always were
            price_text = (cut_cell_amount(cells, rng, False) if cut_cells and rng.random() < 0.4
                          else cells.number(price, rng.choice((2, 4))))
            rows.append([account, symbol, description, quantity_text, price_text, cells.number(value, 2),
                         cells.number(cost, 2), cells.number(value - cost, 2),
                         cells.number(Decimal(rng.randrange(10_000, 99_999)).scaleb(-5), 5)])
    elif kind == "tax-lots":
        header = ["Account", "Symbol", "Acquired", "Quantity", "Cost per share", "Cost basis"]
        for _ in range(rows_wanted):
            value, text = cells.amount(1_000, 2_000_000)
            total += value
            account, day = cells.account(), cells.day()  # drawn in the order they always were
            quantity_text = cells.number(Decimal(rng.randrange(1, 900)), 0)
            cost_text = (cut_cell_amount(cells, rng, True) if cut_cells and rng.random() < 0.5
                         else cells.amount(1, 999, 4)[1])
            rows.append([account, "XYZW", day, quantity_text, cost_text, text])
    elif kind == "realized":
        header = ["Account", "Symbol", "Acquired", "Sold", "Proceeds", "Cost", "Gain or loss"]
        for _ in range(rows_wanted):
            proceeds, proceeds_text = cells.amount(1_000, 3_000_000)
            cost, cost_text = cells.amount(1_000, 3_000_000)
            total += proceeds - cost
            rows.append([cells.account(), "ABC", cells.day(), cells.day(), proceeds_text, cost_text,
                         cells.number(proceeds - cost, 2)])
    elif kind == "accounts":
        header = ["Account number", "Name", "Type", "Balance", "As of"]
        for index in range(rows_wanted):
            value, text = cells.amount(10_000, 9_000_000, signed=True)
            total += value
            rows.append([cells.number(Decimal(rng.randrange(10 ** 8, 10 ** 10)), 0), f"Account {chr(65 + index % 26)}",
                         rng.choice(("Taxable", "IRA", "Trust")), text, cells.day()])
    elif kind == "two-column":
        header = ["Name", "Amount"]
        for index in range(rows_wanted):
            value, text = cells.amount(10_000, 9_000_000, signed=True)
            total += value
            rows.append([f"Holder {chr(65 + index % 26)}", text])
    else:
        header = ["Amount"]
        for _ in range(rows_wanted):
            value, text = cells.amount(10_000, 9_000_000)
            total += value
            rows.append([text])
    if kind in ("two-column", "one-column") and style.bare_fraction and style.mark == "," and rng.random() < 0.3:
        # a short file's note with a fraction and no zero before its decimal comma, glued to the word or apart, as
        # `Cash dividend,57891`: unscreenable, however the rest of the file reads
        note = (rng.choice(WORDS) + rng.choice(("EUR,", ",", ": ,", " ,")) + fraction_figure(rng)
                + rng.choice(("", "", " units", " net")))
        rows.insert(rng.randrange(len(rows) + 1), [note] if kind == "one-column" else [note, cells.amount(10_000, 90_000)[1]])
        export.unscreenable = True
    if style.footer == "total":
        rows.append(["Total"] + [""] * (len(header) - 2) + [cells.number(total, 2)] if len(header) > 1
                    else [cells.number(total, 2)])
    lines = []
    if style.delimiter is None:
        lines = ([header[0]] if style.header else []) + [row[0] for row in rows]
        text = style.eol.join(lines) + style.eol
    else:
        buffer = io.StringIO(newline="")
        if style.malformed:  # nothing quoted: a cell holding the delimiter splits, as some exports write it
            buffer.write("".join(style.delimiter.join(row) + style.eol for row in ([header] if style.header else []) + rows))
        else:
            writer = csv.writer(buffer, delimiter=style.delimiter, quoting=QUOTING[style.quoting],
                                lineterminator=style.eol)
            if style.header:
                writer.writerow(header)
            writer.writerows(rows)
        text = buffer.getvalue()
    if style.footer == "generated":
        text += f"Report generated {cells.day()}{style.eol}"
    elif style.footer == "label":  # the total and its label in one cell, as many statements end
        text += f"{rng.choice(('Total', 'Kontostand:', 'Balance carried forward'))} {cells.number(total, 2)}{style.eol}"
    export.text = (chr(0xFEFF) if style.bom else "") + text
    return export


def hide(export: Export, rng: random.Random) -> None:
    """Write a mark inside one figure, split one by a line break inside a quoted field, or write a mark inside a word;
    the figures are unchanged, so the oracle still never parses."""
    choice, mark = rng.random(), rng.choice(HIDDEN)
    spelled = [spelling for spelling in export.spellings.values() if spelling in export.text]
    if choice < 0.35 and spelled:
        spelling = rng.choice(spelled)
        # between two digits, beside an exponent mark or its sign, or after a decimal mark that starts the number
        exponents = {index for index in range(1, len(spelling) - 1) if spelling[index] in "eE"
                     and spelling[index - 1].isdigit() and (spelling[index + 1].isdigit() or spelling[index + 1] in "+-")}
        inside = [index for index in range(1, len(spelling)) if spelling[index - 1].isdigit() and spelling[index].isdigit()
                  or index in exponents or index - 1 in exponents
                  or spelling[index - 1] in "+-" and index - 2 in exponents
                  or spelling[index - 1] in ".," and spelling[index].isdigit()
                  and (index == 1 or not spelling[index - 2].isdigit())]
        if spelling[:1] in (".", ","):  # before a decimal mark that starts the number, too
            inside.append(0)
        # half the time, where the spelling has one, beside its exponent or after a decimal mark that starts it
        special = [index for index in inside if not index or not (spelling[index - 1].isdigit() and spelling[index].isdigit())]
        if special and rng.random() < 0.5:
            inside = special
        around = [index for index in range(1, len(spelling) - 1) if spelling[index] in ".,'" and
                  spelling[index - 1].isdigit() and spelling[index + 1].isdigit()]
        around += [0] if spelling[:1] in (".", ",") and spelling[1:2].isdigit() else []  # both sides of `.57891`
        if around and rng.random() < 0.4:  # a mark on both sides of a separator, as `98<mark>,<mark>765.43`
            at = rng.choice(around)
            export.text = export.text.replace(
                spelling, spelling[:at] + mark + spelling[at] + rng.choice(HIDDEN) + spelling[at + 1:], 1)
            export.hidden = True
        elif inside:
            at = rng.choice(inside)
            run = mark * (rng.randrange(65, 200) if rng.random() < 0.1 else 1)  # sometimes a long run of marks
            export.text = export.text.replace(spelling, spelling[:at] + run + spelling[at:], 1)
            export.hidden = True
    elif choice < 0.55 and spelled and export.style.delimiter is not None:
        spelling = rng.choice(spelled)
        cuts = [index for index in range(1, len(spelling)) if spelling[index].isdigit()
                and (spelling[index - 1].isdigit() or spelling[index - 1] in ".," and (index == 1
                     or spelling[index - 2].isdigit()))]
        if cuts and '"' not in spelling:
            at, eol = rng.choice(cuts), export.style.eol
            delimiter = export.style.delimiter
            beside = rng.choice(("", "", " ", mark, "\t", " " * 70))  # a space, a mark, a tab or a long run
            export.text += f'Memo{delimiter}"Total {spelling[:at]}{beside}{eol}{spelling[at:]} net"{eol}'
            export.hidden = True
    elif choice < 0.7 and spelled and export.style.delimiter is not None:
        # quoting no reading can parse strictly, around a figure: text after the closing quote, or a quote left open
        spelling, eol, delimiter = rng.choice(spelled), export.style.eol, export.style.delimiter
        other = rng.choice([mark for mark in (",", ";", "\t", "|") if mark != delimiter])
        at = next((index for index in range(len(spelling) // 2, len(spelling)) if spelling[index].isdigit()), 0)
        export.text += rng.choice((f'Memo{delimiter}"Total {spelling}" net{delimiter}1{eol}',
                                   f'Memo{delimiter}"Total {spelling}{eol}',
                                   # a quote after another reading's delimiter, out of step with this reading's
                                   f'Memo{delimiter}a{other}"b{delimiter}"{eol}Total {spelling[:at]}{eol}'
                                   f'{spelling[at:]}"{delimiter}1{eol}'))
        export.hidden = True
    elif choice < 0.8 and spelled and export.style.delimiter is not None:
        # a closing quote followed by another reading's delimiter, between two parts of a figure: that reading's csv
        # runs the cell on past the quote, so it would list the figure in part
        spelling, delimiter = rng.choice(spelled), export.style.delimiter
        cuts = [index for index in range(1, len(spelling))
                if spelling[index - 1].isdigit() and spelling[index].isdigit()]
        if cuts and '"' not in spelling:
            at, other = rng.choice(cuts), rng.choice([mark for mark in (",", ";", TAB, "|") if mark != delimiter])
            inside = rng.choice(("", " ", export.style.eol + " "))
            first = rng.choice(("", f"Memo{delimiter}"))  # at a line's start, or after the delimiter
            end = rng.choice((export.style.eol, "\r", ""))  # the file's line end, a lone CR or the end of the file
            export.text += f'{first}"Total {spelling[:at]}{inside}"{other}{spelling[at:]}{end}'
            export.hidden = True
    elif choice < 0.9:
        for word in WORDS:  # a mark inside a word, far from any digit: read as before
            if word in export.text:
                export.text = export.text.replace(word, word[:2] + mark + word[2:], 1)
                break


def edge(export: Export, rng: random.Random, min_digits: int) -> None:
    """Append one row in a shape a reader once listed in part or not at all (--edge-spellings), recording what a
    correct reading lists or which code must refuse the file. The figures are known from the draw."""
    style = export.style
    delimiter, mark, eol = style.delimiter, style.mark, style.eol

    def row(cell: str) -> str:  # quoted as csv quotes a cell that holds the delimiter
        if delimiter is not None and (delimiter in cell or '"' in cell):
            cell = '"' + cell.replace('"', '""') + '"'
        return cell + eol if delimiter is None else f"Memo{delimiter}{cell}{eol}"

    def grouped(digits: str, group: str) -> str:
        head = len(digits) % 3 or 3
        return digits[:head] + "".join(group + digits[at:at + 3] for at in range(head, len(digits), 3))

    def listed(value: str, spelling: str | None = None) -> None:
        if is_figure(value, min_digits, bare=False):
            export.figures.add(value)
            if spelling is not None:
                export.spellings.setdefault(value, spelling)

    whole = str(rng.randrange(10_000, 10 ** 9))  # at least two groups; not bare, so never a date
    fraction = f"{rng.randrange(1, 100):02d}"
    value = canonical(Decimal(f"{whole}.{fraction}"))
    choice = rng.random()
    if choice < 0.2:  # a bracketed amount grouped by spaces: `432)` is its last group, not a footnote
        space = rng.choice((" ", "\u00a0", "\u2007", "\u2009", "\u202f"))
        cell = rng.choice(("({})", "Total loss ({})", "-({})")).format(grouped(whole, space))
        export.text += row(cell)
        listed(whole, cell)
    elif choice < 0.4:  # eight digits that name a day, written as an amount: a figure, not a date
        day = (date(1900, 1, 1) + timedelta(days=rng.randrange(73_000))).strftime("%Y%m%d")
        group = style.group_character or ("," if mark == "." else ".")
        cents = rng.choice(("00", "50"))
        amount = canonical(Decimal(f"{day}.{cents}"))
        cell, figure = rng.choice(((grouped(day, group), day), (f"{day}{mark}{cents}", amount), (f"USD {day}", day),
                                   (f"{grouped(day, group)} EUR", day), (f"({day})", day),
                                   (f"Total USD {grouped(day, group)}{mark}{cents}", amount),
                                   (f"Total USD{' ' * rng.randrange(1, 9)}{day}", day),
                                   (f"Saldo {day} {rng.choice(('Soll', 'Haben', 'S', 'H', 'CR', 'Dr'))}", day),
                                   (f"Total {rng.choice(('EUR-', 'USD+', 'Haben ', 'Credit '))}{day}", day)))
        export.text += row(cell)
        listed(figure, cell)
    elif choice < 0.6 and style.encoding == "utf-16":  # cut short inside its last row: refused by name, never read in part
        export.tail = row(f"EUR {whole}{mark}{fraction}").encode("utf-16")[2:-1]  # the file's byte order, its mark left out
        export.refusal = "encoding"
        listed(value)
    elif choice < 0.6:
        if rng.random() < 0.5:  # a byte Windows-1252 does not define, inside a figure: refused by name
            line = row(f"EUR {whole[:2]}\x01{whole[2:]}{mark}{fraction}")
            export.tail = line.encode("ascii").replace(b"\x01", bytes([rng.choice(UNDEFINED)]))
            export.refusal = "encoding"
            listed(value)
        else:  # a byte that is not UTF-8 in a note: refused only beside UTF-8 characters, else a Windows export
            if style.encoding == "utf-8":  # a no-break space in a figure, which Windows-1252 would read as a letter
                cell = f"{grouped(whole, chr(0xA0))}{mark}{fraction}"
                export.text += row(cell)
                listed(value, cell)
            # a digit in the note, so that a file with no header never takes the row for one
            export.tail = row("Ref 7 M\x01ller").encode("ascii").replace(b"\x01", b"\xfc")
            export.stray = True
    elif choice < 0.85:  # a look-alike, a sign or a dash inside a number (figure_source_edge_marks): refused by name
        rows, export.refusal, values = look_alike_row(rng, whole, fraction, mark, delimiter, eol, row)
        export.text += rows
        for number, spelling in values:
            listed(canonical(number), spelling)
    else:  # a dash, a minus or times sign or a fraction slash between numbers: read as before
        export.text += row(rng.choice(("Fund 2015\u20132020", "Size 3\u00d74", "Rate 10\u22125", "Lots 1\u20442",
                                       "Fund 2015 \u2013 2020", "Size 3 \u00d7 4", "Rate 10\u00a0\u2212\u00a05")))


def styles(rng: random.Random, kind: str) -> Style:
    delimiter = None if kind == "one-column" else rng.choice(DELIMITERS[:4])
    mark = rng.choice((".", ","))
    group = rng.choice(tuple(GROUPS))
    if group == "apostrophe" and mark == ",":
        group = "space"
    quoting = rng.choice(("minimal", "minimal", "all", "none")) if delimiter else "minimal"
    # Unquoted decimal commas in a comma file with no header can't be told from more columns: `377,20` is one
    # amount or two cells. Such a file is out of scope, as documented; with a header its rows are too wide.
    header = rng.random() < 0.85 or (quoting == "none" and delimiter == mark == ",")
    return Style(delimiter, mark, group, quoting, header, rng.choice(("none", "none", "total", "generated", "label")),
                 rng.choice(("\n", "\r\n")), rng.random() < 0.2, rng.choice(DATES),
                 rng.choice(("minus", "brackets", "trailing")),
                 rng.choice(("none", "none", "symbol", "code-after", "code-before", "code-tight")),
                 rng.choice(("none", "none", "none", "credit-debit", "soll-haben", "footnote")), rng.random() < 0.12,
                 rng.random() < 0.1, rng.choice(("utf-8", "utf-8", "utf-8", "utf-16", "cp1252")), rng.random() < 0.1)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def screen(entry, min_digits: int, round_figures: str = "skip", match: str = "value"):
    try:
        return "listed", load_token_snapshot({"forbidden_token_sources": [entry], "forbidden_token_min_digits": min_digits,
                                              "forbidden_token_round_figures": round_figures,
                                              "forbidden_token_match": match}, ())
    except AssistantError as exc:
        return exc.code, None


def refuses(text: str, snapshot) -> bool:
    try:
        screen_text(text, snapshot)
    except AssistantError as exc:
        return exc.code == "forbidden_token_present"
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--files", type=int, default=480)
    parser.add_argument("--seed", type=int, default=20261114)
    parser.add_argument("--min-digits", type=int, default=5)
    parser.add_argument("--automatic-only", action="store_true", help="skip declared layouts (an older release)")
    parser.add_argument("--round-amounts", action="store_true",
                        help="also write round amounts, as 347,300.00, and some files of round amounts only")
    parser.add_argument("--round-figures", choices=("skip", "list"), default="skip",
                        help="the setting to screen with; under list, round amounts must be listed too")
    parser.add_argument("--cut-cell-amounts", action="store_true",
                        help="also write amounts of 2 to 8 comma groups right after a short quantity, half of those "
                             "files in comma columns with comma groups")
    parser.add_argument("--match", choices=("value", "digits"), default="value", help="the match mode to screen with")
    parser.add_argument("--hidden-marks", action="store_true",
                        help="also write invisible marks inside figures, figures split by a line break inside a quoted "
                             "field, and marks inside words")
    parser.add_argument("--edge-spellings", action="store_true",
                        help="also append rows a reader once listed in part: bracketed space groups, amounts whose "
                             "digits name a day, look-alike marks, bytes that are not UTF-8, UTF-16 cut short")
    options = parser.parse_args(argv)
    listing = options.round_figures == "list"
    rng = random.Random(options.seed)
    counts = {mode: collections.Counter({"files missing a figure": 0, "own spellings not refused": 0,
                                         "unexpected refusals": 0, "unscreenable accepted": 0,
                                         **({"hidden mark accepted": 0} if options.hidden_marks else {}),
                                         **({"edge shape accepted": 0} if options.edge_spellings else {})})
              for mode in ("read every way", "declared")}
    refused_shapes = collections.Counter()
    fingerprint = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix="figure-corpus-") as folder:
        for index in range(options.files):
            kind = KINDS[index % len(KINDS)]
            export = build(kind, styles(rng, kind), rng, options.min_digits, options.round_amounts,
                           options.cut_cell_amounts)
            if not (export.figures or options.round_amounts and export.rounds):
                continue  # one corpus under skip and under list; without round amounts, the corpus as before
            if options.hidden_marks and rng.random() < 0.6:  # drawn only with the profile: the default corpus stays
                hide(export, rng)
            if options.edge_spellings and not export.hidden and rng.random() < 0.5:  # drawn only with the profile
                edge(export, rng, options.min_digits)
            fingerprint.update(export.text.encode("utf-8") + export.tail)
            path = Path(folder) / f"export-{index:04d}.csv"
            try:  # a cp1252 file can't hold every grouping space; such a file stays UTF-8
                if export.style.encoding == "utf-16":  # its encoder writes the one byte-order mark
                    data = export.text.removeprefix(chr(0xFEFF)).encode("utf-16")
                else:
                    data = export.text.encode(export.style.encoding)
            except UnicodeEncodeError:
                data = export.text.encode("utf-8")
            if export.stray and not export.text.isascii() and data == export.text.encode("utf-8"):
                export.refusal = "encoding"  # UTF-8 characters beside a byte that is not UTF-8
            path.write_bytes(data + export.tail)
            wanted = export.figures | (export.rounds if listing else set())
            expected = {_digest(value) for value in wanted}
            spellings = {**export.spellings, **(export.round_spellings if listing else {})}
            layout = export.style.delimiter, export.style.mark
            entries = {"read every way": str(path)}
            if not options.automatic_only:
                entries["declared"] = ({"path": str(path), "delimiter": layout[0], "decimal_mark": layout[1]}
                                       if layout != (",", ",") else None)
            for mode, entry in entries.items():
                tally = counts[mode]
                tally["files"] += 1
                if options.round_amounts:
                    tally["files of round amounts only"] += not export.figures
                if entry is None:
                    tally["not declarable"] += 1
                    continue
                outcome, snapshot = screen(entry, options.min_digits, options.round_figures, options.match)
                if snapshot is None:
                    code = outcome.removeprefix("forbidden_token_source_")
                    tally["refused " + code] += 1
                    if export.hidden:  # a mark inside a figure: refused, by its own reason
                        expected_refusal = code in ("hidden_mark", "malformed_quotes") or export.style.malformed
                    elif export.refusal:  # an edge spelling refused by name
                        expected_refusal = code == export.refusal or export.style.malformed
                    elif export.style.malformed:
                        expected_refusal = True  # refused, for any reason, is safe; only a short reading fails
                    elif mode == "read every way" and code == "malformed_quotes" and '"' in export.text:
                        expected_refusal = True  # quoted for its own delimiter: another reading's quoting runs on
                        tally["quoted for one delimiter"] += 1
                    elif export.long_cut:  # refused whole, never read in part
                        expected_refusal = code == "invalid" or export.unscreenable and code == "unscreenable"
                    elif not export.figures and not listing:  # under skip, round amounts alone list nothing
                        expected_refusal = code == "invalid" or export.unscreenable and code == "unscreenable"
                    elif export.unscreenable:
                        expected_refusal = code == "unscreenable"
                    else:
                        expected_refusal = mode == "read every way" and kind == "one-column" and code == "ambiguous"
                    tally["unexpected refusals"] += not expected_refusal
                    marks = "comma" if layout[1] == "," else "point"
                    refused_shapes[f"{mode}, {code}: {kind}, {NAMES[layout[0]]} columns, {marks} decimals"] += 1
                    continue
                if options.match == "value":
                    missed = expected - snapshot.hashes
                    tally["extras"] += len(snapshot.hashes - expected)
                else:  # digit forms hide the values: each expected figure must be refused as a payload writes it
                    missed = {value for value in wanted if not refuses(f"total {value} today", snapshot)}
                tally["listed"] += 1
                tally["unscreenable accepted"] += export.unscreenable  # its `,57891` would pass the screen
                if export.hidden:  # a figure read in part
                    tally["hidden mark accepted"] += 1
                if export.refusal:  # read, though it must be refused by name
                    tally["edge shape accepted"] += 1
                tally["files missing a figure"] += bool(missed)
                tally["figures missed"] += len(missed)
                sample = sorted(spellings, key=_digest)[:3]  # not from rng: both modes see one corpus
                tally["own spellings not refused"] += sum(not refuses(f"total {spellings[value]} today", snapshot)
                                                          for value in sample)
                if listing:
                    tally["round figures listed"] += len(export.rounds - set(export.figures))
    for mode, tally in counts.items():
        if tally["files"]:
            print(f"{mode}: " + ", ".join(f"{name} {tally[name]}" for name in sorted(tally)))
    for shape, number in sorted(refused_shapes.items()):
        print(f"  refused {number}: {shape}")
    print(f"settings: files {options.files}, seed {options.seed}, min digits {options.min_digits}, round amounts "
          f"{options.round_amounts}, cut-cell amounts {options.cut_cell_amounts}, round figures {options.round_figures}, "
          f"match {options.match}, automatic only {options.automatic_only}"
          f"{', hidden marks True' if options.hidden_marks else ''}"
          f"{', edge spellings True' if options.edge_spellings else ''}; generator "
          f"{hashlib.sha256(GENERATOR.read_bytes() + EDGE_MARKS.read_bytes()).hexdigest()[:16]}")
    print(f"corpus {fingerprint.hexdigest()[:16]}")
    failed = any(tally["files missing a figure"] or tally["own spellings not refused"] or tally["unexpected refusals"]
                 or tally["unscreenable accepted"] or tally["hidden mark accepted"] or tally["edge shape accepted"]
                 for tally in counts.values())
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
