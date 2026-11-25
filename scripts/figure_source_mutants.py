"""Seeded mutants of synthetic figure sources, checked against the one property of the strict reader.

For any bytes, a figure source is refused by name, or every digit in it belongs to a cell read in full as one amount
or to a column its layout declares as text (src/finassist/figure_sources.py). This script plants known amounts in
well-formed synthetic files, damages each file, and checks every mutant three ways:

1. Against a second reader written here on its own, one character at a time and without a pattern library
   (`reference`): the reader under test must refuse exactly the mutants it refuses, and read the same amounts at the
   same lines and columns from the others. A crash counts as a failure.
2. Digit conservation: in a mutant that is read, the digits of the text in order are the digits of its cells in
   order, and every cell outside the text columns that holds a digit is one amount holding all of that cell's digits.
3. The planted amounts, for the mutants of the `noise` family. Each of those is one damage that can't turn a file
   into another honest file: an invisible or look-alike character, a quote added, moved or removed, a line break
   inside a quoted cell, another encoding with bytes dropped, an `=`, spaces, brackets or a text mark around an
   amount, other grouping and decimal marks than the declared ones, or one character that is not a digit, a decimal
   mark, the delimiter or a line break added, removed or replaced; or a pile of two to four additions, none of
   which takes a character away. Such a mutant must be refused, or list exactly the planted amounts, each in full.
   A planted amount listed in part, or not at all, is a miss.

The `any` family applies one to four damages of any kind, raw bytes, digits, delimiters and line breaks included.
Those can make another honest file (`123;456` becomes `123456`), so only checks 1 and 2 apply to them.

    python scripts/figure_source_mutants.py                      # 200,000 mutants over the fixed seed list
    python scripts/figure_source_mutants.py --seeds 7 --mutants 3000

Only counts and, for a failure, the synthetic mutant itself are printed. Exit status: 0 no failure; 1 a failure.
Run it with the interpreter that has the finassist under test installed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
import random
import re
import unicodedata

from finassist.figure_sources import SourceLayout, SourceRefused, read_source, source_amounts

SEEDS = (20261125, 11, 23, 37, 41, 59, 67, 83)
MUTANTS_PER_SEED = 25_000
MUTANTS_PER_FILE = 10
MIN_DIGITS = 5
NOISE_SHARE = 0.65  # of the mutants: those of the noise family
PILED_SHARE = 0.2  # of the mutants: those of the noise family that pile several additions up

DELIMITERS = (",", ";", "\t", "|")
SIGNS = "$\u20ac\u00a3\u00a5"
CODES = ("USD", "EUR", "CHF", "GBP", "JPY")
# Invisible and format characters, controls, separators and spaces that group nothing.
MARKS = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\xad", "\u200e", "\u200f", "\u061c", "\u202a", "\u202c",
         "\u202e", "\u2066", "\u2069", "\ufe0f", "\ufe00", "\U000e0100", "\U000e0041", "\u180e", "\u2062", "\u034f",
         "\u3164", "\u2800", "\x00", "\x0b", "\x0c", "\x1e", "\x7f", "\x85", "\u2028", "\u2029", "\u2008", "\u2002",
         "\u3000", "\u1680", "\xa0", "\u2009", "\u202f", "\u2007", "\ufffd", "\ue000", "\U000f0000", "\u0378"]
LOOK_ALIKES = {".": ["\uff0e", "\u00b7", "\u2024", "\u02d9", "\u066b", "\u06d4"],
               ",": ["\uff0c", "\u066c", "\u201a", "\u060c", "\u02cc"],
               " ": ["\xa0", "\u2009", "\u202f", "\u2007", "\u2003"],
               "'": ["\u2019", "\u02bc", "\u2032", "\uff07", "`"]}
DIGIT_ZEROS = [0xFF10, 0x0660, 0x06F0, 0x0966, 0x1D7CE, 0x2080, 0x2070]  # look-alike digits start at these
NAMES = ["Synthetic Fund", "M\u00fcller Depot", "\u00d8degaard", "Caf\u00e9 Zwei", "\u6771\u4eac", "Alpha; Beta",
         "Gamma, Delta", "Lot 12 of 40", "Ref|7", 'Said "hold"', "Total 98.765,43", "1,234,567.89 gross", "e\u0301t\u00e9",
         "A1", "2026-01-02", "02.01.2026 14:30", "SYN-0042", "00012345", "", "n/a", "\u0416\u0443\u043a"]
LABELS = ["", "EUR", "Buy", "n/a", "-", "open", "USD", "\u20ac"]
AMOUNT_HEADERS = ["Amount", "Betrag", "Value", "Balance", "Net", "Gross", "Fee"]
TEXT_HEADERS = ["Account", "Date", "Memo 2026", "W\u00e4hrung", "Id", "Name", "Note 1"]


@dataclass
class Case:
    layout: SourceLayout
    text: str
    bom: bool
    planted: set
    amounts: list = field(default_factory=list)  # (start, end, whole digits, fraction digits) of each amount's own text
    quoted: list = field(default_factory=list)  # (start, end) of each quoted cell, quotes included

    def raw(self) -> bytes:
        return (b"\xef\xbb\xbf" if self.bom else b"") + self.text.encode("utf-8")


def _layout(rng: random.Random, header: bool, kinds: list[str], names: list[str]) -> SourceLayout:
    delimiter = rng.choice(DELIMITERS)
    decimal_mark = rng.choice([mark for mark in ".," if mark != delimiter])
    group_mark = rng.choice([mark for mark in (None, ",", ".", " ", "'") if mark != decimal_mark])
    columns = []
    for index, kind in enumerate(kinds):
        if kind == "text":
            columns.append(names[index] if header and rng.random() < 0.5 else index + 1)
    rng.shuffle(columns)
    return SourceLayout(delimiter, decimal_mark, group_mark, header, tuple(columns))


def _spelled(rng: random.Random, whole: str, fraction: str, decimal_mark: str, group_mark: str | None) -> str:
    """One amount in the declared grammar: groups or none, a sign or brackets, a currency before or after."""
    if group_mark is not None and len(whole) > 3 and rng.random() < 0.6:
        first = len(whole) % 3 or 3
        whole = group_mark.join([whole[:first]] + [whole[at:at + 3] for at in range(first, len(whole), 3)])
    number = whole + decimal_mark + fraction
    currency = rng.choice([*SIGNS, *CODES])
    choice = rng.random()
    if choice < 0.2:
        number = currency + rng.choice(["", " "]) + number
    elif choice < 0.4:
        number = number + rng.choice(["", " "]) + currency
    choice = rng.random()
    if choice < 0.15:
        number = "(" + number + ")"
    elif choice < 0.4:
        number = rng.choice("+-") + number
    return number


def _quote(cell: str) -> str:
    return '"' + cell.replace('"', '""') + '"'


def generate(rng: random.Random) -> Case:
    """A well-formed file with a declared layout and the amounts planted in it, each of five or more significant
    digits with a fraction, so no single damage of the noise family can make another amount of one."""
    width = rng.choice([1, 2, 2, 3, 3, 4, 5])
    kinds = [rng.choice(["text", "amount", "amount", "label"]) for _ in range(width)]
    kinds[rng.randrange(width)] = "amount"
    header = rng.random() < 0.7
    amount_names, text_names = rng.sample(AMOUNT_HEADERS, len(AMOUNT_HEADERS)), rng.sample(TEXT_HEADERS, len(TEXT_HEADERS))
    names = [text_names.pop() if kind == "text" else amount_names.pop() for kind in kinds]
    layout = _layout(rng, header, kinds, names)
    end = rng.choice(["\n", "\n", "\r\n"])
    case = Case(layout, "", rng.random() < 0.2, set())
    parts: list[str] = []
    length = 0

    def put(piece: str) -> int:
        nonlocal length
        parts.append(piece)
        length += len(piece)
        return length

    rows = rng.randint(3, 6)
    for row in range(rows + header):
        bare_before = None  # the cell before, as written, when it stands without quotes
        for index, kind in enumerate(kinds):
            if index:
                put(layout.delimiter)
            span = None
            if header and row == 0:
                cell = names[index]
            elif kind == "text":
                cell = rng.choice(NAMES)
            elif kind == "label":
                cell = rng.choice(LABELS)
            else:
                whole = str(rng.randint(1, 9)) + "".join(rng.choice("0123456789") for _ in range(rng.randint(3, 9)))
                fraction = "".join(rng.choice("0123456789") for _ in range(rng.choice([0, 1, 1, 2, 3]))) + rng.choice("123456789")
                cell = _spelled(rng, whole, fraction, layout.decimal_mark, layout.group_mark)
                case.planted.add(whole + "." + fraction)
                span = (whole, fraction)
            needs_quotes = layout.delimiter in cell or '"' in cell
            pad = (rng.choice(["", " "]), rng.choice(["", " "])) if span and rng.random() < 0.2 else ("", "")
            # In a comma file a bare cell after one a grouping comma could have cut is refused, so it is quoted.
            cut = layout.delimiter == "," and bare_before is not None and _reference_cut(bare_before, pad[0] + cell + pad[1])
            if needs_quotes or cut or rng.random() < 0.15:
                bare_before = None
                written = _quote(pad[0] + cell + pad[1])
                start = length
                put(written)
                case.quoted.append((start, length))
                if span:
                    case.amounts.append((start + 1 + len(pad[0]), start + 1 + len(pad[0]) + len(cell), *span))
            else:
                bare_before = pad[0] + cell + pad[1]
                start = length
                put(pad[0] + cell + pad[1])
                if span:
                    case.amounts.append((start + len(pad[0]), start + len(pad[0]) + len(cell), *span))
        if row < rows + header - 1 or rng.random() < 0.85:
            put(end)
    case.text = "".join(parts)
    return case


# --- The second reader: the same rules, written apart from the reader under test. ---

REFUSED = "refused"
_LETTERS = {"Lu", "Ll", "Lt", "Lm", "Lo", "Mn", "Mc", "Me"}
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_DIGITS = "0123456789"


def _reference_rows(raw: bytes, delimiter: str):
    if raw[:3] == b"\xef\xbb\xbf":
        raw = raw[3:]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return REFUSED, ""
    for character in text:
        code = ord(character)
        if character in "\r\n" or 0x20 <= code <= 0x7E or character in SIGNS[1:]:
            continue
        if character == "\t" and delimiter == "\t":
            continue
        if code < 0x80 or unicodedata.category(character) not in _LETTERS:
            return REFUSED, text
    rows, row, cell, state, at = [], [], [], "start", 0
    kinds, row_kinds = [], []  # for each cell, the state it ended in: "closed" for a quoted one

    def end_cell(ended: str) -> None:
        row.append("".join(cell))
        row_kinds.append(ended)
        cell.clear()

    while at < len(text):
        character = text[at]
        if state == "quoted":
            if character == '"':
                if text[at + 1:at + 2] == '"':
                    cell.append('"')
                    at += 2
                    continue
                state = "closed"
            elif character in "\r\n":
                return REFUSED, text
            else:
                cell.append(character)
            at += 1
            continue
        if character == delimiter:
            end_cell(state)
            state = "start"
        elif character == "\n" or text[at:at + 2] == "\r\n":
            end_cell(state)
            rows.append(row)
            kinds.append(row_kinds)
            row, row_kinds, state = [], [], "start"
            at += 1 if character == "\n" else 2
            continue
        elif character == "\r" or state == "closed":
            return REFUSED, text
        elif character == '"':
            if state != "start":
                return REFUSED, text
            state = "quoted"
        else:
            cell.append(character)
            state = "open"
        at += 1
    if state == "quoted":
        return REFUSED, text
    if state != "start" or row:
        end_cell(state)
        rows.append(row)
        kinds.append(row_kinds)
    if not rows or any(len(item) != len(rows[0]) for item in rows):
        return REFUSED, text
    if delimiter == "," and any(_reference_cut(row[index - 1], row[index])
                                for row, ended in zip(rows, kinds, strict=True) for index in range(1, len(row))
                                if ended[index - 1] != "closed" and ended[index] != "closed"):
        return REFUSED, text
    return rows, text


def _reference_cut(first: str, second: str) -> bool:
    """Whether two bare cells of a comma file may be one amount a grouping comma cut: a cell that ends with one to
    three digits that are not a fraction, and then exactly three digits."""
    if len(second) < 3 or any(c not in _DIGITS for c in second[:3]) or second[3:4] in tuple(_DIGITS):
        return False
    run = 0
    while run < len(first) and first[len(first) - 1 - run] in _DIGITS:
        run += 1
    return 1 <= run <= 3 and first[len(first) - 1 - run:len(first) - run] != "."


def _reference_currency(text: str, at_end: bool) -> int:
    """How many characters of a currency stand at the start, or the end, of text: 1, 3 or 0."""
    if text and (text[-1] if at_end else text[0]) in SIGNS:
        return 1
    code = text[-3:] if at_end else text[:3]
    return 3 if len(code) == 3 and all(letter in _UPPER for letter in code) else 0


def _reference_amount(cell: str, layout: SourceLayout):
    """None for a cell with no digit, (whole digits, fraction digits) for one amount, or REFUSED."""
    text = cell
    while text[:1] == " ":
        text = text[1:]
    while text[-1:] == " ":
        text = text[:-1]
    if not any(character in _DIGITS for character in text):
        return None
    if text[0] == "(":
        if text[-1] != ")":
            return REFUSED
        text = text[1:-1]
    elif text[0] in "+-":
        text = text[1:]
    before = _reference_currency(text, False)
    if before:
        text = text[before:]
        if text[:1] == " ":
            text = text[1:]
    at = 0
    while at < len(text) and text[at] in _DIGITS:
        at += 1
    if at == 0:
        return REFUSED
    whole = text[:at]
    if layout.group_mark is not None and at <= 3:
        while (text[at:at + 1] == layout.group_mark and len(text) >= at + 4
               and all(character in _DIGITS for character in text[at + 1:at + 4])
               and text[at + 4:at + 5] not in tuple(_DIGITS)):
            whole += text[at + 1:at + 4]
            at += 4
    fraction = ""
    if text[at:at + 1] == layout.decimal_mark:
        stop = at + 1
        while stop < len(text) and text[stop] in _DIGITS:
            stop += 1
        if stop == at + 1:
            return REFUSED
        fraction, at = text[at + 1:stop], stop
    rest = text[at:]
    if rest:
        if before:
            return REFUSED
        if rest[0] == " ":
            rest = rest[1:]
        if not rest or _reference_currency(rest, True) != len(rest):
            return REFUSED
    if len(whole) + len(fraction) > 260:
        return REFUSED
    return whole, fraction


def reference(raw: bytes, layout: SourceLayout):
    """REFUSED, or ([(line, column, canonical magnitude)], rows, text columns, decoded text)."""
    rows, text = _reference_rows(raw, layout.delimiter)
    if rows == REFUSED:
        return REFUSED
    columns = set()
    for item in layout.text_columns:
        if isinstance(item, int):
            if item > len(rows[0]):
                return REFUSED
            columns.add(item - 1)
        else:
            if rows[0].count(item) != 1:
                return REFUSED
            columns.add(rows[0].index(item))
    amounts = []
    for line, row in enumerate(rows, 1):
        for index, cell in enumerate(row):
            if index in columns:
                continue
            if any(ord(character) >= 0x80 and character not in SIGNS for character in cell):
                return REFUSED
            read = _reference_amount(cell, layout)
            if read == REFUSED:
                return REFUSED
            if read is not None:
                whole, fraction = read
                if "".join(character for character in cell if character in _DIGITS) != whole + fraction:
                    raise AssertionError("the second reader dropped a digit of a cell")
                fraction = fraction.rstrip("0")
                amounts.append((line, index + 1, (whole.lstrip("0") or "0") + ("." + fraction if fraction else "")))
    if "".join(c for c in text if c in _DIGITS) != "".join(c for row in rows for cell in row for c in cell if c in _DIGITS):
        raise AssertionError("the second reader's cells do not hold the digits of the text in order")
    return amounts, rows, columns, text


# --- Damages. Each takes and returns bytes; those of the noise family are listed in NOISE. ---

def _inside(rng: random.Random, case: Case) -> int:
    """A position strictly inside one planted amount's own text."""
    start, end, _whole, _fraction = rng.choice(case.amounts)
    return rng.randint(start + 1, end - 1)


def _anywhere(rng: random.Random, case: Case) -> int:
    return _inside(rng, case) if rng.random() < 0.7 else rng.randint(0, len(case.text))


def _encoded(case: Case, text: str) -> bytes:
    return (b"\xef\xbb\xbf" if case.bom else b"") + text.encode("utf-8", "surrogatepass")


def invisible(rng, case):
    at, text = _anywhere(rng, case), case.text
    return _encoded(case, text[:at] + rng.choice(MARKS) * rng.choice([1, 1, 1, 2, 130]) + text[at:])


def look_alike(rng, case):
    start, end, _whole, _fraction = rng.choice(case.amounts)
    text = case.text
    places = [at for at in range(start, end) if text[at] in LOOK_ALIKES or text[at].isdigit()]
    at = rng.choice(places)
    if text[at].isdigit():
        swap = chr(rng.choice(DIGIT_ZEROS) + int(text[at]))
    else:
        swap = rng.choice(LOOK_ALIKES[text[at]])
    return _encoded(case, text[:at] + swap + text[at + 1:])


def quotes(rng, case):
    text = case.text
    start, end, _whole, _fraction = rng.choice(case.amounts)
    choice = rng.randrange(9)
    if choice == 0:  # a stray quote
        at = _anywhere(rng, case)
        return _encoded(case, text[:at] + '"' + text[at:])
    if choice == 1 and case.quoted:  # a quote removed
        first, last = rng.choice(case.quoted)
        at = rng.choice([first, last - 1])
        return _encoded(case, text[:at] + text[at + 1:])
    if choice == 2 and case.quoted:  # a closing quote moved
        first, last = rng.choice(case.quoted)
        to = rng.randint(first + 1, min(len(text), last + 6))
        without = text[:last - 1] + text[last:]
        return _encoded(case, without[:to] + '"' + without[to:])
    inner = text[start:end]
    cut = rng.randint(1, len(inner) - 1)
    lead = rng.choice([" ", "=", "= ", "\t", "'", "x"])
    spelled = [f'"{inner}"', f'{lead}"{inner}"', f'"{inner}"{lead}', f'"{inner[:cut]}"{inner[cut:]}',
               f'{inner[:cut]}"{inner[cut:]}"', f'"{inner[:cut]}""{inner[cut:]}"', f'""{inner}""',
               f'"{inner[:cut]}" "{inner[cut:]}"', f"'{inner}'"]
    if text[start - 1:start] == '"':  # already quoted: the quotes are the cell's own
        return _encoded(case, text[:start] + rng.choice([lead, '"', '""']) + text[start:])
    return _encoded(case, text[:start] + rng.choice(spelled) + text[end:])


def split_line(rng, case):
    """A line break inside a quoted cell: an amount quoted and split, or a break put into a cell already quoted."""
    text = case.text
    start, end, _whole, _fraction = rng.choice(case.amounts)
    break_ = rng.choice(["\n", "\r\n", "\r", "\n ", "\n\t", " \n", "\n" + " " * 65, "\u2028", "\x0b", "\x85"])
    if rng.random() < 0.2 and case.quoted:
        first, last = rng.choice(case.quoted)
        at = rng.randint(first + 1, last - 1)
        return _encoded(case, text[:at] + break_ + text[at:])
    inner = text[start:end]
    cut = rng.randint(1, len(inner) - 1)
    if text[start - 1:start] == '"':
        return _encoded(case, text[:start + cut] + break_ + text[start + cut:])
    lead = rng.choice(["", "", " ", "=", "= ", "\t"])
    return _encoded(case, text[:start] + f'{lead}"{inner[:cut]}{break_}{inner[cut:]}"' + text[end:])


def other_encoding(rng, case):
    codec = rng.choice(["utf-16", "utf-16-le", "utf-16-be", "utf-32", "latin-1", "cp1252", "utf-8-cut"])
    text = case.text
    if codec == "utf-8-cut":  # one byte of a character written in several bytes is dropped
        raw = bytearray(text.encode("utf-8"))
        places = [at for at, byte in enumerate(raw) if byte >= 0x80]
        if not places:
            codec = "utf-16"
        else:
            del raw[rng.choice(places)]
            return (b"\xef\xbb\xbf" if case.bom else b"") + bytes(raw)
    try:
        raw = bytearray(text.encode(codec))
    except UnicodeEncodeError:
        raw = bytearray(text.encode("utf-16"))
        codec = "utf-16"
    if codec.startswith("utf-") and rng.random() < 0.6:
        for _ in range(rng.choice([1, 2, 2, 3])):
            del raw[rng.randrange(len(raw))]
    return bytes(raw)


def decorated(rng, case):
    text = case.text
    start, end, _whole, _fraction = rng.choice(case.amounts)
    inner = text[start:end]
    spelled = rng.choice(["=" + inner, "= " + inner, "(" + inner + ")", "[" + inner + "]", "{" + inner + "}",
                          inner + "-", inner + " CR", inner + " DR", inner + "%", inner + " %", inner + "*",
                          inner + " (e)", "  " + inner + "  ", "\t" + inner, inner + "\t", "(" + inner, inner + ")",
                          "((" + inner + "))", "+" + inner, "-" + inner, "--" + inner, inner + " H", inner + " S",
                          "~" + inner, "<" + inner, "#" + inner, inner + "/", inner + ":", "'" + inner, inner + "'"])
    return _encoded(case, text[:start] + spelled + text[end:])


def other_marks(rng, case):
    """An amount respelled with grouping and decimal marks that are not all the declared ones."""
    text, layout = case.text, case.layout
    spans = [span for span in case.amounts if len(span[3]) != 3]
    if not spans:
        return decorated(rng, case)
    start, end, whole, fraction = rng.choice(spans)
    delimiter_free = [mark for mark in ".,' " if mark != layout.delimiter]
    while True:
        decimal_mark = rng.choice([mark for mark in ".," if mark != layout.delimiter] or ["."])
        group_mark = rng.choice([None, *[mark for mark in delimiter_free if mark != decimal_mark]])
        if (decimal_mark, group_mark) != (layout.decimal_mark, layout.group_mark):
            break
    if group_mark is not None and len(whole) > 3:
        first = len(whole) % 3 or 3
        whole = group_mark.join([whole[:first]] + [whole[at:at + 3] for at in range(first, len(whole), 3)])
    return _encoded(case, text[:start] + whole + decimal_mark + fraction + text[end:])


def one_character(rng, case):
    """One character that is not a digit, the declared decimal mark, the delimiter or a line break added, removed or
    replaced. No such change makes another amount of a planted one."""
    text, layout = case.text, case.layout
    kept = set("0123456789\r\n") | {layout.decimal_mark}
    fresh = [chr(code) for code in range(0x20, 0x7F) if chr(code) not in "0123456789" and chr(code) != layout.delimiter]
    choice = rng.randrange(3)
    if choice == 0:
        at = _anywhere(rng, case)
        return _encoded(case, text[:at] + rng.choice(fresh) + text[at:])
    places = [at for at, character in enumerate(text) if character not in kept]
    if not places:
        return invisible(rng, case)
    at = rng.choice(places)
    return _encoded(case, text[:at] + (rng.choice(fresh) if choice == 1 else "") + text[at + 1:])


NOISE = (invisible, look_alike, quotes, split_line, other_encoding, decorated, other_marks, one_character)
_QUOTED = re.compile(r'"[^"\r\n]+"')


def piled(rng, case):
    """Two to four additions on top of one another, none of which takes a character away or adds a digit, the
    delimiter or a line break outside quotes: an invisible character, a printable one that is no quote, a
    look-alike in place of a mark, a pair of quotes around any stretch of a line that holds no quote, a line break
    inside a quoted cell. Cells can then only merge, never part, so no pile of these makes another amount of a
    planted one either. (Quotes added inside a quoted cell that holds the delimiter could part it: `"a;b"` to
    `"a";"b"`. That is another honest file, so the pile adds none there.)"""
    text = case.text
    fresh = [chr(code) for code in range(0x20, 0x7F)
             if chr(code) not in '0123456789"' and chr(code) != case.layout.delimiter]
    for _ in range(rng.randint(2, 4)):
        digits = [at for at, character in enumerate(text) if character in _DIGITS]
        at = rng.choice(digits) + rng.randint(0, 1) if digits and rng.random() < 0.7 else rng.randint(0, len(text))
        choice = rng.randrange(5)
        marks = [place for place, character in enumerate(text) if character in LOOK_ALIKES]
        cells = list(_QUOTED.finditer(text))
        start = text.rfind("\n", 0, at) + 1
        stop = text.find("\n", at)
        stop = len(text) if stop < 0 else stop
        if choice == 0:
            text = text[:at] + rng.choice(MARKS) + text[at:]
        elif choice == 1 or choice == 2 and not marks or choice == 4 and not cells or choice == 3 and '"' in text[start:stop]:
            text = text[:at] + rng.choice(fresh) + text[at:]
        elif choice == 2:
            place = rng.choice(marks)
            text = text[:place] + rng.choice(LOOK_ALIKES[text[place]]) + text[place + 1:]
        elif choice == 3:
            first = rng.randint(start, at)
            last = rng.randint(at, stop)
            text = text[:first] + '"' + text[first:last] + '"' + text[last:]
        else:
            cell = rng.choice(cells)
            place = rng.randint(cell.start() + 1, cell.end() - 1)
            text = text[:place] + rng.choice(["\n", "\r\n"]) + text[place:]
    return _encoded(case, text)


def raw_bytes(rng, raw: bytes) -> bytes:
    """One damage of any kind on raw bytes: a byte, a digit, a delimiter, a line break or a mark added, removed or
    replaced, a run moved, cut or repeated."""
    data = bytearray(raw)
    choice = rng.randrange(8)
    at = rng.randrange(len(data) + 1)
    piece = rng.choice([bytes([rng.randrange(256)]), rng.choice(b"0123456789").to_bytes(1, "big"), b",", b";", b"\t",
                        b"|", b"\n", b"\r\n", b"\r", b".", b" ", b"'", b'"', b"(", b")", b"-", b"=", b"\xc2\xa0",
                        b"\xe2\x80\x8b", b"\xef\xbb\xbf", b"\x00", b"e2", b"USD", b"\xe2\x82\xac"])
    if choice <= 1 or not data:
        data[at:at] = piece
    elif choice == 2:
        del data[min(at, len(data) - 1)]
    elif choice == 3:
        data[min(at, len(data) - 1):min(at, len(data) - 1) + 1] = piece
    elif choice == 4:
        del data[at:]
    elif choice == 5:
        stop = min(len(data), at + rng.randint(1, 12))
        data[at:at] = data[at:stop]
    elif choice == 6:
        stop = min(len(data), at + rng.randint(1, 12))
        run = bytes(data[at:stop])
        del data[at:stop]
        to = rng.randrange(len(data) + 1)
        data[to:to] = run
    else:
        del data[at:min(len(data), at + rng.randint(1, 6))]
    return bytes(data)


def mutant(rng: random.Random, case: Case) -> tuple[str, str, bytes]:
    """(family, damage names, bytes) of one mutant of a file."""
    roll = rng.random()
    if roll < NOISE_SHARE - PILED_SHARE:
        damage = rng.choice(NOISE)
        return "noise", damage.__name__, damage(rng, case)
    if roll < NOISE_SHARE:
        return "noise", piled.__name__, piled(rng, case)
    raw = case.raw()
    names = []
    for _ in range(rng.randint(1, 4)):
        if rng.random() < 0.3:
            damage = rng.choice(NOISE)
            names.append(damage.__name__)
            raw = damage(rng, case) if len(names) == 1 else raw_bytes(rng, raw)
        else:
            names.append("raw_bytes")
            raw = raw_bytes(rng, raw)
    return "any", "+".join(names), raw


def check(family: str, case: Case, raw: bytes) -> tuple[str, str | None]:
    """("refused" or "read", None) for a mutant that passes every check, or (outcome, what failed)."""
    expected = reference(raw, case.layout)
    try:
        found = source_amounts(raw, case.layout)
    except SourceRefused:
        return "refused", None if expected == REFUSED else "refused a file the second reader reads"
    except Exception as error:  # noqa: BLE001 - any other exception is a crash of the reader under test
        return "refused", f"crashed: {type(error).__name__}"
    if expected == REFUSED:
        return "read", "read a file the second reader refuses"
    amounts, _rows, _columns, _text = expected
    if found != amounts:
        return "read", "read other amounts than the second reader"
    if family == "noise":
        listed, _forms, rounds = read_source(raw, case.layout, MIN_DIGITS, True)
        if listed | rounds != case.planted:
            return "read", ("listed an amount that is not a planted one" if (listed | rounds) - case.planted
                            else "read the file and left a planted amount out")
    return "read", None


def run(seed: int, mutants: int) -> dict:
    rng = random.Random(seed)
    counts = {"seed": seed, "mutants": 0, "noise": 0, "any": 0, "refused": 0, "read": 0, "noise_read": 0,
              "unchanged": 0, "by_damage": {}, "failures": []}
    case = generate(rng)
    for number in range(mutants):
        if number % MUTANTS_PER_FILE == 0:
            case = generate(rng)
            if check("noise", case, case.raw()) != ("read", None):
                counts["failures"].append({"what": "a well-formed file is not read with its planted amounts",
                                           "layout": list(case.layout), "bytes": repr(case.raw())})
        family, damage, raw = mutant(rng, case)
        outcome, failure = check(family, case, raw)
        counts["mutants"] += 1
        counts[family] += 1
        counts[outcome] += 1
        counts["unchanged"] += raw == case.raw()
        counts["noise_read"] += family == "noise" and outcome == "read"
        row = counts["by_damage"].setdefault(damage.split("+")[0] if family == "noise" else "any", [0, 0])
        row[outcome == "read"] += 1
        if failure and len(counts["failures"]) < 20:
            counts["failures"].append({"what": failure, "family": family, "damage": damage, "mutant": number,
                                       "layout": list(case.layout), "bytes": repr(raw), "file": repr(case.raw())})
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, nargs="+", default=list(SEEDS))
    parser.add_argument("--mutants", type=int, default=MUTANTS_PER_SEED, help="mutants for each seed")
    args = parser.parse_args()
    results = [run(seed, args.mutants) for seed in args.seeds]
    total = {key: sum(result[key] for result in results)
             for key in ("mutants", "noise", "any", "refused", "read", "noise_read", "unchanged")}
    total["refused_share"] = round(total["refused"] / max(1, total["mutants"]), 4)
    total["failures"] = sum(len(result["failures"]) for result in results)
    print(json.dumps({"seeds": args.seeds, "mutants_per_seed": args.mutants, "total": total, "runs": results},
                     indent=1, sort_keys=True))
    return 1 if total["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
