"""Figure sources: delimited export files whose amounts the confidential-figure screen lists.

A source is read one way only, by the layout its entry declares, and strictly. For any bytes, either the file is
refused by name, or every digit in it belongs to a cell that was read in full as one amount, or to a column the entry
declares as text. Nothing is guessed and no cell is read in part:

- Bytes: UTF-8, read strictly, with at most one byte-order mark, at the very start. A NUL byte or bytes that are not
  UTF-8 refuse the file.
- Characters: printable ASCII; the tab, only as the delimiter; line ends, `\\n` or `\\r\\n`; the four currency
  signs the figure file reads (`CURRENCY_SIGNS`); and letters and combining marks outside ASCII (Unicode categories
  L and M), in text columns only. Any other character refuses the file wherever it stands: a control, a format or
  invisible character, a space or a digit outside ASCII, any other symbol, a private or unassigned code point.
- Rows and quotes: one row per line. A cell is quoted as a whole or not at all: a quote stands only as a cell's
  first and last character, or doubled inside a quoted cell. A quoted cell ends on its own line, so a line break
  inside one refuses the file. Every row has as many cells as the first. In a comma file, a comma that may be a
  grouping comma between two bare cells refuses the file (`_check_cut_groups`).
- Cells outside the text columns, with the spaces around them dropped: empty; or a label, which holds no digit; or
  one amount, in full (`_amount_pattern`). Any other cell with a digit refuses the file.

The refusals name a line and a column, never a cell's content. What an amount is listed as, and the bounds on a
number, are those of the figure file: `normalize_numeric_token` and `_digit_forms` of forbidden_tokens, which loads
sources here.
"""

import codecs
from functools import lru_cache
import re
from typing import NamedTuple
import unicodedata

from .errors import AssistantError
from .forbidden_tokens import MAX_SOURCE_FIGURES, _CURRENCIES, _digit_forms, normalize_numeric_token
from .python_source import MAX_FIGURE_DIGITS

DELIMITERS = (",", ";", "\t", "|")
DECIMAL_MARKS = (".", ",")
GROUP_MARKS = (None, ",", ".", " ", "'")  # None: the whole part is written without groups
CURRENCY_SIGNS = _CURRENCIES  # one may stand beside an amount; they are the signs the figure file reads
MAX_TEXT_COLUMNS = 64
MAX_COLUMN_NAME = 256
MAX_COLUMN_POSITION = 4096

# Which rules decide what a figure source lists. It is raised with every change to that, and it is part of the
# identity of a configuration, and of the bytes of a gate policy, that lists sources: the same settings can then never
# mean another list. 1 is every release before sources. 28 reads a source strictly, by its declared layout only, as
# this module says. 2 to 27 are of builds that read a source in other ways: they are refused like 1, and no setting
# brings them back.
SOURCE_RULE = 28
# 29 lists round figures too, when forbidden_token_round_figures is "list": 28 does not list them. The rule follows
# the setting; no setting chooses an older reading.
ROUND_RULE = 29
ROUND_LIST = "list"
ROUND_OPTIONS = ("skip", ROUND_LIST)
ROUND_MIN_SIGNIFICANT = 4  # fixed: rounder values are constants in ordinary code


def source_rule(round_figures: str) -> int:
    """The source rule a setting reads sources by: 29 when round figures are listed, else 28."""
    return ROUND_RULE if round_figures == ROUND_LIST else SOURCE_RULE


class SourceLayout(NamedTuple):
    """How one source is read, as its entry declares it; every part is stated, none is guessed."""

    delimiter: str
    decimal_mark: str
    group_mark: str | None
    header: bool  # the first row names the columns, so a text column may be given by its name
    text_columns: tuple  # 1-based positions, and with a header exact names, of the columns that hold no figures


def layout_valid(layout) -> bool:
    """Whether a layout can be read at all: known marks, and text columns given once each.

    A comma that both parts columns and marks decimals is not a layout: quoted or not, `1,5` would be one amount or
    two cells. A comma may part columns and group digits, as most comma files do: an amount with a grouping comma
    is then read from a quoted cell only, and a bare one is refused (`_check_cut_groups`).
    """
    if not (isinstance(layout, SourceLayout) and all(type(part) is str for part in layout[:2])
            and layout.delimiter in DELIMITERS and layout.decimal_mark in DECIMAL_MARKS
            and (layout.group_mark is None or type(layout.group_mark) is str) and layout.group_mark in GROUP_MARKS
            and type(layout.header) is bool and isinstance(layout.text_columns, tuple)):
        return False
    if layout.decimal_mark in (layout.delimiter, layout.group_mark):
        return False
    columns = layout.text_columns
    if len(columns) > MAX_TEXT_COLUMNS:
        return False
    for item in columns:
        if type(item) is int:
            if not 1 <= item <= MAX_COLUMN_POSITION:
                return False
        elif type(item) is not str or not item or len(item) > MAX_COLUMN_NAME or not layout.header:
            return False
    return len(set(columns)) == len(columns)  # a position and a name are never equal: 1 is not "1"


class SourceRefused(ValueError):
    """A source that is not read: the whole file is refused, at this line and column where one is known. The
    position is a count of lines and cells, never a cell's content."""

    def __init__(self, line: int | None = None, column: int | None = None):
        super().__init__("a figure source is refused")
        self.line, self.column = line, column

    @property
    def position(self) -> dict:
        return {name: value for name, value in (("line", self.line), ("column", self.column)) if value is not None}


class EncodingSource(SourceRefused):
    """Bytes that are not UTF-8, or a NUL byte."""


class HiddenMarkSource(SourceRefused):
    """A character a source may not hold, or a letter outside ASCII outside the text columns."""


class MalformedQuotesSource(SourceRefused):
    """A quote that does not open and close one whole cell on one line."""


class LayoutMismatchSource(SourceRefused):
    """A file that is not the table its layout declares: no rows, rows of different widths, or a text column the
    first row does not hold exactly once."""


class AmbiguousSource(SourceRefused):
    """A comma file with a comma that may group the digits of one amount or part two cells."""


class CellSource(SourceRefused):
    """A cell outside the text columns that holds a digit and is not one amount in full."""


class UnscreenableSource(SourceRefused):
    """An amount of more digits than the screen reads in a payload."""


_ASCII_REFUSED = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # every ASCII control but tab, LF and CR
_OUTSIDE_ASCII = re.compile(r"[^\x00-\x7f]")
_DIGIT = re.compile(r"[0-9]")


def _line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _decode(raw: bytes) -> str:
    """The file's text: UTF-8 read strictly, less one byte-order mark at the very start."""
    if b"\x00" in raw:
        raise EncodingSource
    if raw.startswith(codecs.BOM_UTF8):
        raw = raw[len(codecs.BOM_UTF8):]
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EncodingSource from None


def _is_text_letter(character: str) -> bool:
    """A letter or combining mark outside ASCII: allowed in a text column, and nowhere else."""
    return unicodedata.category(character)[0] in "LM"


def _check_characters(text: str, delimiter: str) -> None:
    """Refuse the file for any character it may not hold, wherever it stands (see the module's list). Letters
    outside ASCII pass here; a cell outside the text columns refuses them (`source_amounts`)."""
    refused = _ASCII_REFUSED.search(text)
    if refused is None and delimiter != "\t" and (tab := text.find("\t")) >= 0:
        raise HiddenMarkSource(_line_of(text, tab))
    if refused is not None:
        raise HiddenMarkSource(_line_of(text, refused.start()))
    if text.isascii():
        return
    allowed: dict[str, bool] = {}
    for match in _OUTSIDE_ASCII.finditer(text):
        character = match.group()
        fits = allowed.get(character)
        if fits is None:
            fits = allowed[character] = character in CURRENCY_SIGNS or _is_text_letter(character)
        if not fits:
            raise HiddenMarkSource(_line_of(text, match.start()))


def _cells(line: str, delimiter: str, number: int) -> tuple[list[str], list[bool]]:
    """The cells of one line without their quotes, and whether each was written bare, without quotes; or refused: a
    quote may only open and close one whole cell, and stand doubled inside it."""
    cells, bare, position, end = [], [], 0, len(line)
    while True:
        bare.append(not (position < end and line[position] == '"'))
        if not bare[-1]:
            parts, start = [], position + 1
            while True:
                close = line.find('"', start)
                if close < 0:  # never closed on its own line: an open quote, or a line break inside a quoted cell
                    raise MalformedQuotesSource(number, len(cells) + 1)
                if close + 1 < end and line[close + 1] == '"':
                    parts.append(line[start:close + 1])  # a doubled quote is one quote of the cell
                    start = close + 2
                    continue
                parts.append(line[start:close])
                position = close + 1
                break
            if position < end and line[position] != delimiter:  # anything between the closing quote and the delimiter
                raise MalformedQuotesSource(number, len(cells) + 1)
            cell = "".join(parts)
        else:
            stop = line.find(delimiter, position)
            if stop < 0:
                stop = end
            cell = line[position:stop]
            if '"' in cell:  # a quote that does not start its cell
                raise MalformedQuotesSource(number, len(cells) + 1)
            position = stop
        cells.append(cell)
        if position >= end:
            return cells, bare
        position += 1  # past the delimiter: a line that ends in one has a last, empty cell


# In a comma file, what a comma may have cut out of one amount grouped by commas: a bare cell that is a whole number
# of one to three digits, with the sign, bracket or currency that may start an amount, and then a bare cell that
# starts with exactly three digits.
_CUT_FIRST = re.compile(rf" *\(?[+-]?(?:(?:[{re.escape(CURRENCY_SIGNS)}]|[A-Z]{{3}}) ?)?[0-9]{{1,3}}")
_CUT_NEXT = re.compile(r"[0-9]{3}(?![0-9])")


def _check_cut_groups(cells: list[str], bare: list[bool], number: int) -> None:
    """Refuse a comma file in which a comma may be a grouping comma, not a column break: `1,234,567.89` written
    without quotes is three cells here, and each would read as an amount of its own. The comma is the one delimiter
    that also groups digits, so such a pair is refused whatever group mark the layout declares; quoted, either cell
    is its writer's own cell and is read."""
    for index in range(1, len(cells)):
        if (bare[index - 1] and bare[index] and _CUT_NEXT.match(cells[index])
                and _CUT_FIRST.fullmatch(cells[index - 1])):
            raise AmbiguousSource(number, index + 1)


def _table(text: str, delimiter: str) -> list[list[str]]:
    """The file's rows of cells. A line is one row: a quoted cell never holds a line break (`_cells`), so no row
    spans two lines and no line holds two rows. A CR stands only before the LF that ends a line."""
    lines = text.split("\n")
    ended = lines[-1] == ""
    if ended:
        lines.pop()  # the last line's own end; without one, the last line just ends with the file
    if not lines:
        raise LayoutMismatchSource(1)
    rows = []
    for number, line in enumerate(lines, 1):
        if line.endswith("\r") and (number < len(lines) or ended):
            line = line[:-1]
        if "\r" in line:
            raise HiddenMarkSource(number)
        cells, bare = _cells(line, delimiter, number)
        if delimiter == ",":
            _check_cut_groups(cells, bare, number)
        if rows and len(cells) != len(rows[0]):
            raise LayoutMismatchSource(number)
        rows.append(cells)
    return rows


def _text_columns(layout: SourceLayout, first: list[str]) -> frozenset[int]:
    """The declared text columns as positions from 0 in the first row, or refused: a position past the row's last
    cell, or a name the first row does not hold exactly once, is a layout that is not the file's."""
    found = set()
    for item in layout.text_columns:
        if type(item) is int:
            if item > len(first):
                raise LayoutMismatchSource(1)
            found.add(item - 1)
        else:
            places = [index for index, cell in enumerate(first) if cell == item]
            if len(places) != 1:
                raise LayoutMismatchSource(1)
            found.add(places[0])
    return frozenset(found)


@lru_cache(maxsize=None)
def _amount_pattern(decimal_mark: str, group_mark: str | None) -> re.Pattern:
    """The one spelling of an amount, matched against a whole cell:

        amount   = "(" unsigned ")"  |  [ "+" | "-" ] unsigned
        unsigned = [ currency [ " " ] ] number  |  number [ [ " " ] currency ]
        currency = one of CURRENCY_SIGNS  |  three ASCII capital letters
        number   = whole [ decimal_mark digit+ ]
        whole    = digit+  |  digit{1,3} ( group_mark digit{3} )+     (the second only with a declared group mark)

    Brackets mean a negative amount. There is no exponent, percent sign, footnote, `=`, text mark such as CR or DR,
    leading decimal mark or second currency, and no space but the one beside a currency or a declared grouping space.
    The pattern allows a currency on both sides and unpaired brackets; `_amount` refuses those.
    """
    whole = "[0-9]+"
    if group_mark is not None:
        whole = rf"(?:[0-9]{{1,3}}(?:{re.escape(group_mark)}[0-9]{{3}})+|[0-9]+)"
    currency = rf"(?:[{re.escape(CURRENCY_SIGNS)}]|[A-Z]{{3}})"
    return re.compile(rf"(?P<open>\()?(?P<sign>[+-])?(?:(?P<before>{currency}) ?)?(?P<whole>{whole})"
                      rf"(?:{re.escape(decimal_mark)}(?P<fraction>[0-9]+))?(?: ?(?P<after>{currency}))?(?P<close>\))?")


def _amount(cell: str, layout: SourceLayout, line: int, column: int) -> str | None:
    """The canonical magnitude of the one amount a cell holds in full, as the figure file writes a figure; None for
    an empty cell or a label, which holds no digit. Any other cell with a digit refuses the file."""
    text = cell.strip(" ")
    if not text or _DIGIT.search(text) is None:
        return None
    match = _amount_pattern(layout.decimal_mark, layout.group_mark).fullmatch(text)
    if (match is None or (match["open"] is None) != (match["close"] is None) or match["open"] and match["sign"]
            or match["before"] and match["after"]):
        raise CellSource(line, column)
    digits = re.sub("[^0-9]", "", match["whole"])
    try:
        figure = normalize_numeric_token(digits + ("." + match["fraction"] if match["fraction"] else ""),
                                         max_digits=MAX_FIGURE_DIGITS)
    except AssistantError:  # more digits than the screen reads in a payload: listed, it would match nothing
        raise UnscreenableSource(line, column) from None
    return figure


def source_amounts(raw: bytes, layout: SourceLayout) -> list[tuple[int, int, str]]:
    """(line, column, canonical magnitude) of every amount in the file, in order, or refused whole (SourceRefused).

    Every cell outside the declared text columns is empty, a label or one of these amounts: the file has no digit
    that is not in one of them or in a text column.
    """
    if not layout_valid(layout):
        raise ValueError("a figure source's layout is not valid")
    text = _decode(raw)
    _check_characters(text, layout.delimiter)
    rows = _table(text, layout.delimiter)
    text_columns = _text_columns(layout, rows[0])
    amounts, read = [], {}
    for number, row in enumerate(rows, 1):
        for index, cell in enumerate(row):
            if index in text_columns:
                continue
            if cell in read:  # the same cell reads the same wherever it stands; a refused one never gets here
                figure = read[cell]
            else:
                if not cell.isascii() and any(not character.isascii() and character not in CURRENCY_SIGNS
                                              for character in cell):
                    raise HiddenMarkSource(number, index + 1)
                figure = read[cell] = _amount(cell, layout, number, index + 1)
            if figure is not None:
                amounts.append((number, index + 1, figure))
    return amounts


def _round_figure(whole: str, fraction: str, min_digits: int) -> bool:
    """A value the digit minimum leaves out though it is that large: at least min_digits digits before the point and
    at least ROUND_MIN_SIGNIFICANT significant digits, as 347300.00 under a minimum of 5. Zero never is, nor a value
    already a figure. Listed only when round figures are on."""
    magnitude = whole.lstrip("0")
    significant = (magnitude + fraction).strip("0")
    return (len(magnitude) >= min_digits and len(significant) >= ROUND_MIN_SIGNIFICANT
            and not _digit_forms(whole, fraction, min_digits))


def read_source(raw: bytes, layout: SourceLayout, min_digits: int,
                round_figures: bool = False) -> tuple[set[str], set[str], set[str]]:
    """(canonical values, digit forms, round figures) of one source, or refused whole (SourceRefused).

    Each amount `source_amounts` reads is a figure when it has a digit form of at least min_digits significant
    digits, as an entry of the figure file has; with round_figures, one the minimum leaves out though it is that
    large is a round figure (`_round_figure`). An amount of fewer digits is read, and listed as neither. More
    figures than one snapshot holds refuse the source.
    """
    values, forms, rounds = set(), set(), set()
    for _line, _column, figure in source_amounts(raw, layout):
        whole, _, fraction = figure.lstrip("-").partition(".")
        found = _digit_forms(whole, fraction, min_digits)
        if found:
            values.add(figure.lstrip("-"))
            forms.update(found)
        elif round_figures and _round_figure(whole, fraction, min_digits):
            rounds.add(figure.lstrip("-"))
        if len(values) > MAX_SOURCE_FIGURES or len(rounds) > MAX_SOURCE_FIGURES:
            raise ValueError("a source lists more figures than one snapshot holds")
    return values, forms, rounds
