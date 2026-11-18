"""Figure sources: delimited files, such as custody exports, whose amounts the confidential-figure screen lists.

A source is read with every delimiter, and as one cell per line, unless its layout is declared. A reading that cuts
an amount is ruled out; a source whose readings disagree, or that holds a number the payload screen can't read, is
refused. The numeric primitives it shares with the payload screen live in forbidden_tokens, which loads sources here.
"""

import bisect
from collections.abc import Iterator
from contextvars import ContextVar
import csv
import io
from itertools import chain
import re
import unicodedata

from .figure_source_marks import decode_source, leading_fractions, marked_amount, refuse_hidden_marks
from .forbidden_tokens import (_GROUPS_TRIED, MAX_FIGURE_DIGITS, MAX_SOURCE_FIGURES, _GAP_CLASS,
                               _LEADING_POINTS, _RUN, _digit_forms, _is_date, _plain_decimal, _readings)


# A cell is a figure when nothing but signs, currency signs, brackets, percent signs, asterisks, quotes, a
# spreadsheet's `=`, spaces and at most two words surround its one number, each word a currency code, a mark of one
# or two letters (`EUR CR`, `DR`, `S` or `H`), or Soll, Haben, Credit or Debit. A footnote reference after it, such
# as ` 1)` or `[2]`, is not part of it; one whose digits may be the number's last group, as ` 432)` in `(98 765 432)`,
# is read both ways (`_SPACED_NOTE`).
_CELL_EDGE = re.compile(r"[\s$\u00a2-\u00a5\u20a0-\u20c0%()+\-\u2212\"'*=]*"
                        r"(?:(?:[A-Z]{3}|[A-Za-z]{1,2}\.?|Soll|Haben|SOLL|HABEN|Credit|Debit)"
                        r"[\s$\u00a2-\u00a5\u20a0-\u20c0%()+\-\u2212\"'*=]*){0,2}")


_FOOTNOTE = re.compile(r"(?:\s+\d{1,3}\)|\s*\[\d{1,3}\])\s*\Z")
_SPACED_NOTE = re.compile(r"\d\s+\d{3}\)\s*\Z")
_EDGE_WORDS = frozenset({"Soll", "Haben", "SOLL", "HABEN", "Credit", "Debit"})


def _is_edge(text: str) -> bool:
    """Whether text may surround a cell's one number (`_CELL_EDGE`), each run of letters one word: `Rest` is not
    the two marks `Re` and `st`, so a note such as `Rest 98.765,43 offen` stays text."""
    return bool(_CELL_EDGE.fullmatch(text)) and all(len(word) <= 3 or word in _EDGE_WORDS
                                                    for word in re.findall(r"[A-Za-z]+", text))


def _held_decimal(whole: str, fraction: str, exponent: int) -> str | None:
    """The canonical decimal a source's number holds (as `_plain_decimal` writes it), or None when the payload screen
    reads it in no spelling: one has at most MAX_FIGURE_DIGITS digits written and an exponent within 128. So an
    exponent past 128 hides nothing that a spelling within it shows: `12,345,678.90e129` is 123456789e128."""
    if not (whole + fraction).strip("0"):
        return "0"  # zero, in any spelling
    point = len(whole) + exponent
    if not -MAX_FIGURE_DIGITS - 129 <= point <= len(whole) + len(fraction) + MAX_FIGURE_DIGITS + 129:
        return None  # far past any spelling the screen reads
    digits = whole + fraction
    if point <= 0:
        integer, fractional = "0", "0" * -point + digits
    else:
        padded = digits + "0" * (point - len(digits))
        integer, fractional = padded[:point], padded[point:]
    integer, fractional = integer.lstrip("0") or "0", fractional.rstrip("0")
    # The shortest spelling: the point moved by up to 128 places, over trailing zeros or into the fraction, and below
    # 1 written with a leading point and no whole digits, as the screen reads `.57`.
    if fractional:
        shift = min(len(fractional), 128)
        written = len((integer + fractional[:shift]).lstrip("0")) + len(fractional) - shift
    else:
        written = len(integer) - min(len(integer) - len(integer.rstrip("0")), 128)
    return integer + ("." + fractional if fractional else "") if written <= MAX_FIGURE_DIGITS else None


# The readings of each cell, kept for one `_source_figures` call only: its readings and their checks read the same
# cells and pieces many times. Nothing is kept after the call.
_CELL_MEMO: ContextVar[dict | None] = ContextVar("figure_source_cells", default=None)
_NO_NUMBERS = (frozenset(), frozenset(), frozenset())  # what a text cell with no figure holds, kept once


def _cell_readings(cell: str) -> list[tuple[str, str]]:
    """`_read_cell`, from the memo of the `_source_figures` call that is running, if any."""
    if (memo := _CELL_MEMO.get()) is None:
        return _read_cell(cell)
    if (found := memo.get(cell)) is None:
        found = memo[cell] = tuple(_read_cell(cell))
    return list(found)


def _read_cell(cell: str) -> list[tuple[str, str]]:
    """Every value a cell that holds exactly one number can have, as (whole, fraction) digits.

    Any notation the screen reads in a payload is read here: groups, either decimal mark, a
    leading point as in `.4821357`, and an exponent as in `1.23456789e6`, which is applied.
    """
    runs = list(_RUN.finditer(cell))
    if not runs or len(runs) > 64:
        return []
    lead = cell[:runs[0].start()]
    pointed = lead[-1:] in _LEADING_POINTS and bool(lead)  # `.57`: the point is part of the number.
    if not (_is_edge(lead[:-1] if pointed else lead) and _is_edge(cell[runs[-1].end():])):
        return []
    found = []
    for whole, fraction, exponent, first, last in _readings(cell):
        if first:
            break  # readings come in the order of their first run, and one that starts later can't take in the cell
        # The reading must take in the whole cell; behind a leading point it has no whole part.
        if exponent is None or last != len(runs) - 1 or (pointed and whole):
            continue
        number = _held_decimal(whole, fraction.rstrip("0"), exponent)
        if number is not None:
            found.append(tuple(number.partition(".")[::2]))
        # Past an exponent of 128 the screen reads such a payload's digits without it: list those as well.
        if abs(exponent) > 128 and (mantissa := _plain_decimal(whole, fraction.rstrip("0"), 0, MAX_FIGURE_DIGITS)):
            found.append(tuple(mantissa.partition(".")[::2]))
    return found


def _declared_reading(cell: str, decimal_mark: str) -> tuple[str, str] | None:
    """(whole, fraction) of a cell's one number read with a declared decimal mark, or None when it does not read so.

    The edges are those `_cell_readings` allows. A point just before the first digit, as in `.57`, starts the
    fraction, as the payload screen reads it; a leading comma is refused before this (`_leading_comma`).
    """
    runs = list(_RUN.finditer(cell))
    if not runs or len(runs) > 64:
        return None
    start, end = runs[0].start(), runs[-1].end()
    if start and cell[start - 1] == decimal_mark == ".":
        start -= 1
    if not (_is_edge(cell[:start]) and _is_edge(cell[end:])):
        return None
    core = "".join(str(unicodedata.decimal(c)) if c.isdecimal() else c for c in cell[start:end])
    match = _DECLARED_NUMBERS[decimal_mark].fullmatch(("0" if core[0] == decimal_mark else "") + core)
    if match is None:
        return None
    number = _plain_decimal(re.sub("[^0-9]", "", match["whole"]), match["fraction"] or "",
                            int(match["exponent"] or "0"), MAX_FIGURE_DIGITS)
    return None if number is None else tuple(number.partition(".")[::2])


_DELIMITERS = (",", ";", "\t", "|")


_DELIMITER_CHARACTERS = re.compile(r"[,;\t|]")
# Commas that group a number's digits in a text cell, as in `Balance USD 1,234,567.89 CR`, after a space or a start:
# not delimiters. One after a comma or a word, as in `SYN1,12,345.67`, may be a column break, so it is left alone.
# Where a number may start: after no word character, point, slash, colon or date dash, or right after a three-letter
# currency code written against it, as in `EUR29,737,610.16`. `SYN1,123,456.78` then reads both ways, which can only
# refuse more.
_CODE = r"(?<=[A-Z]{3})(?<![A-Za-z][A-Z]{3})"
_START = rf"(?:(?<![\w./:])(?<!\d-)|{_CODE})"
_GROUPING_COMMAS = re.compile(rf"(?:(?<![\w.,])|{_CODE})\d{{1,3}}(?:,\d{{3}})+(?!\d)")
_GROUP_HEAD, _GROUP_TAIL = re.compile(rf"{_START}\d{{1,3}}\Z"), re.compile(r"\d{3}(?!\d)")
_INDIAN_HEAD, _INDIAN_GROUP = re.compile(rf"{_START}\d{{1,2}}\Z"), re.compile(r"\d{2}")


def _record_width(row: list[str]) -> int:
    """A row's filled cells, counting as one an amount that unquoted comma groups cut into cells, as a footer line
    `Balance carried forward 60,927,718.98` cut into `...forward 60`, `927` and `718.98`, Indian groups as well, as
    `31`, `41` and `592.65` of `SYN-0001,31,41,592.65`."""
    filled = max((index + 1 for index, cell in enumerate(row) if cell.strip()), default=0)
    cells = row[:filled]
    # Whether a cell and those after it are groups of two digits that a group of three ends, as `41` and `592.65`.
    indian = [False] * (filled + 1)
    for index in range(filled - 2, -1, -1):
        indian[index] = bool(_INDIAN_GROUP.fullmatch(cells[index])) and (
            indian[index + 1] or bool(_GROUP_TAIL.match(cells[index + 1])))
    return filled - sum(1 for index in range(1, filled)
                        if _GROUP_HEAD.search(cells[index - 1]) and _GROUP_TAIL.match(cells[index])
                        or indian[index] and _INDIAN_HEAD.search(cells[index - 1]))


# A date in a common layout, alone in its cell, with an optional time: not a figure, and not a fragment either.
_DATE_CELL = re.compile(r"[\s\"']*(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})"
                        r"(?:[ T]\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?(?:\s?(?:Z|[+-]\d{2}:?\d{2}))?)?[\s\"']*")


# The column breaks a text cell must not hold beside a number under each reading: every delimiter but the reading's
# own, which a quoted cell may hold, and the comma, which also marks decimals. `Alice<tab>12,345.67` read with the
# comma leaves `Alice<tab>12`, whose piece `12` after the tab is a number: that reading did not split the line.
_BREAKS = {delimiter: re.compile("[" + re.escape("".join(sorted({";", "\t", "|"} - {delimiter}))) + "]")
           for delimiter in (*_DELIMITERS, None)}


class AmbiguousSource(ValueError):
    """A figure source that can be read in more than one way, and the readings would list different figures."""


class UnscreenableSource(ValueError):
    """A figure source that writes a number as the payload screen does not read it: a decimal comma with no digit
    before it, as in `,57891`."""


_CODE_BEFORE = re.compile(r"(?<![A-Za-z])[A-Z]{3}\Z")  # a currency code ends the edge, as `EUR` in `EUR,57891`
_INNER_COMMA = re.compile(r",(\d+)(?!\d|[,.]\d)")  # a fraction ends there: `USD,1,234,560.00` is a group


def _inner_leading_commas(cell: str, min_digits: int, after_words: bool = False) -> tuple[str, bool] | None:
    """A text cell's figures written with a decimal comma and no digit before it, as in `Total EUR,57891` or
    `Balance: ,57891`: the cell with each one blanked. None when it holds none; one too short to be a figure is left.

    The comma must follow the cell's start, a space, a colon, a bracket, a sign or currency sign, or a three-letter
    code; right after a digit, a point, a delimiter or another letter it is a column break or a group, as in
    `A,12345`. With a space before it, as in `Rate ,82317`, it belongs to the number. after_words counts one right
    after a letter too, as in `TotalEUR,57891 units`, where the comma can't be the reading's column break.
    """
    kept, last, figure = [], 0, None
    for match in _INNER_COMMA.finditer(cell):
        mark = cell[match.start() - 1:match.start()]
        if mark and not mark.isspace() and (mark.isdigit() or mark in ".,;\t|" or mark.isalpha() and not after_words
                                            and not _CODE_BEFORE.search(cell[:match.start()])):
            continue
        if not _digit_forms("0", match.group(1), min_digits):
            continue
        figure = True
        kept += [cell[last:match.start()], " "]
        last = match.end()
    return None if figure is None else ("".join(kept) + cell[last:], figure)


_OTHER_BREAKS = re.compile(r"[;\t|]")


def _may_be_leading_comma(before: str) -> bool:
    """Whether a comma after the text before it may be a decimal comma with no digit before it rather than a column
    break, as `_inner_leading_commas` reads one: after nothing, a space, a colon, a bracket, a sign or currency sign,
    or a three-letter code; never after a digit, a point, a delimiter or another letter."""
    mark = before[-1:]
    return not mark or mark.isspace() or not (mark.isdigit() or mark in ".,;\t|"
                                              or mark.isalpha() and not _CODE_BEFORE.search(before))


def _glued(cell: str, min_digits: int, split: bool = False) -> bool:
    """Whether a text cell holds a figure that a delimiter character glues on, as `Alice,12345` read with `;` does.
    Where the comma can't be the reading's column break (split), only the other delimiters glue: `Rate9,57891` is
    9.57891 there, not 57891 glued on."""
    unglued = _GROUPING_COMMAS.sub(lambda match: match.group().replace(",", ""), cell)
    return any(_digit_forms(*reading, min_digits) for piece in (_OTHER_BREAKS if split else _DELIMITER_CHARACTERS)
               .split(unglued) for reading in _cell_readings(piece))


def _leading_comma(cell: str, min_digits: int) -> bool | None:
    """None when a cell is not one number written with a decimal comma and no digit before it, as `,57891` or
    `EUR -,5`; otherwise whether that number is a figure.

    The payload screen reads a leading point and never a leading comma, so such a figure can't be listed: listed as
    0.57891, the spelling `,57891` would pass the screen. One with too few digits to be a figure is harmless. A comma
    right after a letter, as in `A,12345`, is a column break, not a decimal mark; after a currency code, as in
    `EUR,57891`, it may be either, so the number counts.
    """
    lead = _CELL_EDGE.match(cell).end()
    if (cell[lead:lead + 1] != "," or not cell[lead + 1:lead + 2].isdigit()
            or cell[lead - 1:lead].isalpha() and not _CODE_BEFORE.search(cell[:lead])):
        return None
    readings = _cell_readings(cell[:lead] + "0" + cell[lead:])
    return any(_digit_forms(*reading, min_digits) for reading in readings) if readings else None


# Amounts a comma file cut into cells because it did not quote them: comma groups, as `1,234,567.89`, or a decimal
# comma with up to four decimals, as `123,45` or `24352173,47 EUR`, its whole part grouped by points or spaces or not.
# A comma, a space or a line start may come before one, never a letter, a digit or a point,
# so neighbouring numeric columns such as `20261110,00012345`, or a date and a number either side of a comma, are not
# fused. Each shape is its own pass,
# and decimal commas may overlap, so neither `02,1` in `2026-01-02,1,234,567.89` nor `215,858` in `215,858,2616`
# hides an amount. An exponent is part of the amount, with all its digits, and an amount never ends right before
# one: `1,234,567.89e0002` is 123456789, never 1234567.89. A group gap is never a line break.
_EXPONENT = r"(?:[eE][+-]?\d+)?(?![eE][+-]?\d)"
_STARTS = (r"(?<![\w./:])(?<!\d-)", _CODE)
# An amount in comma groups, which an unquoted comma file cuts into cells.
_GROUPED_CUTS = tuple(re.compile(rf"{start}\d{{1,3}}(?:,\d{{3}})+(?:\.\d+)?{_EXPONENT}(?!\d)") for start in _STARTS)
# The cut cells' own pass (`_cut_cell_figures`) also starts one after a letter, an underscore after one, a colon, a
# slash or a date's dash, which may end a mark, a label or a code, as in `x12,345,678.90`, `EUR_12,345,678.90` or
# `Rate:12,345,678.90`: listing more can only refuse more. Never after a digit, or an underscore after one, inside a
# number, nor after a point, on a fraction's digits: `1.5,345,678.90` holds 1.5 and 345,678.90, and no 5,345. Indian
# groups, as in `12,34,567.89`, are cut the same way: at most six groups of two before the last group of three, since
# an amount of seven commas or more refuses the source (`_MAX_RUN_PIECES`) and a longer row still holds such a piece.
# The bound keeps the pattern from walking a long row of groups of two from every start, as in `12,12,12,...`.
_CELL_START = r"(?<![\d.])(?<!\d_)"
_CELL_CUTS = (re.compile(rf"{_CELL_START}\d{{1,3}}(?:,\d{{3}})+(?:\.\d+)?{_EXPONENT}(?!\d)"),
              re.compile(rf"{_CELL_START}\d{{1,2}}(?:,\d{{2}}){{1,6}},\d{{3}}(?:\.\d+)?{_EXPONENT}(?!\d)"))
# A decimal-comma amount a comma cut (`_decimal_comma_cuts`): a whole part of groups of three joined by one point,
# apostrophe or space, or one run of digits, then a decimal comma and up to four decimals, never running into a
# following number, date or time.
_DECIMAL_TAIL = re.compile(rf",\d{{1,4}}{_EXPONENT}(?![\d.]|[-/:]\d)")
# The same, its decimals perhaps joined by underscores, as the screen reads `1234,5_6`.
_JOINED_TAIL = re.compile(rf",\d(?:_?\d){{0,3}}{_EXPONENT}(?![\d.]|_\d|[-/:]\d)")
_DIGIT_RUNS = re.compile(r"\d+")
_GROUP_GAP = re.compile(r"[.']|[^\S\r\n]")
_MAY_START = re.compile("|".join(_STARTS))


# The most cells a cut amount may span, 21 digits before the point and past any amount. Every shorter run of a cut
# amount's cells is listed, at most 20 runs; a longer cut amount refuses the source, so no run is ever left out.
_MAX_RUN_PIECES = 7


def _cut_runs(amount: str) -> list[str]:
    """Each shorter amount that the cells an unquoted comma cut `amount` into may hold, as a plain number: under
    `Account,Quantity,Cost`, `SYN-1,12,345,678.90` holds 12 and 345,678.90, or 12,345 and 678.90, as well as the one
    amount read whole. Every run of two or more neighbouring pieces but the whole."""
    pieces = amount.split(",")
    return ["".join(pieces[first:last]) for first in range(len(pieces)) for last in range(first + 2, len(pieces) + 1)
            if last - first < len(pieces)]


def _run_readings(run: str) -> list[tuple[str, str]]:
    """`_cell_readings` of one cut-cell run: a run of whole pieces is plain digits, read without the cell machinery,
    which a dense file would otherwise call millions of times; one ending in the amount's fraction or exponent is read
    in full."""
    return [(run.lstrip("0") or "0", "")] if run.isdigit() and run.isascii() else _cell_readings(run)


def _decimal_comma_cuts(text: str, extra: bool = False, quoted: list[tuple[int, int]] | None = None) -> Iterator[str]:
    """Each decimal-comma amount a comma cut, from every place a number may start (`_STARTS`) and after each point
    that groups its digits: `1 234,56` and its 234,56, and `1.234,56` and its 234,56, as the screen reads them in a
    payload. With extra, instead the ones that shape leaves out and the
    screen still reads: a first digit glued to a letter, as in `x1234567,89` or `EUR_1234567,89`, a whole part of runs
    joined by underscores, as in `1_234,56`, or decimals joined by them, as in `1234,5_6`. A row's first start is
    read whole, and a later one up to `_LATER_GROUPS` groups, as far as the screen reads from such a start; a later
    start with more groups raises, so the source is refused, never read in part. Each decimal comma's groups are
    walked back once, so a row costs one pass, not one per group; the longest amount comes first. With quoted, the
    comma reading's quoted fields (`_quoted_spans`), a decimal comma inside one is passed over: the field is one
    cell, read whole, which no comma cut."""

    def strict(at: int) -> bool:
        return bool(_MAY_START.match(text, at))

    def glued(at: int) -> bool:
        mark = text[at - 1:at]
        return not strict(at) and (mark.isalpha() or mark == "_" and text[at - 2:at - 1].isalpha())

    def may_start(at: int) -> bool:
        return strict(at) or extra and glued(at)

    runs = [(match.start(), match.end()) for match in _DIGIT_RUNS.finditer(text)]
    opens = [first for first, _last in quoted or ()]
    for last, (start, end) in enumerate(runs):
        if text[end:end + 1] != "," or (tail := (_JOINED_TAIL if extra else _DECIMAL_TAIL).match(text, end)) is None:
            continue
        if (index := bisect.bisect_right(opens, end) - 1) >= 0 and end < quoted[index][1]:
            continue  # a decimal comma inside a quoted field: one cell, which no comma cut
        joined = "_" in tail.group()
        starts = [(start, 1)] if may_start(start) else []  # the whole part one run of digits
        back, groups = last, 1
        while end - start == 3 and back > 0:  # a group of three: the run before it may start the amount
            before, gap = runs[back - 1]
            if gap + 1 != start or gap - before > 3 or not _GROUP_GAP.fullmatch(text, gap, start):
                break
            if text[gap] == "." and not may_start(start):
                starts.append((start, groups))  # after a point that groups the row: no `_STARTS` start, but a later one
            back, start, end, groups = back - 1, before, gap, groups + 1
            if may_start(start):
                starts.append((start, groups))
        if not extra and any(groups > _LATER_GROUPS for _first, groups in starts[:-1]):
            raise ValueError("an amount inside a row of groups past what is read from a later start")
        kept = [first for first, groups in starts if groups <= _LATER_GROUPS]
        if starts and starts[-1][1] > _LATER_GROUPS:
            kept.append(starts[-1][0])  # the row's first start, read whole
        if extra:  # only what the plain shape leaves out
            kept = [first for first in kept if joined or glued(first)]
            back = last  # a whole part of runs joined by underscores, read from its first run
            while back and runs[back - 1][1] + 1 == runs[back][0] and text[runs[back - 1][1]] == "_":
                back -= 1
            if back < last and may_start(runs[back][0]):
                kept.append(runs[back][0])
        yield from (text[first:tail.end()] for first in reversed(kept))


# A later start inside a row of groups is read up to the groups the screen reads from one: its own and
# `_GROUPS_TRIED` more, 27 digits.
_LATER_GROUPS = _GROUPS_TRIED + 1


def _quoted_spans(text: str) -> list[tuple[int, int]]:
    """The spans of text inside quoted fields of a comma reading, in order, as Python's csv module reads them by
    default: a `"` that opens a field quotes it, `""` inside is one quote, and an unclosed field runs to the end. A
    quote anywhere else is a character of its field. An amount inside one, as `"USD 6,729,102.50"`, is in one cell."""
    spans, index, opens = [], 0, True
    while index < len(text):
        if opens and text[index] == '"':
            close = index + 1
            while (close := text.find('"', close)) != -1 and text[close + 1:close + 2] == '"':
                close += 2
            end = len(text) if close == -1 else close
            spans.append((index + 1, end))
            index, opens = end + 1, False
            continue
        opens = text[index] in ",\r\n"
        index += 1
    return spans


def _within_limit(values: set, rounds: set) -> None:
    """Raise as soon as a reading lists more figures, or more round figures, than one snapshot holds
    (MAX_SOURCE_FIGURES): the source is then refused, and a large file's read stays short and small. A reading that
    a later cell would have ruled out is refused with it, which can only refuse more. Round figures are kept, and so
    counted, only where the setting lists them."""
    if len(values) > MAX_SOURCE_FIGURES or len(rounds) > MAX_SOURCE_FIGURES:
        raise ValueError("a reading of the source lists more figures than one snapshot holds")


# A cell of one run of eight digits and nothing that marks an amount: the one spelling that may be a date.
_BARE_CELL = re.compile(r"[\s\"'=]*\d{8}[\s\"']*")


def _classify(readings, min_digits: int, values: set, forms: set, rounds: set | None, bare: bool = False) -> None:
    """Add each (whole, fraction) reading that is a figure to values and its digit forms to forms, and one that is a
    round figure to rounds, unless rounds is None, as where round figures are not listed; a number of too few digits
    is neither, nor is a date where bare: eight digits that name a day, written as one run with no group, decimals,
    exponent, sign, bracket, currency or code. `20,170,520.00` and `USD 20170520` are figures."""
    for whole, fraction in readings:
        found = _digit_forms(whole, fraction, min_digits)
        if found and not (bare and not fraction and _is_date(whole.lstrip("0"))):
            values.add(whole + ("." + fraction if fraction else ""))
            forms.update(found)
        elif rounds is not None and _round_figure(whole, fraction, min_digits, bare):
            rounds.add(whole + ("." + fraction if fraction else ""))


_TRAILING_EXPONENT = re.compile(r"[eE][+-]?\d+\Z")


def _cut_cell_figures(text: str, min_digits: int, quoted: list[tuple[int, int]] | None = None, *,
                      round_figures: bool) -> tuple[set[str], set[str], set[str]]:
    """(values, digit forms, round figures) of every amount the cells of each unquoted comma cut may hold: the amount
    whole and every shorter run (`_CELL_CUTS`). They are listed whichever reading the source is read by: a cell
    elsewhere that rules the comma reading out, a layout declared with another delimiter, or a longer number another
    reading finds around the amount, as `5,345,678.90` in `1.5,345,678.90`, never hides them. Raises when an amount is
    cut into more cells than are read, so the source is refused, never read in part. When the amount does not read
    whole, as with an exponent past the bounds (`12,345,678.90e200`), the runs of its mantissa and the mantissa are
    listed as well, as the screen reads such a payload. Round figures are found only with round_figures."""
    values, forms, rounds = set(), set(), set()
    kept = rounds if round_figures else None
    quoted = _quoted_spans(text) if quoted is None else quoted  # the comma reading's quoted fields, if not given
    starts = [first for first, _last in quoted]
    # Each amount from every start, and each from the plain start as well (`_GROUPED_CUTS`): one that a wider start
    # makes the end of a longer cut, as `342,678` in `EUR_12,342,678`, is still read whole, as 342.678 too.
    for match in (match for pattern in (*_CELL_CUTS, *_GROUPED_CUTS) for match in pattern.finditer(text)):
        amount, start = match.group(), match.start()
        if (index := bisect.bisect_right(starts, start) - 1) >= 0 and start < quoted[index][1]:
            continue  # inside a quoted field: one cell, which no comma cut
        if amount.count(",") >= _MAX_RUN_PIECES:
            raise ValueError("an amount cut into more cells than are read")
        whole, runs = _cell_readings(amount), _cut_runs(amount)
        if not whole:
            runs += [*_cut_runs(mantissa := _TRAILING_EXPONENT.sub("", amount)), mantissa]
        _classify([*whole, *(reading for run in runs for reading in _run_readings(run))], min_digits, values, forms,
                  kept)
        _within_limit(values, rounds)
    return values, forms, rounds


def _inner_numbers(text: str, min_digits: int, *, round_figures: bool,
                   first: bool = False) -> tuple[set[str], set[str], set[str]]:
    """(values, digit forms, round figures) of every figure read anywhere in a text, as the payload screen reads a
    payload: every span, in each way it reads.

    A text cell may hold a figure, as a total written `Total USD 87654.32` does, and listing more can only refuse more.
    A number inside a longer reading is listed too, since a reader may take the text either way: `Lots 25 157 435.77`
    may be 25 lots at 157,435.77, `Note 1 345 678.90` note 1 and 345,678.90, and `Lot 1.5 345 678.90` holds
    345,678.90 though its digits also read as 5,345,678.90. A span that reads as no number within the limits, as
    `1,234,567.89e200`, hides nothing: what it holds is listed, as the screen reads it. Round figures are found only
    with round_figures. With first, the reading stops at its first figure or round figure, counted against no limit.
    """
    values, forms, rounds, seen, runs = set(), set(), set(), set(), None
    kept = rounds if round_figures else None
    for whole, fraction, exponent, start_run, end_run in _readings(text):
        if (number := _held_decimal(whole, fraction.rstrip("0"), exponent)) is None:
            continue
        bare = False
        if start_run == end_run and not fraction and not exponent and len(whole) == 8:  # one run, as a date writes it
            runs = runs or [match.span() for match in _RUN.finditer(text)]
            start, end = runs[start_run]
            bare = end - start == 8 and not marked_amount(text, start, end)  # `EUR-20170520` is an amount
        if (reading := tuple(number.partition(".")[::2])) + (bare,) not in seen:
            seen.add(reading + (bare,))
            _classify([reading], min_digits, values, forms, kept, bare)
            if first and (values or rounds):
                break
            _within_limit(values, rounds)
    return values, forms, rounds


DECIMAL_MARKS = (".", ",")

# Which rules decide what a figure source lists. It is raised with every change to that, and it is part of the
# identity of a configuration, and of the bytes of a gate policy, that lists sources: the same settings can then never
# mean another list. 1 is every release before it. 26 reads a source every way, with every amount the cut cells of a
# comma file may hold, whichever reading is the file's, and every number a text cell holds, up to the digits the
# screen reads, Indian groups included, and refuses what the screen can't read, an amount cut into more cells than
# are read, a reading of more figures than one snapshot holds, and a mark, a look-alike of one or a byte of another
# encoding inside a figure that a reading would list in part (`figure_source_marks`). 2 to 25 are of builds before any
# release: they are refused like 1, and no setting brings them back.
SOURCE_RULE = 26
# 27 lists round figures too, when forbidden_token_round_figures is "list", and refuses a reading of more of them than
# one snapshot holds: 26 neither lists nor counts them. The rule follows the setting; no setting chooses an older
# reading.
ROUND_RULE = 27
ROUND_LIST = "list"
ROUND_OPTIONS = ("skip", ROUND_LIST)
ROUND_MIN_SIGNIFICANT = 4  # fixed: rounder values are constants in ordinary code


def source_rule(round_figures: str) -> int:
    """The source rule a setting reads sources by: 27 when round figures are listed, else 26."""
    return ROUND_RULE if round_figures == ROUND_LIST else SOURCE_RULE


def _round_figure(whole: str, fraction: str, min_digits: int, bare: bool = False) -> bool:
    """A value the digit minimum leaves out though it is that large: at least min_digits digits before the point and
    at least ROUND_MIN_SIGNIFICANT significant digits, as 347300.00 under a minimum of 5. Zero never is, nor a date
    where bare (`_classify`), nor a value already a figure. Listed only when round figures are on."""
    magnitude = whole.lstrip("0")
    significant = (magnitude + fraction).strip("0")
    return (len(magnitude) >= min_digits and len(significant) >= ROUND_MIN_SIGNIFICANT
            and not _digit_forms(whole, fraction, min_digits) and not (bare and not fraction and _is_date(magnitude)))



def _header_width(rows: list[list[str]]) -> int:
    """The widest row of more than one cell with no digit, the header, or 0 when there is none."""
    return max((len(row) for row in rows if len(row) > 1 and not any(map(str.isdigit, "".join(row)))), default=0)


def _leading_header_width(rows: list[list[str]]) -> int:
    """The widest row of more than one cell before the first row with a digit, or 0: a header above the data, never
    a note after it."""
    width = 0
    for row in rows:
        if any(map(str.isdigit, "".join(row))):
            break
        width = max(width, len(row) if len(row) > 1 else 0)
    return width


def _interpretation(text: str, delimiter: str | None, min_digits: int, decimal_mark: str | None = None,
                    cut: tuple[set, set, set] | None = None, inner: dict | None = None,
                    quoted: list[tuple[int, int]] | None = None, whether: bool = False, *,
                    round_figures: bool) -> tuple[frozenset, frozenset, bool, frozenset] | None:
    """(values, digit forms, unscreenable, round figures) of the whole text read with one delimiter (None: each line
    is one cell), or None when that reading leaves a fragment.

    Every cell must be a number, a date, empty, or text with no figure in it next to a delimiter character. A cell
    with digits that reads as no one number is what a wrong split leaves of an amount (`67;98.765` from
    `12.345,67;98.765,43` split on the comma), so the reading is not the file's. A text cell's own figures
    (`_inner_numbers`, kept in inner by cell when given, since readings share cells), and in a comma reading the
    amounts a comma cut into cells (`_GROUPED_CUTS`, `_decimal_comma_cuts`), with every amount those cells may hold
    (`_cut_cell_figures`, given as cut or found here), are listed too; one cut into more than `_MAX_RUN_PIECES` cells
    refuses the source. With a declared decimal_mark, a
    number is read with that mark only (`_declared_reading`), and one that does not read so means the layout is not
    the file's either. The third item says whether a cell holds a number with a leading decimal comma
    (`_leading_comma`, `_inner_leading_commas`): the reading is still compared with the others, so a wrong split can't
    win by default. With whether, one cell per line, only whether the reading holds a figure or a round figure counts,
    as for the one-column check of `_read_source`, which lists nothing: it stops at the first, reads each text cell
    only to its first, and is never refused for how many it holds. Round figures are found only with round_figures;
    inner holds what `_inner_numbers` found under the same setting.
    """
    rows = ([[line] for line in text.splitlines()] if delimiter is None
            else list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)))
    # Complete records: a row with more filled cells than the widest row without a digit, the header, holds this
    # reading's delimiter unquoted inside a cell, as `SYN1,USD,1,234,567.89` under `Account,CCY,Amount` does.
    header = _header_width(rows)
    if header and any(_record_width(row) > header for row in rows):
        return None
    values, forms, unscreenable, rounds = set(), set(), False, set()
    inner = {} if inner is None else inner
    taken, amounts = set(), set()  # cells and cut amounts already listed: each reads the same wherever it stands

    def bound() -> None:  # the limit on what a reading lists, or with whether one figure and one round figure kept
        if not whether:
            _within_limit(values, rounds)
            return
        forms.clear()
        for kept in (values, rounds):
            while len(kept) > 1:
                kept.pop()

    def take(readings: list[tuple[str, str]], bare: bool = False) -> None:  # a figure, a round figure or neither
        if not (whether and (values or rounds)):  # with whether, the first settles what counts
            _classify(readings, min_digits, values, forms, rounds if round_figures else None, bare)

    def take_text(cell: str) -> None:  # every figure the screen reads in the cell, once whichever readings share it
        if whether and (values or rounds):
            return
        if whether:  # whether it holds a number: read to the first, kept nowhere and counted against nothing
            found = _inner_numbers(cell, min_digits, round_figures=round_figures, first=True)
        elif (found := inner.get(cell)) is None:
            found = _inner_numbers(cell, min_digits, round_figures=round_figures)
            found = inner[cell] = found if any(found) else _NO_NUMBERS
        values.update(found[0])
        forms.update(found[1])
        rounds.update(found[2])

    for row in rows:
        previous = ""
        # A comma right after a word may be a decimal comma, not a column break, where this reading splits the
        # file's lines on another mark or only quotes can put a comma in a cell, unless a declared decimal mark is
        # the point; and in one column declared with decimal commas.
        split = decimal_mark != "." and (delimiter is None and decimal_mark == "," or delimiter is not None and (
            delimiter == "," or len(row) > 1 or header > 1))
        for cell in row:
            # In a comma reading read every way, a number right after a comma that may be a decimal one may begin
            # with that comma's fraction: `Lot ,5 345 678.90` may be 0,5 and 345,678.90, so what a text cell would
            # hold is listed too.
            after_leading = (delimiter == "," and decimal_mark is None and cell[:1].isdigit() and bool(previous)
                             and _may_be_leading_comma(previous))
            previous = cell or " "  # an empty cell ends in no mark: the next comma may follow nothing
            if (stripped := _FOOTNOTE.sub("", cell)) != cell and _SPACED_NOTE.search(cell):
                # `(98 765 432)`: its last group reads as a footnote ` 432)`, so the cell is listed whole as well
                read = None if decimal_mark is None else _declared_reading(cell, decimal_mark)
                if full := [read] if read else _cell_readings(cell):
                    take(full)
                elif any(map(str.isalpha, cell)):
                    take_text(cell)
            cell = stripped
            leading = _leading_comma(cell, min_digits)
            if leading is not None:
                unscreenable |= leading  # read on: if this reading is not ruled out, a figure here refuses the source
                continue
            readings = _cell_readings(cell)
            if decimal_mark is not None and not _DATE_CELL.fullmatch(cell):
                declared = _declared_reading(cell, decimal_mark)
                if declared is not None:
                    readings = [declared]
                elif readings:
                    return None  # a number the declared mark does not read: the layout is not the file's
            if not readings:
                if not any(character.isdigit() for character in cell) or _DATE_CELL.fullmatch(cell):
                    continue
                if not any(character.isalpha() for character in cell):
                    return None  # digits that read as no one number: a fragment
                # `Total EUR,57891`, and where the comma can't be this reading's column break `TotalEUR,57891 units`:
                # a figure the screen can't read refuses the source. Read as 57891, or ruled out as glued so that a
                # comma reading lists 57891 alone, it would let 0.57891 through.
                # Wherever decimal commas are declared, one after a word is a leading decimal comma, in rows of one
                # cell too: `Cash dividend,57891 units` declared with `;` is refused as unscreenable.
                if (masked := _inner_leading_commas(cell, min_digits, split or decimal_mark == ",")) is not None:
                    cell, figure = masked
                    unscreenable |= figure
                if _glued(cell, min_digits, split):
                    return None  # text with a figure glued on by a delimiter: lines that were not split
                if len(pieces := _BREAKS[delimiter].split(cell)) > 1 and any(map(_cell_readings, pieces)):
                    return None  # a column break beside a number inside a cell: this reading did not split the line
                take_text(cell)  # listed, not skipped
                continue
            if cell not in taken:
                taken.add(cell)
                take(readings, bool(_BARE_CELL.fullmatch(cell)))
            if after_leading:
                take_text(cell)
        bound()
    if delimiter == ",":  # read as written, so a quoted cell is never fused with its neighbour
        quoted = _quoted_spans(text) if quoted is None else quoted
        for amount in chain((match.group() for pattern in _GROUPED_CUTS for match in pattern.finditer(text)),
                            _decimal_comma_cuts(text, quoted=quoted)):
            if amount in amounts:
                continue
            amounts.add(amount)
            if not (readings := _cell_readings(amount)):
                return None  # an amount cut into cells that does not read whole: this reading leaves a fragment
            take(readings)
            bound()
        # `x1234567,89`: listed when it reads, ruling nothing out
        for amount in _decimal_comma_cuts(text, extra=True, quoted=quoted):
            if amount not in amounts:
                amounts.add(amount)
                take(_cell_readings(amount))
                bound()
        cut_values, cut_forms, cut_rounds = (cut if cut is not None
                                             else _cut_cell_figures(text, min_digits, quoted, round_figures=round_figures))
        values |= cut_values
        forms |= cut_forms
        rounds |= cut_rounds
    return frozenset(values), frozenset(forms), unscreenable, frozenset(rounds)


def _source_figures(raw: bytes, min_digits: int, layout: tuple[str, str] | None = None,
                    round_figures: bool = False) -> tuple[set[str], set[str], set[str]]:
    """`_read_source`, with the cells' readings kept for this call (`_CELL_MEMO`)."""
    token = _CELL_MEMO.set({})
    try:
        return _read_source(raw, min_digits, layout, round_figures)
    finally:
        _CELL_MEMO.reset(token)


def _read_source(raw: bytes, min_digits: int, layout: tuple[str, str] | None,
                 round_figures: bool) -> tuple[set[str], set[str], set[str]]:
    """(canonical values, digit forms, round figures) of every cell of one delimited text that holds a figure. Round
    figures are found only with round_figures, and then the readings must agree on them too; without it they are
    neither listed nor compared.

    The whole text is read with each delimiter, and as one cell per line; a reading that leaves a fragment is not the
    file's (`_interpretation`). When the readings left agree, their figures are listed. When none is left the source
    is not read; when they disagree, as with one column of `12.345,67` (one cell of 12345.67, or two cells of 12.345
    and 67), the source is refused as ambiguous rather than listed in a way that may miss its amounts. When a reading
    left holds a number written with a leading decimal comma, the source is refused as unscreenable, whatever the
    others say. So it is when the file reads whole as one column with decimal commas, holds such a fraction glued to
    a word and a figure or a round figure, as `Cash dividend,57891 units` under `0,12345` or `347300,00` under either
    setting, and no header above the data makes those commas column breaks: a comma reading would list 57891 there,
    not 0.57891. A declared layout,
    (delimiter, decimal mark), is the one reading tried. A cell with fewer significant digits than min_digits, or eight
    bare digits that name a day (`_classify`), is not a figure.
    """
    text = decode_source(raw)  # UTF-8, UTF-16 or UTF-32 with its mark, or a plain Windows export; else refused
    refuse_hidden_marks(text, layout)  # a mark inside a figure, which a reading would list in part (rules 26, 27)
    ways = [layout] if layout is not None else [(delimiter, None) for delimiter in (*_DELIMITERS, None)]
    # A line longer than a csv field may be, without one of the delimiters a reading splits on, is one field too long
    # for that reading, which refuses the source: refused here before any cell is read, as `1,1,1,...` on one line.
    limit, delimiters = csv.field_size_limit(), [delimiter for delimiter, _mark in ways if delimiter is not None]
    if any(len(line) > limit and not all(delimiter in line for delimiter in delimiters) for line in text.splitlines()):
        raise ValueError("a line of the source is longer than a csv field may be")
    quoted = _quoted_spans(text)  # the comma reading's quoted fields, found once
    # Before any reading, so a long cut refuses whichever is read. Round figures are kept only where they are listed,
    # so under skip they are never counted against the limit.
    cut = _cut_cell_figures(text, min_digits, quoted, round_figures=round_figures)
    for fraction in leading_fractions(text):  # `USD\u00b757891`: also 0.57891, whichever reading is the file's
        found = _inner_numbers(fraction, min_digits, round_figures=round_figures)
        cut = (cut[0] | found[0], cut[1] | found[1], cut[2] | found[2])
        _within_limit(cut[0], cut[2])
    inner = {}  # a text cell's figures, read once whichever readings share the cell
    found = {(delimiter, mark): _interpretation(text, delimiter, min_digits, mark, cut, inner, quoted,
                                                round_figures=round_figures)
             for delimiter, mark in ways}
    readings = {reading for reading in found.values() if reading is not None}  # no round figures under skip
    if layout is None:
        # One column, read with decimal commas: only whether it holds a figure or a round figure, either of which shows
        # a number beside the leading decimal comma under either setting, and a leading decimal comma, counts.
        column = _interpretation(text, None, min_digits, ",", whether=True, round_figures=True)
        if (column is not None and (column[0] or column[3]) and column[2]
                and not _leading_header_width(list(csv.reader(io.StringIO(text, newline=""), delimiter=",")))):
            raise UnscreenableSource
    if not readings:
        raise ValueError("no reading of the source leaves every cell whole")
    if any(reading[2] for reading in readings):
        raise UnscreenableSource
    if len(readings) > 1:
        raise AmbiguousSource
    reading = next(iter(readings))
    # The cut cells' shorter amounts, whichever reading is the file's: the comma reading lists them already, and a
    # reading that ruled it out by a cell elsewhere, or a declared other delimiter, must not drop them.
    return set(reading[0]) | cut[0], set(reading[1]) | cut[1], set(reading[3]) | cut[2]


def _declared_number(decimal_mark: str) -> re.Pattern:
    """A cell's number under a declared decimal mark: the other mark, a space or an apostrophe may group the whole
    part in threes, one kind throughout, and only the declared mark starts a fraction."""
    other = "," if decimal_mark == "." else "."
    groups = re.escape("".join(character for character, role in _GAP_CLASS.items() if role in (" ", "'", other)))
    return re.compile(rf"(?P<whole>[0-9]{{1,3}}(?P<group>[{groups}])[0-9]{{3}}(?:(?P=group)[0-9]{{3}})*|[0-9]+)"
                      rf"(?:{re.escape(decimal_mark)}(?P<fraction>[0-9]+))?(?:[eE](?P<exponent>[+-]?0*[0-9]{{1,3}}))?")


_DECLARED_NUMBERS = {mark: _declared_number(mark) for mark in DECIMAL_MARKS}
