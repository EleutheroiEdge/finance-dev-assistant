"""Marks that hide a figure in a figure source: refused before the source is read (source rules 26 and 27).

A figure written with an invisible mark between its digits, such as a zero-width space, a bidirectional control, a
variation selector or tag character, a soft hyphen, a control character or a space that groups no digits, shows as
one number but reads as two, so it would be listed in part: `98<ZWSP>765.43` as 765.43 alone. A line break or a tab
inside a quoted field between the parts of a figure, as `"Total 1,234,<LF>567.89"`, does the same. Such a source is
refused with a reason of its own. Between two digits, any run, however long, of such marks, grouping spaces and
decimal or grouping marks that holds at least one mark refuses it. A space that groups digits, as the screen reads
one (`_GAP_CLASS`: the space, the no-break, figure, thin and narrow no-break spaces), and the apostrophes are not
marks: `1 234 567,89` is still read whole. Declared with a delimiter other than a tab, or as one column, a tab is a
character of its cell, so one between two digits hides part of a figure as it does inside quotes. A text that is
UTF-16 read without its byte-order mark is refused as well.

A visible look-alike of a grouping or decimal mark that no reading takes for one, as a middle dot, a low quote, an
ideographic or Arabic comma, a prime, an accent or a modifier letter, is such a mark too, wherever a hidden one would
be (`_look_alike`): `EUR 98\u00b7765.43` would be listed as 765.43. So is a currency sign, bracket or percent sign with
no letter, space or delimiter beside it, as in `EUR 98765\u20ac.43`, and a dash or minus sign as an exponent's sign, as
in `1.2345e\u22126`. So does a number that writes two marks of one class, which the readings take for one mark, as the
Arabic thousands separator beside the point in `98\u066c765.43`. Such a source is refused as hiding a mark too. One
right before a number's digits, as in `USD\u00b757891`, may be its decimal point: the reader lists the fraction as well
(`leading_fractions`); beside another mark there, as in `Total \u00b7<ZWSP>57891` or `Total\u00b7\u20ac57891`, the
source is refused instead. A source that is neither UTF-8 nor plain Windows-1252 text is refused before it is read
(`decode_source`): read as Windows-1252, its UTF-8 grouping spaces and digits would turn into letters.
"""

import codecs
import re
import unicodedata

from .forbidden_tokens import _GAP_CLASS


class HiddenMarkSource(ValueError):
    """A figure source that writes a figure with a mark inside it that hides part of it from a reading."""


class EncodingSource(ValueError):
    """A figure source that is neither UTF-8 nor plain Windows-1252 text: one that mixes characters written as UTF-8
    with bytes that are not UTF-8, or holds a byte Windows-1252 does not define; or one marked UTF-16 or UTF-32 that
    does not decode whole."""


# A character written as UTF-8 in more than one byte; the bytes Windows-1252 does not define.
_UTF8_SEQUENCE = re.compile(rb"[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee\xef][\x80-\xbf]{2}"
                            rb"|\xed[\x80-\x9f][\x80-\xbf]|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}"
                            rb"|\xf4[\x80-\x8f][\x80-\xbf]{2}")
_UNDEFINED = re.compile(rb"[\x81\x8d\x8f\x90\x9d]")


def decode_source(raw: bytes) -> str:
    """The text of a figure source: UTF-32 or UTF-16 after its byte-order mark, a spreadsheet's "Unicode text";
    otherwise UTF-8, a UTF-8 byte-order mark left out; otherwise Windows-1252, a Windows export, only when no
    character is written as UTF-8 writes one and no byte is one that code page leaves undefined. Raises EncodingSource
    for any other text, and for a file marked UTF-16 or UTF-32 that does not decode whole, as one cut short, shifted
    by a byte or holding a lone surrogate: read as far as it goes, it would list its figures in part."""
    try:
        if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
            return raw.decode("utf-32")
        if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            return raw.decode("utf-16")
    except UnicodeDecodeError:
        raise EncodingSource from None
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        if _UTF8_SEQUENCE.search(raw) or _UNDEFINED.search(raw):
            raise EncodingSource from None
        return raw.decode("cp1252")


class MalformedQuotesSource(ValueError):
    """A figure source whose quoting a reading can't parse strictly: a quote left open at the end, or anything but
    that reading's own delimiter, a line end or the end of the text after a closing quote, another reading's delimiter
    included. A lenient reading runs such a field on past its quote, so it would read it in part."""


# Letters that show as nothing (Hangul and Braille fillers), and the replacement character, which stands for what
# could not be read; every other mark is found by its Unicode category.
_FILLERS = frozenset("\u115f\u1160\u3164\uffa0\u2800\ufffd")
_HIDING_CATEGORIES = frozenset({"Cc", "Cf", "Cn", "Co", "Cs", "Me", "Mn", "Zl", "Zp", "Zs"})
# What a walk crosses between two parts of one number: grouping and decimal marks, and an exponent mark and its sign,
# as in `1.2345e6` and `12.34e+5`. A decimal mark that starts a number, as in `.57891` or `,57891`, is the first
# part of it (_DECIMALS).
_SEPARATORS = frozenset(character for character, role in _GAP_CLASS.items() if role in " .,'") | frozenset("eE+-")
_DECIMALS = frozenset(character for character, role in _GAP_CLASS.items() if role in ".,")
_IN_QUOTES = frozenset("\t\r\n")  # inside a quoted field, these split a figure too
_NEAR = "\\d \\.,'\\xa0\\u2007\\u2009\\u202f\\u2019\\uff0c\\uff0e\\u066b\\u066ceE+\\-"
_MARK = "\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f`\\x7f-\\U0010ffff"
# A character that may be a mark, not a digit, next to a digit or a separator: where a walk to both sides begins.
_START = re.compile(rf"(?!\d)(?:(?<=[{_NEAR}])[{_MARK}]|[{_MARK}](?=[{_NEAR}]))")
_START_TAB = re.compile(rf"(?!\d)(?:(?<=[{_NEAR}])[\t{_MARK}]|[\t{_MARK}](?=[{_NEAR}]))")
_START_QUOTED = re.compile(rf"(?!\d)(?:(?<=[{_NEAR}])[\t\r\n{_MARK}]|[\t\r\n{_MARK}](?=[{_NEAR}]))")


# Characters that part two numbers, as the ASCII `-`, `x` and `/` do: a minus or times sign and the fraction and
# division slashes, and every dash (category Pd). Saltillos are letters that look like apostrophes.
_PARTS = frozenset("\u2212\u00d7\u2044\u2215")
_APOSTROPHE_LETTERS = frozenset("\ua78b\ua78c")


def _look_alike(character: str) -> bool:
    """Whether a character may be taken for a grouping or decimal mark though no reading takes it for one: any but a
    letter, a digit, a space, a mark the readings know or a character that parts numbers (_PARTS) outside ASCII, and
    modifier letters and saltillos, which look like apostrophes. In ASCII, only the grave accent."""
    if character.isascii():
        return character == "`"
    if character in _GAP_CLASS or character.isdecimal() or character in _PARTS:
        return False
    category = unicodedata.category(character)
    return (category == "Lm" or character in _APOSTROPHE_LETTERS
            or category[0] in "MNPS" and category != "Pd")


# Signs that stand beside an amount, as the ASCII `$`, brackets and `%` do: a currency sign, a bracket other than the
# low quotes that look like commas, and percent and per-mille signs. One is a mark where no letter, space or
# delimiter stands beside it (`_ordinary`), as in `5\u20ac50` or `98765\u20ac.43`; `;\u20ac75 929 683`, `Cash,\u20ac75` or
# `\uff0812 345\uff09` reads as before, and so does `SYN-1,\u20ac75 929 683` with the comma declared as the delimiter.
_PERCENTS = frozenset("\u066a\u2030\u2031\ufe6a\uff05")


def _beside_amounts(character: str) -> bool:
    category = unicodedata.category(character)
    return (category == "Sc" or category in ("Ps", "Pe") and character not in "\u201a\u201e"
            or character in _PERCENTS)


def _hides(character: str, extra: frozenset) -> bool:
    if character in _IN_QUOTES:  # a tab or line break outside quotes ends a cell or a line, it hides nothing
        return character in extra
    return character not in _GAP_CLASS and (
        character in _FILLERS or unicodedata.category(character) in _HIDING_CATEGORIES or _look_alike(character))


def _hides_at(text: str, at: int, extra: frozenset, comma_delimits: bool = False) -> bool:
    """`_hides` at a place in text. A visible look-alike beside an ASCII space parts two numbers, as `, ` does in
    `98, 765.43` or ` - ` in `10 - 20`: `98\u201a 765.43`, `10 \u2192 20` and `Art. 5 \u00a712` are read as two numbers,
    so it is not a mark there, unless what stands on its other side hides too, as in `Total \u00b7<ZWSP>57891`. Beside
    any other space, a tab or a line break it is. A sign that stands beside amounts (`_beside_amounts`) is a mark
    unless what stands on one side parts it from the number (`_parts_sign`). A dash, minus, times sign or slash parts
    two numbers (`_parts_at`)."""
    character = text[at]
    before, after = text[at - 1:at], text[at + 1:at + 2]
    if character in _PARTS or unicodedata.category(character) == "Pd":
        return not character.isascii() and not _parts_at(text, at, extra)
    if not _hides(character, extra):
        return False
    if character in _FILLERS or unicodedata.category(character) in _HIDING_CATEGORIES:
        return True
    if _beside_amounts(character):  # `5\u20ac50`, `98765\u20ac.43` or `98<ZWSP>\u20ac765`, never `;\u20ac75`
        return not (_parts_sign(text, at, -1, extra, comma_delimits) or _parts_sign(text, at, 1, extra, comma_delimits))
    if " " not in (before, after):
        return True
    other = after if before == " " else before  # `Total \u00b7<ZWSP>57891`, `"Total \u00b7<LF>57891"`
    return other not in ("", " ") and _hides(other, extra)


def _parts_at(text: str, at: int, extra: frozenset) -> bool:
    """Whether a dash, minus, times sign or slash parts two numbers at a place, as in `2015 \u2013 2020`: not beside a
    hidden mark or break, as in `2015\u2013<ZWSP>2020`, nor an exponent's sign, with only marks between it and the exponent mark, as in
    `1.2345e\u22126` or `1.2345e\u20ac\u22126`."""
    for step in (-1, 1):
        near = at + step
        if 0 <= near < len(text) and text[near] not in _GAP_CLASS and (
                text[near] in _FILLERS or text[near] in extra or unicodedata.category(text[near]) in _HIDING_CATEGORIES):
            return False
        while 0 <= near < len(text) and _hides(text[near], extra):
            near += step
        if 0 <= near < len(text) and text[near] in "eE":
            return False
    return True


def _ordinary(character: str, extra: frozenset) -> bool:
    """The edge of the text, a letter, a space, a delimiter or a quote: never a digit or what a number writes between
    its digits, a decimal or grouping mark, an exponent mark or sign or the grave accent, as in `98765\u20ac.43` or
    `1.2345\u20ace6`, nor a letter that shows as nothing or looks like a mark. A tab or line end is ordinary where it
    ends a cell or a line, not inside quotes (extra). The comma is judged by `_parts_sign`."""
    if not character:
        return True
    if character in "\t\r\n":
        return character not in extra
    if character.isascii():
        return character.isprintable() and not character.isdecimal() and character not in ".,'eE+-`"
    return character.isalpha() and character not in _FILLERS and not _look_alike(character)


def _parts_sign(text: str, at: int, step: int, extra: frozenset, comma_delimits: bool) -> bool:
    """Whether what stands on one side of a sign (step -1 or 1) parts it from a number: an ordinary character
    (`_ordinary`), or a comma that is the declared delimiter outside quotes, or one beyond which stands a word, a
    space, a delimiter, a quote or the edge, as in `Cash,\u20ac75` or `Fee,\u20ac75`. Read every way a comma may be a
    decimal mark, so with a digit, a mark or an exponent beyond it, as in `98,\u20ac765.43`, `98\u3164,\u20ac765.43` or
    `1.2345\u20ac,e6`, it hides one."""
    near = at + step
    character = text[near] if 0 <= near < len(text) else ""
    if character != ",":
        return _ordinary(character, extra)
    if comma_delimits:
        return True
    far = near + step
    beyond = text[far] if 0 <= far < len(text) else ""
    if beyond and beyond in "eE":  # a word, as `Fee`, or an exponent mark, as `e6`
        word = far + step
        return 0 <= word < len(text) and text[word].isascii() and text[word].isalpha()
    return beyond == "," or _ordinary(beyond, extra)


def _walk(text: str, at: int, step: int, extra: frozenset, comma_delimits: bool) -> tuple[int, bool, bool]:
    """From at going by step over separators and marks: where the walk stops, whether a digit stops it, and
    whether it passed a mark."""
    marked = False
    while 0 <= at < len(text):
        character = text[at]
        if _hides_at(text, at, extra, comma_delimits):
            marked = True
        elif character not in _SEPARATORS:
            break
        at += step
    return at, 0 <= at < len(text) and text[at].isdecimal(), marked


def _starts_a_number(text: str, first: int, last: int, comma_delimits: bool, extra: frozenset = frozenset()) -> bool:
    """Whether text[first:last] holds a decimal mark that may start a number. The readings take one after a letter
    too, as `USD.57891` or `\u5143.57891`, so any decimal mark may; only a comma that is the declared delimiter, outside
    quotes, is a column break instead. So may a look-alike of a mark beside a space, a hidden mark, a break or another
    mark, as in `USD\u00b7<ZWSP>57891`, `USD\u00b7<thin space>57891` or `Total\u00b7\u20ac57891`, whose fraction
    `leading_fractions` would not see."""
    run = text[first:last]
    return any(text[at] in _DECIMALS and not (comma_delimits and text[at] == ",") for at in range(first, last)) or (
        any(_look_alike(character) and not _beside_amounts(character) for character in run)
        and (any(character in extra or character in _FILLERS or unicodedata.category(character) in _HIDING_CATEGORIES
                 for character in run) or sum(_hides_at(text, at, extra, comma_delimits) for at in range(first, last)) > 1))


def _hidden_inside(text: str, start: re.Pattern, extra: frozenset = frozenset(), comma_delimits: bool = False) -> bool:
    """Whether a run of separators and marks between two digits, or between a decimal mark that starts a number and
    its digits, holds a mark. Each run is walked once."""
    resume = 0
    for match in start.finditer(text):
        at = match.start()
        if at < resume or not _hides_at(text, at, extra, comma_delimits):
            continue
        left, digit_before, _ = _walk(text, at - 1, -1, extra, comma_delimits)
        right, digit_after, _ = _walk(text, at + 1, 1, extra, comma_delimits)
        # The whole run, both sides of the mark: `<mark>.<mark>57891` hides the second mark behind the first.
        if digit_after and (digit_before or _starts_a_number(text, left + 1, right, comma_delimits, extra)):
            return True
        resume = right
    return False


# The marks of each class the readings read alike (`_GAP_CLASS`): one number that writes two of one class, as `.` and
# U+066C, is read as if it wrote one, so a reading may take its decimal mark for a group. A number is read here with
# every mark the readings know, runs of them and spaces included, each quantifier possessive.
_MATES = tuple(frozenset(character for character, role in _GAP_CLASS.items() if role == mark) for mark in ".,")
_RARE_MATES = tuple(sorted((_MATES[0] | _MATES[1]) - {".", ","}))
_CHAIN = re.compile(r"\d++(?:[" + re.escape("".join(sorted(character for character, role in _GAP_CLASS.items()
                                                             if role in " .,'"))) + r"]++\d++)++")


def _mixed_marks_inside(text: str) -> bool:
    """Whether one number writes two marks of one class, as `98\u066c765.43` or `1\u066c234 567.89`, which a reading
    would list in part."""
    if any(character in text for character in _RARE_MATES):
        for match in _CHAIN.finditer(text):
            marks = set(match.group())
            if any(len(marks & mates) > 1 for mates in _MATES):
                return True
    return False


# What marks a number in text as an amount: a sign, a bracket, a currency sign or code, a sign after a code, a credit
# or debit mark, or a percent sign after it (`marked_amount`).
_MARKED_BEFORE = re.compile(r"(?:(?<!\w)[-+\u2212]|[($\u00a2-\u00a5\u20a0-\u20c0]|(?<![A-Za-z])(?:[A-Z]{3}[-+\u2212]?"
                            r"|Soll|Haben|SOLL|HABEN|Credit|Debit|Cr|Dr))\Z")
_MARKED_AFTER = re.compile(r"\s*(?:[)%$\u00a2-\u00a5\u20a0-\u20c0]|-(?!\d)"
                           r"|(?:[A-Z]{1,3}|Soll|Haben|SOLL|HABEN|Credit|Debit|Cr|Dr)(?![A-Za-z]))")


def marked_amount(text: str, start: int, end: int) -> bool:
    """Whether the number text[start:end] is marked as an amount, with any spaces between it and what marks it before:
    `USD 20170520`, `EUR-20170520`, `Haben 20170520`, `(20170520)` or `20170520 Soll`. Eight bare digits are a date."""
    gap = start
    while gap and text[gap - 1].isspace():
        gap -= 1
    return bool(_MARKED_BEFORE.search(text[max(0, gap - 7):gap]) or _MARKED_AFTER.match(text, end))


_BEFORE_DIGITS = re.compile(r"(?<!\d)[`\x80-\U0010ffff](\d+(?:[eE][+-]?\d+)?)")


def leading_fractions(text: str) -> list[str]:
    """Each number right after a look-alike of a mark with no digit before it, written as the fraction it is if that
    look-alike is a decimal point: `USD\u00b757891` gives `.57891`, so the reader lists 0.57891 beside 57891, and
    `USD\u00b712345e3` gives `.12345e3`, 123.45."""
    return ["." + match.group(1) for match in _BEFORE_DIGITS.finditer(text)
            if _look_alike(match.group()[0]) and not _beside_amounts(match.group()[0])]


def _utf16_without_mark(text: str) -> bool:
    """Whether a text is UTF-16 read without its byte-order mark: NULs at nearly every other place."""
    half = len(text) // 2
    return half > 0 and max(text[0::2].count("\x00"), text[1::2].count("\x00")) >= 0.9 * half


_DELIMITERS = (",", ";", "\t", "|")


def _quoted_spans(text: str, delimiter: str | None) -> list[tuple[int, int]]:
    """The (opening, closing) quote positions of each field one delimiter's reading quotes, read strictly: a `"` at
    the start of the text, of a line (LF, CRLF or a lone CR) or right after the delimiter opens a field, `""` inside
    it is one quote, and the next lone `"` closes it. Raises MalformedQuotesSource when a field is left open at the
    end, or a closing quote is followed by anything but this delimiter, a line end or the end: csv would run the cell
    on past the quote, as `"1,234"<TAB>567.89` read with `,` is one cell. A `"` inside an unquoted cell is a character
    of that cell, as csv reads it. With None, one cell per line, only a line end stops a field."""
    stops, spans, index = frozenset(("\r", "\n") if delimiter is None else (delimiter, "\r", "\n")), [], 0
    while (opening := text.find('"', index)) != -1:
        if opening and text[opening - 1] not in stops:
            index = opening + 1  # inside an unquoted cell
            continue
        close = opening + 1
        while (close := text.find('"', close)) != -1 and text[close + 1:close + 2] == '"':
            close += 2
        if close == -1 or close + 1 < len(text) and text[close + 1] not in stops:
            raise MalformedQuotesSource
        spans.append((opening, close))
        index = close + 1
    return spans


def _quoted_fields(text: str, delimiters: tuple[str | None, ...]) -> tuple[list[str], bool]:
    """The inside of every field a delimiter's reading quotes strictly, and whether the source must be refused as
    MalformedQuotesSource: quoting malformed under any of the delimiters, or two readings that disagree about where a
    quoted field holding a digit begins or ends. The screen can't know which reading the file's author meant."""
    found, malformed = set(), False
    for delimiter in delimiters:
        try:
            found.update(_quoted_spans(text, delimiter))
        except MalformedQuotesSource:
            malformed = True
    spans = sorted(found)
    holds_digit = [any(character.isdecimal() for character in text[first + 1:last]) for first, last in spans]
    reach = -1, False  # the furthest closing quote so far, and whether its field or one overlapping it holds a digit
    for (first, last), digit in zip(spans, holds_digit, strict=True):
        malformed = malformed or first <= reach[0] and (digit or reach[1])
        reach = (last, digit) if last > reach[0] else (reach[0], reach[1] or digit)
    return [text[first + 1:last] for first, last in spans], malformed


def refuse_hidden_marks(text: str, layout: tuple[str | None, str] | None = None) -> None:
    """Raise HiddenMarkSource when marks between two digits, hidden or look-alikes, two marks of one class in a number,
    or a line break or tab inside a quoted field between the parts of a figure, would let a reading list it in part; MalformedQuotesSource when the quoting can't be
    read strictly; ValueError for UTF-16 read without its mark."""
    if "\x00" in text and _utf16_without_mark(text):
        raise ValueError("UTF-16 text without a byte-order mark")
    # Declared with a delimiter other than a tab, or as one column, a tab is a character of its cell, as inside quotes.
    tab = frozenset("\t") if layout is not None and layout[0] != "\t" else frozenset()
    # Read every way, a comma may be a decimal mark under the other readings, so a mark after one refuses the source;
    # declared with the comma as its delimiter, a comma outside quotes is a column break.
    if _hidden_inside(text, _START_TAB if tab else _START, tab, layout is not None and layout[0] == ","):
        raise HiddenMarkSource
    if _mixed_marks_inside(text):  # two marks of one class inside a number
        raise HiddenMarkSource
    if '"' in text:
        # Each reading's quoting on its own: a declared delimiter only, otherwise each one the readings try. Quoting
        # one of them can't parse strictly, or readings that disagree, refuse the source; declare the layout instead.
        # So a file quoted for one delimiter, as `"SYN-1","98765.43"`, is refused read every way: `,` after a closing
        # quote is not strict under `;`. Fail closed: the screen can't know which reading the file's author meant. A
        # mark inside a field another reading quotes strictly is named first, as the more telling reason.
        fields, malformed = _quoted_fields(text, _DELIMITERS if layout is None else (layout[0],))
        if any(_hidden_inside(field, _START_QUOTED, _IN_QUOTES) for field in fields):
            raise HiddenMarkSource
        if malformed:
            raise MalformedQuotesSource
