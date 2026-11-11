"""Bounded decimal normalization for confidential-number screening.

This module does not load policy, authorize a request or dispatch a provider.
"""

import csv
from dataclasses import dataclass, field
from datetime import date
import hashlib
import html
import io
import os
from pathlib import Path
import re
import stat
import tokenize
import unicodedata

from .errors import AssistantError
from .python_source import (MAX_FIGURE_DIGITS, SOURCE_ERRORS, fstring_constant_texts, hidden_fstring_fields, is_python_path,
                            number_text, python_tokens, python_tree, string_constant_values,
                            strings_read_differently)
from .security import regular_path

_CURRENCIES = "$€£¥"
_GROUP_SEPARATORS = "   "
_DECIMAL = re.compile(r"(?P<integer>[0-9]+|[0-9]{1,3}(?:,[0-9]{3})+)"
                      r"(?:\.(?P<fraction>[0-9]+))?(?:[eE](?P<exponent>[+-]?[0-9]{1,3}))?")


def normalize_numeric_token(value: str, *, max_digits: int = 128) -> str:
    """Return a dot-decimal canonical value, without floating-point rounding.

    Only explicit dot decimals, comma/space thousands groups, underscores between
    digits, Unicode decimal digits, one currency prefix, signs, parentheses and bounded
    decimal exponents are supported. Invalid input has a non-disclosing error.
    Policy entries use the default bound; screening passes MAX_FIGURE_DIGITS, so
    every value a policy entry can expand to can also be matched.
    """
    if not isinstance(value, str) or not value or len(value) > max(256, 2 * max_digits + 16):
        raise AssistantError("forbidden_token_invalid")
    value = value.strip(" ")
    value = "".join(str(unicodedata.decimal(c)) if c.isdecimal() else c for c in value)
    value = re.sub(r"(?<=[0-9])_(?=[0-9])", "", value)
    negative = value.startswith("(") and value.endswith(")")
    if negative:
        value = value[1:-1]
    if value[:1] in _CURRENCIES and value:
        value = value[1:]
    if value.startswith(("+", "-")):
        if negative:
            raise AssistantError("forbidden_token_invalid")
        negative = value.startswith("-")
        value = value[1:]
        if value[:1] in _CURRENCIES and value:
            value = value[1:]
    # Grouping must use one separator throughout, with exactly three digits
    # after each separator. Whitespace never changes a decimal's magnitude.
    used = [c for c in _GROUP_SEPARATORS if c in value]
    if used:
        if len(used) != 1 or "," in value:
            raise AssistantError("forbidden_token_invalid")
        value = value.replace(used[0], ",")
    match = _DECIMAL.fullmatch(value)
    if match is None:
        raise AssistantError("forbidden_token_invalid")
    result = _plain_decimal(match["integer"].replace(",", ""), match["fraction"] or "",
                            int(match["exponent"] or "0"), max_digits)
    if result is None:
        raise AssistantError("forbidden_token_invalid")
    return ("-" if negative and result != "0" else "") + result


def _plain_decimal(integer: str, fraction: str, exponent: int, max_digits: int) -> str | None:
    """The unsigned canonical decimal of ASCII digits, or None when it is over the bounds."""
    if len(integer) + len(fraction) > max_digits or abs(exponent) > 128:
        return None
    digits = integer + fraction
    point = len(integer) + exponent
    if point <= 0:
        result = "0." + "0" * (-point) + digits
    elif point >= len(digits):
        result = digits + "0" * (point - len(digits))
    else:
        result = digits[:point] + "." + digits[point:]
    whole, _, fractional = result.partition(".")
    whole = whole.lstrip("0") or "0"
    fractional = fractional.rstrip("0")
    return whole + ("." + fractional if fractional else "")


MAX_TOKEN_BYTES = 131_072
MAX_TOKENS = 1024
# Figure sources: delimited files, such as custody exports, whose numeric cells are all listed.
MAX_SOURCE_FILES = 16
MAX_SOURCE_BYTES = 8_000_000
MAX_SOURCE_FIGURES = 200_000
MATCHES = ("value", "digits")
# The settings that name a list. The screen runs when any is set.
LIST_RULES = ("forbidden_token_file", "forbidden_token_hashes", "forbidden_token_sources")
MIN_DIGITS, MAX_MIN_DIGITS, DEFAULT_MIN_DIGITS = 4, 18, 5


@dataclass(frozen=True)
class TokenSnapshot:
    """Private ephemeral deny set; never serialize into packets or reports."""

    hashes: frozenset[str] = field(repr=False)
    file_path: Path | None = field(default=None, repr=False)
    line_count: int = 0
    file_digest: str | None = field(default=None, repr=False)
    # Digit matching: hashes of significant-digit strings, and the lengths that occur among them.
    digit_hashes: frozenset[str] = field(default=frozenset(), repr=False)
    digit_lengths: frozenset[int] = field(default=frozenset(), repr=False)
    source_digests: tuple[str, ...] = field(default=(), repr=False)
    source_figures: int = 0
    listed: int = 0  # Distinct figures listed, however they are matched.

    @property
    def active(self) -> bool:
        return bool(self.hashes or self.digit_hashes)


def _read_token_file(value: str, excluded_roots: tuple[Path, ...], *, limit: int = MAX_TOKEN_BYTES,
                     home: bool = False) -> tuple[bytes, Path]:
    """Read a bounded regular non-linked external file, with identity checks."""
    descriptor = None
    try:
        candidate = Path(value).expanduser() if home else Path(value)
        if not candidate.is_absolute() or ".git" in candidate.parts:
            raise ValueError
        path = regular_path(candidate)
        if any(path.is_relative_to(root.resolve()) for root in excluded_roots):
            raise ValueError
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_BINARY", 0))
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ValueError
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(descriptor, min(65_536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        current = regular_path(candidate).stat()
        def identity(st):
            return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        def metadata(st):
            return (*identity(st), st.st_ctime_ns, st.st_nlink)
        # Windows stat/fstat can expose different ctime semantics. Compare
        # ctime within each API, and cross-check the shared object identity.
        if (size > limit or metadata(opened) != metadata(after)
                or metadata(before) != metadata(current) or identity(after) != identity(current)):
            raise ValueError
        return b"".join(chunks), path
    except (OSError, ValueError, RuntimeError, AssistantError):
        raise AssistantError("forbidden_token_file_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_date(digits: str) -> bool:
    """Eight digits that name a real day from 1900 to 2100, as a date column holds; not a figure."""
    if len(digits) != 8 or not 1900 <= int(digits[:4]) <= 2100:
        return False
    try:
        date(int(digits[:4]), int(digits[4:6]), int(digits[6:]))
    except ValueError:
        return False
    return True


def _digit_forms(whole: str, fraction: str, min_digits: int) -> set[str]:
    """Significant-digit strings that stand for one decimal: its own and its two-place rounding's.

    Leading and trailing zeros are dropped, so the same digits match at any scale. A form
    shorter than min_digits is left out, because it would match ordinary numbers.
    """
    whole, fraction = whole.lstrip("0"), fraction.rstrip("0")
    forms = {(whole + fraction).strip("0")}
    if len(fraction) > 2:  # Half up at two places, on the digits: a digit string has no point.
        forms.add(str(int((whole + fraction[:2]) or "0") + (fraction[2] >= "5")).strip("0"))
    return {form for form in forms if len(form) >= min_digits}


# A cell is a figure when nothing but a sign, a currency sign or code, brackets, a percent sign,
# quotes or spaces surrounds its one number.
_CELL_EDGE = re.compile(r"[\s$\u20ac\u00a3\u00a5%()+\-\u2212\"']*(?:[A-Z]{3})?[\s$\u20ac\u00a3\u00a5%()+\-\u2212\"']*")


def _cell_readings(cell: str) -> list[tuple[str, str]]:
    """Every value a cell that holds exactly one number can have, as (whole, fraction) digits.

    Any notation the screen reads in a payload is read here: groups, either decimal mark, a
    leading point as in `.4821357`, and an exponent as in `1.23456789e6`, which is applied.
    """
    runs = list(_RUN.finditer(cell))
    if not runs or len(runs) > 64:
        return []
    lead = cell[:runs[0].start()]
    pointed = lead[-1:] in _LEADING_POINTS and bool(lead)  # `.57`: the point is part of the number.
    if not (_CELL_EDGE.fullmatch(lead[:-1] if pointed else lead) and _CELL_EDGE.fullmatch(cell[runs[-1].end():])):
        return []
    found = []
    for whole, fraction, exponent, first, last in _readings(cell):
        # The reading must take in the whole cell; behind a leading point it has no whole part.
        if exponent is None or first != 0 or last != len(runs) - 1 or (pointed and whole):
            continue
        number = _plain_decimal(whole, fraction.rstrip("0"), exponent, 128)
        if number is not None:
            found.append(tuple(number.partition(".")[::2]))
    return found


def _source_figures(raw: bytes, min_digits: int) -> tuple[set[str], set[str]]:
    """(canonical values, digit forms) of every cell of one delimited text that holds a figure.

    The delimiter is the commonest of comma, semicolon, tab and bar in the first lines. A cell
    with fewer significant digits than min_digits, or one that is a date, is not a figure.
    """
    text = raw.decode("utf-8", errors="replace")
    delimiter = max(",;\t|", key=text[:8192].count)
    values, forms = set(), set()
    for row in csv.reader(io.StringIO(text, newline=""), delimiter=delimiter):
        for cell in row:
            for whole, fraction in _cell_readings(cell):
                found = _digit_forms(whole, fraction, min_digits)
                if not found or (not fraction and _is_date(whole.lstrip("0"))):
                    continue
                values.add(whole + ("." + fraction if fraction else ""))
                forms |= found
    return values, forms


def load_token_snapshot(rules: dict, excluded_roots: tuple[Path, ...], parsed: dict | None = None) -> TokenSnapshot:
    """Union optional literal and normalized-hash declarations without logging.

    Every file is read again on each call. `parsed` keeps a source's figures by the digest of its
    bytes, so a guard that rechecks an unchanged source does not parse it again.
    """
    configured = rules.get("forbidden_token_hashes", [])
    if (not isinstance(configured, list) or len(configured) > MAX_TOKENS
            or any(not isinstance(h, str) or re.fullmatch(r"[0-9a-f]{64}", h) is None for h in configured)):
        raise AssistantError("forbidden_token_hashes_invalid")
    hashes = set(configured)
    path, count, fingerprint = None, 0, None
    match = rules.get("forbidden_token_match", MATCHES[0])
    min_digits = rules.get("forbidden_token_min_digits", DEFAULT_MIN_DIGITS)
    if match not in MATCHES or type(min_digits) is not int or not MIN_DIGITS <= min_digits <= MAX_MIN_DIGITS:
        raise AssistantError("forbidden_token_match_invalid")
    forms: set[str] = set()
    if "forbidden_token_file" in rules:
        value = rules["forbidden_token_file"]
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise AssistantError("forbidden_token_file_invalid")
        raw, path = _read_token_file(value, excluded_roots)
        try:
            lines = raw.decode("utf-8").replace("\r\n", "\n").split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            if not lines or len(lines) > MAX_TOKENS:
                raise ValueError
            for line in lines:
                normalized = normalize_numeric_token(line)
                hashes.add(_digest(normalized))
                whole, _, fraction = normalized.lstrip("-").partition(".")
                forms |= _digit_forms(whole, fraction, min_digits)
        except (UnicodeError, ValueError, AssistantError):
            raise AssistantError("forbidden_token_file_invalid") from None
        count = len(lines)
        fingerprint = hashlib.sha256(raw).hexdigest()
    sources = rules.get("forbidden_token_sources", [])
    if (not isinstance(sources, (list, tuple)) or len(sources) > MAX_SOURCE_FILES or len(set(sources)) != len(sources)
            or any(not isinstance(item, str) or not item or len(item) > 4096 for item in sources)):
        raise AssistantError("forbidden_token_source_invalid")
    digests, figures = [], set()
    for source in sources:
        try:
            raw, _path = _read_token_file(source, excluded_roots, limit=MAX_SOURCE_BYTES, home=True)
            source_digest = hashlib.sha256(raw).hexdigest()
            if parsed is None or source_digest not in parsed:
                values, found = _source_figures(raw, min_digits)
                if parsed is not None:
                    parsed[source_digest] = (values, found)
            else:
                values, found = parsed[source_digest]
        except (csv.Error, ValueError, ArithmeticError, AssistantError):
            raise AssistantError("forbidden_token_source_invalid") from None
        if not values:  # A source with no figure is a wrong file or a wrong setting: never a pass.
            raise AssistantError("forbidden_token_source_invalid")
        figures |= values
        forms |= found
        digests.append(source_digest)
    if len(figures) > MAX_SOURCE_FIGURES:
        raise AssistantError("forbidden_token_source_invalid")
    listed = len(hashes) + len(figures)
    if match == "digits":
        # A source figure's digit forms cover every notation of its value, and they leave out
        # digits inside a hash, which an exact entry for a short whole number would refuse.
        pass
    else:
        hashes.update(_digest(value) for value in figures)
        forms = set()
    return TokenSnapshot(frozenset(hashes), path, count, fingerprint, frozenset(_digest(form) for form in forms),
                         frozenset(len(form) for form in forms), tuple(digests), len(figures), listed)


_RUN = re.compile(r"\d+")  # Any Unicode decimal digits, like str.isdecimal.
# What one character between two digit runs can mean inside a single number. Each class is
# tried as every role it can play, so `48.213,57` is read both ways.
_GAP_CLASS = {
    "_": "_", "e": "e", "E": "e",
    ".": ".", "\uff0e": ".", "\u066c": ".",
    ",": ",", "\uff0c": ",", "\u066b": ",",
    " ": " ", "\u00a0": " ", "\u2007": " ", "\u2009": " ", "\u202f": " ",
    "'": "'", "\u2019": "'",
}
_MARKS = (".", ",")
_GROUP_CLASSES = frozenset(". ,'")
_LEADING_POINTS = ".\uff0e"
# Inside a row of three-digit groups, a start after the row's first run is read up to this many
# groups past its own: 27 digits. The first run is read at every length.
_GROUPS_TRIED = 8
# No reading reaches further than this many runs past its first: a whole part of at most
# MAX_FIGURE_DIGITS + 1 runs, a fraction of as many, and an exponent.
_LOOKAHEAD = 2 * MAX_FIGURE_DIGITS + 8


def _gap_class(text: str, end: int, start: int) -> str | None:
    """How the characters between two digit runs join them, or None when they do not."""
    if start - end == 1:
        return _GAP_CLASS.get(text[end])
    if start - end == 2 and text[end] in "eE" and text[end + 1] in "+-":
        return "e" + text[end + 1]
    return None


_DIGIT_JOINS = frozenset("_., '")
_WORD = frozenset("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_HEX = frozenset("0123456789abcdefABCDEF")
_HEX_LETTERS = frozenset("abcdfABCDF")  # Without e: `482135712e-4` is a number with an exponent.


def _hex_token(text: str, start: int, end: int) -> tuple[int, int, bool]:
    """The word around a digit run, as (start, end, hexadecimal).

    Hexadecimal means seven or more hexadecimal characters with a letter other than e: a commit
    or content hash, whose digits are not a figure. The caller keeps the answer for every other
    run inside the same word, so a word is scanned once however many runs it holds.
    """
    while start and text[start - 1] in _WORD:
        start -= 1
    while end < len(text) and text[end] in _WORD:
        end += 1
    word = text[start:end]
    return start, end, len(word) >= 7 and all(c in _HEX for c in word) and any(c in _HEX_LETTERS for c in word)


def _readings(text: str, digit_limit: int = 0):
    """Yield (whole, fraction, exponent, first, last) for every way the digits in text read as a number.

    first and last number the digit runs the reading spans, counted from the start of the text.
    With digit_limit, also yield (digits, None, None, first, last) for digit matching: the digits
    of every row of runs joined by separators, from each start, up to digit_limit significant
    digits. A lone run inside a hexadecimal word is left out of those.

    A number is a whole part, an optional fraction and an optional exponent. The whole part is
    one digit run, runs joined by underscores, or groups of three joined by one separator.
    Signs, currency signs, brackets and letters beside a number never hide it, because only
    digit runs and the single characters between them are read. Reading every start and every
    role over-reads on purpose: `1,234` is also read as 1 and as 234. A point between digits is
    a decimal point first: `73026.04` is not also read as 73026, and the digits after a point
    start a number of their own only with their own fraction or groups, as in `1.48213.57`.

    Leading zeros are dropped from each whole part, so padding never hides a value. Work is
    linear in the text and memory is bounded: runs are read through a sliding window, and
    only the first run of a row of groups or of underscore-joined runs is read at every length.
    """
    starts, digits, before, gaps, inner = [], [], [], [], []
    word = (0, 0, False)  # The last word examined for digit matching: (start, end, hexadecimal).

    def joined(index: int, value: str) -> tuple[str, int]:
        last = index
        while gaps[last] == "_" and len(value) <= MAX_FIGURE_DIGITS:
            last += 1
            value += digits[last]
        return value, last

    def with_exponent(whole: str, fraction: str, last: int):
        yield whole, fraction, 0, last
        gap = gaps[last]
        if gap is not None and gap[0] == "e":
            power = digits[last + 1].lstrip("0")  # Zero padding never changes an exponent.
            if len(power) <= 3:
                yield whole, fraction, int(power or "0") * (-1 if gap[-1] == "-" else 1), last + 1

    def with_fraction(whole: str, last: int, separator: str | None, alone: bool):
        mark = gaps[last]
        decimal = mark in _MARKS and mark != separator
        if alone and not (decimal and mark == "."):
            yield from with_exponent(whole, "", last)
        if decimal:
            yield from with_exponent(whole, digits[last + 1], last + 1)
            fraction, far = joined(last + 1, digits[last + 1])
            if far > last + 1:
                yield from with_exponent(whole, fraction, far)

    def from_run(index: int):
        first = digits[index].lstrip("0")
        fractional = before[index] == "."
        yield from with_fraction(first, index, None, not fractional)
        # After an all-zero run the next run starts the same value, and a run inside an
        # underscore-joined number is not read as the start of another one.
        if first and not inner[index]:
            whole, last = joined(index, first)
            if last > index:
                yield from with_fraction(whole, last, None, not fractional)
        separator = gaps[index]
        if separator in _GROUP_CLASSES and len(first) <= 3:
            # A row's first run is read at every length, so a long figure that starts a row is
            # found whatever follows it. From a later start only a few groups are tried.
            most = MAX_FIGURE_DIGITS if before[index] != separator else _GROUPS_TRIED
            whole, last, groups = first, index, 0
            while (gaps[last] == separator and len(digits[last + 1]) == 3 and groups < most
                   and len(whole) <= MAX_FIGURE_DIGITS):
                last += 1
                whole = (whole + digits[last]).lstrip("0")
                groups += 1
                yield from with_fraction(whole, last, separator, True)
        start = starts[index]
        if start and text[start - 1] in _LEADING_POINTS and not fractional:
            yield from with_exponent("", digits[index], index)  # `.57`
            fraction, far = joined(index, digits[index])
            if far > index:
                yield from with_exponent("", fraction, far)
        # Digit matching: significant digits never start with a zero run, and a row is followed
        # only while it can still be as short as a listed form (trailing zeros do not count).
        if digit_limit and first:
            nonlocal word
            row, last = first, index
            if not word[0] <= start < word[1]:  # Runs come in text order, so one word is scanned once.
                word = _hex_token(text, start, start + len(digits[index]))
            if not word[2]:
                yield row, None, None, index
            while gaps[last] in _DIGIT_JOINS and len(row.rstrip("0")) <= digit_limit and len(row) <= digit_limit + 32:
                last += 1
                row += digits[last]
                yield row, None, None, last

    previous_end, significant, passed = None, False, 0
    for match in _RUN.finditer(text):
        gap = None if previous_end is None else _gap_class(text, previous_end, match.start())
        if previous_end is not None:
            gaps.append(gap)
        # True when the underscore-joined run before this one already holds a non-zero digit.
        significant = gap == "_" and (significant or bool(digits[-1].strip("0")))
        run = match.group()
        starts.append(match.start())
        digits.append(run if run.isascii() else "".join(str(unicodedata.decimal(c)) for c in run))
        before.append(gap)
        inner.append(significant)
        previous_end = match.end()
        if len(digits) > 2 * _LOOKAHEAD:
            ready = len(digits) - _LOOKAHEAD
            for index in range(ready):
                for whole, fraction, exponent, last in from_run(index):
                    yield whole, fraction, exponent, passed + index, passed + last
            del starts[:ready], digits[:ready], before[:ready], gaps[:ready], inner[:ready]
            passed += ready
    gaps.append(None)
    for index in range(len(digits)):
        for whole, fraction, exponent, last in from_run(index):
            yield whole, fraction, exponent, passed + index, passed + last


_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\x([0-9a-fA-F]{2})")


def _spelled_out(text: str) -> str | None:
    """The text with character escapes and HTML entities replaced by what they spell, or None if it has none.

    JSON, JavaScript and Python write a no-break space as an escape and HTML writes it as an
    entity, so `48\\u00a0213.57` and `48&nbsp;213.57` are read as the figure they display.
    """
    if "\\" not in text and "&" not in text:
        return None

    def character(match: re.Match) -> str:
        try:
            return chr(int(match.group(1) or match.group(2) or match.group(3), 16))
        except (ValueError, OverflowError):
            # Past the last code point: not a character. Before Python 3.13, chr() raises
            # OverflowError, not ValueError, for a number of 2**31 or more.
            return match.group()

    decoded = html.unescape(_ESCAPE.sub(character, text))
    return None if decoded == text else decoded


def _listed(magnitude: str, snapshot: TokenSnapshot) -> bool:
    # A hash-only policy can list either sign. Compare both without
    # recovering or retaining any configured plaintext value.
    forms = (magnitude, "-" + magnitude) if magnitude != "0" else ("0",)
    return any(hashlib.sha256(form.encode("utf-8")).hexdigest() in snapshot.hashes for form in forms)


def _digits_listed(forms, snapshot: TokenSnapshot) -> bool:
    return any(len(form) in snapshot.digit_lengths and _digest(form) in snapshot.digit_hashes for form in forms)


def screen_text(text: str, snapshot: TokenSnapshot) -> None:
    """Check content only; callers must select typed content, not filenames."""
    if not snapshot.active:
        return
    limit = max(snapshot.digit_lengths, default=0)
    seen, rows = set(), set()
    for view in (text, _spelled_out(text)):
        for whole, fraction, exponent, _first, _last in _readings(view or "", limit):
            if exponent is None:  # A row of digits, matched by its significant digits.
                row = whole.rstrip("0")
                if row not in rows:
                    rows.add(row)
                    if _digits_listed((row,), snapshot):
                        raise AssistantError("forbidden_token_present")
                continue
            # Zeros that never change the value are dropped before the bounds apply.
            fraction = fraction.rstrip("0")
            number = _plain_decimal(whole, fraction, exponent, MAX_FIGURE_DIGITS)
            if number is None or number in seen:
                continue
            seen.add(number)
            if _listed(number, snapshot):
                raise AssistantError("forbidden_token_present")
            # A longer decimal also matches by its two-place rounding, as the list's own figures do.
            # The rounding is of the value, with any exponent applied: `9.05125e2` is 905.125.
            units, _, places = number.partition(".")
            if limit and len(places) > 2 and len(number) <= 65 and _digits_listed(
                    _digit_forms(units, places, MIN_DIGITS) - {(units + places).strip("0")}, snapshot):
                raise AssistantError("forbidden_token_present")


def _screen_python_numbers(numbers, snapshot: TokenSnapshot) -> None:
    """Refuse a listed value among the plain decimal texts of Python literals."""
    for plain in numbers:
        if plain is None:
            continue
        try:
            number = normalize_numeric_token(plain, max_digits=MAX_FIGURE_DIGITS)
        except AssistantError:
            continue
        if _listed(number.lstrip("-"), snapshot):
            raise AssistantError("forbidden_token_present")
        whole, _, fraction = number.lstrip("-").partition(".")
        if snapshot.digit_hashes and len(number) <= 64 and _digits_listed(_digit_forms(whole, fraction, MIN_DIGITS), snapshot):
            raise AssistantError("forbidden_token_present")


def screen_source(text: str, path: str | None, snapshot: TokenSnapshot) -> None:
    """Screen one file's text; in Python, also read every number as Python does."""
    if not snapshot.active:
        return
    # What leaves the machine is text, so the text screen runs on every file,
    # Python included: `(6,729,102.50)` is a tuple in code but reads as the figure.
    screen_text(text, snapshot)
    if not is_python_path(path):
        return
    tokens = python_tokens(text)
    if tokens is None:
        # Never fall back silently: an unreadable Python file is refused.
        raise AssistantError("forbidden_token_python_unreadable")
    numbers = [number_text(token.string) for token in tokens if token.type == tokenize.NUMBER]
    # Before Python 3.12 numbers inside f-string fields stay inside one STRING token, and a
    # string's value can differ from its source text. Only the AST can read either.
    hidden, respelled = hidden_fstring_fields(tokens), strings_read_differently(tokens)
    tree = python_tree(text) if hidden or respelled else None
    if tree is None and (hidden or respelled):
        raise AssistantError("forbidden_token_python_unreadable")
    if hidden:
        numbers += fstring_constant_texts(tree, text)
    _screen_python_numbers(numbers, snapshot)
    if respelled:
        for value in string_constant_values(tree):
            screen_text(value, snapshot)


def _line_numbers(line: str) -> list[str | None]:
    """Plain decimal text of every Python number on one line.

    A snippet line may be partial code, such as an open signature, so tokens are read up to
    the first tokenizer error rather than refused. Before Python 3.12 an f-string is one
    STRING token with no NUMBER inside, so each complete f-string token is parsed on its own
    and its field constants are read from the AST, as screen_source does for a whole file.
    """
    tokens = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(line + "\n").readline):
            tokens.append(token)
    except SOURCE_ERRORS:
        pass
    found = [number_text(token.string) for token in tokens if token.type == tokenize.NUMBER]
    if hidden_fstring_fields(tokens):
        for token in tokens:
            prefix = re.match(r"[A-Za-z]*", token.string).group().lower()
            if token.type == tokenize.STRING and "f" in prefix and "{" in token.string:
                tree = python_tree(token.string)
                if tree is None:  # Never pass a field that can't be read.
                    raise AssistantError("forbidden_token_python_unreadable")
                found += fstring_constant_texts(tree, token.string)
    return found


def screen_lines(lines: list[str], path: str | None, snapshot: TokenSnapshot) -> None:
    """Screen a related-context snippet: its text, and in Python every number on each line."""
    if not snapshot.active:
        return
    screen_text("\n".join(lines), snapshot)
    if not is_python_path(path):
        return
    for line in lines:
        _screen_python_numbers(_line_numbers(line), snapshot)


def screen_packet(packet: dict, system: str, snapshot: TokenSnapshot) -> None:
    """Select content after the caller validates the packet's strict schema."""
    screen_text(system, snapshot)
    for item in packet["files"]:
        for side in ("before", "after"):
            if item[side] is not None:
                screen_source(item[side], item.get("path"), snapshot)
    screen_related(packet, snapshot)


def screen_related(packet: dict, snapshot: TokenSnapshot) -> None:
    """The related-context snippets of a packet: each symbol and every line shown."""
    for item in packet.get("related", {}).get("snippets", ()):
        screen_text(item["symbol"], snapshot)
        screen_lines([line for _number, line in item["lines"]], item.get("path"), snapshot)


def screen_review_output(review: dict, snapshot: TokenSnapshot) -> None:
    """The free text a model returned in a review, before any of it is shown or saved."""
    screen_text(review["summary"], snapshot)
    for finding in review["findings"]:
        for name in ("claim", "impact", "reproduction"):
            screen_text(finding[name], snapshot)


@dataclass(frozen=True)
class TokenGuard:
    """Ephemeral screening state, excluded from Config and serialized identity."""

    rules: dict = field(repr=False)
    roots: tuple[Path, ...] = field(repr=False)
    snapshot: TokenSnapshot = field(repr=False)
    # Figures of each source by the digest of its bytes: an unchanged source is not parsed twice.
    parsed: dict = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def load(cls, rules: dict, roots: tuple[Path, ...]) -> "TokenGuard":
        parsed: dict = {}
        return cls(dict(rules), tuple(roots), load_token_snapshot(rules, tuple(roots), parsed), parsed)

    def recheck(self, packet: dict, system: str) -> None:
        current = load_token_snapshot(self.rules, self.roots, self.parsed)
        # Even a semantically equivalent rewrite invalidates a prior snapshot.
        if current != self.snapshot:
            raise AssistantError("forbidden_token_configuration_changed")
        screen_packet(packet, system, current)


def token_file_audit(snapshot: TokenSnapshot) -> dict | None:
    """Only non-content metadata may enter the private budget audit."""
    if snapshot.file_path is None and not snapshot.source_digests:
        return None
    path = None if snapshot.file_path is None else str(snapshot.file_path)
    try:
        screen_text(path or "", snapshot)
    except AssistantError:
        path = "[redacted]"
    event = {"event": "forbidden_token_file_screened", "file_path": path, "line_count": snapshot.line_count}
    if snapshot.source_digests:  # Counts only: never a source's path, digest or contents.
        event.update(source_files=len(snapshot.source_digests), source_figures=snapshot.source_figures)
    return event
