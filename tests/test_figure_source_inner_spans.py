"""A longer reading never hides a shorter number a reader sees. A text cell lists every number the payload screen
reads in it, the cut cells of a comma file list each amount whole and in every shorter run, and the decimal-comma
amounts a comma cut are found in time proportional to the text. Synthetic only."""

import random
import re
import time

import pytest

from finassist import figure_sources
from finassist.forbidden_tokens import _LEADING_POINTS, _RUN, MAX_FIGURE_DIGITS, _plain_decimal, _readings

# A later start after a point that groups a row, as 234,56 in `1.234,56`: a group of three after a point that ends a
# run of one to three digits.
_AFTER_A_GROUPING_POINT = r"(?:(?<=(?<!\d)\d\.)|(?<=(?<!\d)\d\d\.)|(?<=(?<!\d)\d\d\d\.))(?=\d{3}(?!\d))"
# The pattern the comma reading sought decimal-comma cut amounts with, tried at every start: the oracle.
_TRIED_AT_EVERY_START = tuple(re.compile(
    rf"(?={start}((?:\d{{1,3}}(?:(?:[.']|[^\S\r\n])\d{{3}})+|\d+),\d{{1,4}}{figure_sources._EXPONENT})"
    r"(?![\d.]|[-/:]\d))") for start in (*figure_sources._STARTS, _AFTER_A_GROUPING_POINT))
# The cut cells' pass at the start every reading used before it, for comparison.
_EARLIER_CUTS = figure_sources._GROUPED_CUTS
ALPHABET = ("1", "2", "45", "678", "123", "0", "٣", ",", ",", ".", "'", " ", "\t", "\r", "\n", "\xa0", " ",
            "-", "/", ":", "e", "E", "+", "EUR", "aEUR", "x", "_", "12,34", "1 234", "1'234,5", "9e9", '"')


# What the screen also reads in a comma-cut decimal-comma amount: a first digit glued to a letter, or to an underscore
# after one, a whole part of runs joined by underscores, and decimals joined by them.
_TRIED_WITH_EXTRAS = (re.compile(
    rf"(?=(?:{'|'.join(figure_sources._STARTS)}|{_AFTER_A_GROUPING_POINT}|(?<=[^\W\d_])|(?<=[^\W\d_]_))"
    rf"((?:\d{{1,3}}(?:(?:[.']|[^\S\r\n])\d{{3}})+|\d+(?:_\d+)*),\d(?:_?\d){{0,3}}{figure_sources._EXPONENT})"
    r"(?![\d.]|_\d|[-/:]\d))"),)


def _glued_start(text, at):
    return (not figure_sources._MAY_START.match(text, at)
            and (text[at - 1:at].isalpha() or text[at - 1:at] == "_" and text[at - 2:at - 1].isalpha()))


def _expected_extras(text):
    """The extra pass: what the wider pattern finds and the plain one does not, with the same nine-group rule for a
    later start in a row; a whole part joined by underscores is read from its first run."""
    found = [(match.start(1), match.end(1), match.group(1)) for match in _TRIED_WITH_EXTRAS[0].finditer(text)]
    first_start = {}
    for first, end, _amount in found:
        first_start[end] = min(first_start.get(end, first), first)
    kept = [(first, amount) for first, end, amount in found
            if first == first_start[end] or len(_RUN.findall(amount.split(",")[0])) <= 9]
    return sorted(amount for first, amount in kept if "_" in amount or _glued_start(text, first))


def _expected_cuts(text):
    """The oracle's amounts, a later start in a row kept up to nine groups before its decimal comma; None when a later
    start has more, which refuses the source."""
    found = [(match.start(1), match.end(1), match.group(1)) for pattern in _TRIED_AT_EVERY_START
             for match in pattern.finditer(text)]
    first_start = {}
    for first, end, _amount in found:
        first_start[end] = min(first_start.get(end, first), first)
    if any(first != first_start[end] and len(_RUN.findall(amount.split(",")[0])) > 9 for first, end, amount in found):
        return None
    return sorted(amount for first, end, amount in found
                  if first == first_start[end] or len(_RUN.findall(amount.split(",")[0])) <= 9)


def _cuts_or_refusal(text):
    try:
        return sorted(figure_sources._decimal_comma_cuts(text))
    except ValueError:
        return None


def _texts(seed, count, length=24):
    rng = random.Random(seed)
    return ["".join(rng.choice(ALPHABET) for _ in range(rng.randrange(1, length))) for _ in range(count)]


@pytest.mark.parametrize("text,held", [
    ("Lot 1.5 345 678.90", "345678.9"),
    ("Lot 12.5 345 678.90", "345678.9"),
    ("Lot .5 345 678.90", "345678.9"),
    ("Total1.5 345 678.90", "345678.9"),
    ("Lot 1.5 345\xa0678.90", "345678.9"),
    ("Lots 25 157 435.77", "157435.77"),
    ("Note 1 345 678.90", "345678.9"),
    ("SYN-1,1.5,345,678.90", "345678.9"),
    ("Rate:12,345,678.90", "12345"),
], ids=["after-a-decimal", "after-a-longer-decimal", "after-a-leading-point", "after-a-glued-decimal",
        "no-break-space-groups", "after-a-small-number", "after-a-word-and-number", "comma-cut", "after-a-label"])
def test_a_number_inside_a_longer_reading_of_a_text_cell_is_listed(text, held):
    assert held in figure_sources._inner_numbers(text, 5, round_figures=True)[0]


@pytest.mark.parametrize("cell,value", [
    ("1 345 678.90", "1345678.9"),
    ("USD 1 345 678.90", "1345678.9"),
    ("S 1 345 678.90", "1345678.9"),
    ("EUR 1.234.567,89", "1234567.89"),
    ("CHF 1'234'567.89", "1234567.89"),
], ids=["spaced", "code-then-spaced", "mark-then-spaced", "code-then-points", "code-then-apostrophes"])
def test_a_cell_of_one_number_is_read_as_one(cell, value):
    # The contract for a cell that holds exactly one number: signs, codes and marks around it, read as one figure.
    assert figure_sources._source_figures(f"Account;Amount\nSYN-2;{cell}\n".encode(), 5)[0] == {value}


def test_a_text_cell_lists_every_number_the_screen_reads_in_it():
    for text in _texts(20261114, 2000):
        values, forms, rounds = set(), set(), set()
        figure_sources._classify(
            [tuple(number.partition(".")[::2]) for whole, fraction, exponent, _first, _last in _readings(text)
             if (number := figure_sources._held_decimal(whole, fraction.rstrip("0"), exponent)) is not None],
            5, values, forms, rounds)
        assert figure_sources._inner_numbers(text, 5, round_figures=True) == (values, forms, rounds), repr(text)


@pytest.mark.parametrize("text,amounts", [
    ("x 1 234,56 ", ["1 234,56", "234,56"]),
    ("x 1.234,56 ", ["1.234,56", "234,56"]),  # after a point that groups the row, as the screen reads it
    ("x1'234,5", ["234,5"]),
    ("EUR1 234,5678", ["1 234,5678", "234,5678"]),
    ("1 234 5678,9", ["5678,9"]),
    ("12:30,15", []),
], ids=["space-groups", "point-groups", "after-a-word", "after-a-code", "a-long-last-run", "a-time"])
def test_the_decimal_comma_cuts_start_where_a_number_may(text, amounts):
    assert sorted(figure_sources._decimal_comma_cuts(text)) == sorted(amounts)


@pytest.mark.parametrize("text", [
    "1 234,567 890,12", "1,2,3", "1 234,56e5", "1 234,56e5.", "1 234,56e+5x", "12,3456", "12,34-5", "12,34/5",
    "12,34:5", "12,34.5", "1.234.567,89", "1'234'567,8", "EUR1 234,5", "aEUR1 234,5", "2026-12,34", "x/12,34",
    "1\xa0234\u2009567,1", "1 234\r\n567,1", "\u0661\u0662,\u0663\u0664", "1  234,5", "1 2345,6", "123 456 789 012,3",
], ids=lambda text: repr(text))
def test_a_decimal_comma_cut_at_each_boundary_is_one_the_pattern_found(text):
    assert _cuts_or_refusal(text) == _expected_cuts(text)


def test_the_decimal_comma_cuts_are_those_the_pattern_found_at_every_start():
    for text in _texts(20261115, 20_000) + _texts(20261117, 2000, 90) + _texts(20261120, 300, 240):
        assert _cuts_or_refusal(text) == _expected_cuts(text), repr(text)


def test_a_later_start_in_a_row_is_read_as_far_as_the_screen_reads_and_a_longer_one_refuses():
    row = "x 7" + " 234" * 9 + ",56"  # a quantity and an amount of nine groups, as 234,234,...,234.56
    amounts = list(figure_sources._decimal_comma_cuts(row))
    assert amounts[0] == row[2:] and len(amounts) == 10  # the row whole, then each later start of up to nine groups
    assert sorted(len(_RUN.findall(amount.split(",")[0])) for amount in amounts[1:]) == list(range(1, 10))
    with pytest.raises(ValueError, match="later start"):
        list(figure_sources._decimal_comma_cuts("x 7" + " 234" * 10 + ",56"))


@pytest.mark.parametrize("text,strict,extra", [
    ("SYN-1,x1234567,89", [], ["1234567,89"]),
    ("SYN-1,ab1 234,56", ["234,56"], ["1 234,56"]),
    ("SYN-1,EUR1234567,89", ["1234567,89"], []),
    ("SYN-1,x 1234567,89", ["1234567,89"], []),
    ("SYN-1,EUR_1234567,89", [], ["1234567,89"]),
    ("A;1_234,56", [], ["1_234,56"]),
    ("A;1234,5_6", ["1234,5"], ["1234,5_6"]),
    ("A;9_1234567,89", [], ["9_1234567,89"]),
], ids=["a-letter", "two-letters-and-groups", "a-code", "a-space", "an-underscore-after-a-code", "joined-whole",
        "joined-decimals", "joined-to-a-digit"])
def test_a_decimal_comma_cut_the_plain_shape_leaves_out_is_found_apart(text, strict, extra):
    assert sorted(figure_sources._decimal_comma_cuts(text)) == strict
    assert sorted(figure_sources._decimal_comma_cuts(text, extra=True)) == extra


def test_the_extra_decimal_comma_cuts_are_those_the_wider_pattern_adds():
    for text in _texts(20261119, 20_000):
        assert sorted(figure_sources._decimal_comma_cuts(text, extra=True)) == _expected_extras(text), repr(text)


@pytest.mark.parametrize("text,value", [
    ("12,34,567.89", ("1234567", "89")),
    ("1,23,45,678", ("12345678", "")),
    ("Total \u20b912,34,567.89", ("1234567", "89")),
], ids=["lakh", "crore", "rupee"])
def test_the_screen_reads_indian_groups(text, value):
    assert value in {(whole.lstrip("0"), fraction) for whole, fraction, exponent, _first, _last in _readings(text)
                     if exponent == 0}


def test_groups_of_two_without_a_last_group_of_three_are_no_indian_number():
    assert ("1234", "") not in {(whole, fraction) for whole, fraction, *_rest in _readings("12,34")}
    assert ("123456", "") not in {(whole, fraction) for whole, fraction, *_rest in _readings("12,34,56")}


def _cell_readings_of_every_start(cell):  # the reading before it stopped at the first later start: the oracle
    runs = list(_RUN.finditer(cell))
    if not runs or len(runs) > 64:
        return []
    lead = cell[:runs[0].start()]
    pointed = lead[-1:] in _LEADING_POINTS and bool(lead)
    if not (figure_sources._is_edge(lead[:-1] if pointed else lead) and figure_sources._is_edge(cell[runs[-1].end():])):
        return []
    found = []
    for whole, fraction, exponent, first, last in _readings(cell):
        if exponent is None or first != 0 or last != len(runs) - 1 or (pointed and whole):
            continue
        if (number := figure_sources._held_decimal(whole, fraction.rstrip("0"), exponent)) is not None:
            found.append(tuple(number.partition(".")[::2]))
        if abs(exponent) > 128 and (mantissa := _plain_decimal(whole, fraction.rstrip("0"), 0, MAX_FIGURE_DIGITS)):
            found.append(tuple(mantissa.partition(".")[::2]))
    return found


def test_a_cell_is_read_from_its_first_run_only():
    cells = ("1", "23", "456", "0", "\u0663", ",", ".", "'", " ", "_", "e", "E", "-", "+", "$", "EUR ", "CR", "(", ")",
             "x", "%", "\xa0", "1,234", "1 234", "12.345,67", ".5", "9e9", "1_000", "e129", "e200")
    rng = random.Random(20261118)
    for _ in range(20_000):
        cell = "".join(rng.choice(cells) for _ in range(rng.randrange(1, 20)))
        assert figure_sources._cell_readings(cell) == _cell_readings_of_every_start(cell), repr(cell)


def _every_spelling(whole, fraction, exponent):  # the value under some spelling the screen reads, if any
    digits, point = whole + fraction, len(whole) + exponent
    for shift in range(-128, 129):
        place = point - shift
        if place <= 0:
            integer, fractional = "0", "0" * -place + digits
        else:
            padded = digits + "0" * max(0, place - len(digits))
            integer, fractional = padded[:place], padded[place:]
        integer, fractional = integer.lstrip("0"), fractional.rstrip("0")
        if (number := _plain_decimal(integer, fractional, shift, MAX_FIGURE_DIGITS)) is not None:
            return number
    return None


@pytest.mark.parametrize("exponent", [0, 6, -6, 128, -128, 129, -129, 200, -200, 260, -260, 300, 388, -388, 400,
                                      -400, -500, 800])
def test_a_number_is_listed_when_any_spelling_the_screen_reads_holds_it(exponent):
    rng = random.Random(exponent)
    for _ in range(60):
        whole = rng.choice(["", "0", "1", "12", "12345", "1234567890", "9" * rng.randrange(1, 300), "0" * 40])
        fraction = rng.choice(["", "0", "5", "000123", "7" * rng.randrange(1, 120), "0" * 30 + "45"])
        whole += "0" * rng.choice([0, 50, 140, 200]) if whole else ""
        if whole or fraction:
            assert figure_sources._held_decimal(whole, fraction, exponent) == _every_spelling(whole, fraction, exponent)


def test_zero_and_a_leading_point_spelling_are_held():
    assert figure_sources._held_decimal("0", "", 900) == "0"
    assert figure_sources._held_decimal("12345", "", -388) == "0." + "0" * 383 + "12345"  # `.000...12345e-128`


def test_the_cut_cells_list_each_amount_whole_and_all_they_listed_at_the_earlier_start():
    for text in _texts(20261116, 4000, 30):
        try:
            values = figure_sources._cut_cell_figures(text, 4, round_figures=True)[0]
        except ValueError:
            continue  # an amount cut into more cells than are read: the source is refused
        quoted = figure_sources._quoted_spans(text)
        earlier = set()
        for match in (match for pattern in _EARLIER_CUTS for match in pattern.finditer(text)):
            if any(first <= match.start() < last for first, last in quoted):
                continue
            readings = figure_sources._cell_readings(match.group())
            runs = [reading for run in figure_sources._cut_runs(match.group())
                    for reading in figure_sources._run_readings(run)]
            figure_sources._classify(readings + runs if readings else runs, 4, earlier, set(), set())
        assert earlier <= values, repr(text)


@pytest.mark.alone
@pytest.mark.parametrize("row,rows", [
    ("x1" + "'234" * 4000 + "\n", 60),  # every group was tried to the end of its row: about 27 s
    ("x1" + " 234" * 4000 + "\n", 60),
    ("x" + " 234" * 62 + ",56\n", 8000),  # each later start's amount was read whole: about 19 s
    ("SYN-1,12,345,678.90\n", 40_000),  # each cell was read again by every reading and check: 5 times as long
    ("12," * 40_000 + "\n", 1),  # the Indian cut pattern walked the rest of the row from every start: about 16 s
    ("1,2,3,4,5,6,7,8,9,10\n", 20_000),  # each cell and cut amount was classified again wherever it stood
], ids=["apostrophes", "spaces", "rows-with-decimal-commas", "a-plain-export", "groups-of-two", "tiny-cells"])
def test_long_rows_of_digit_groups_are_read_in_time(row, rows):
    raw = (row * rows).encode("utf-8")
    start = time.perf_counter()
    try:
        figure_sources._source_figures(raw, 5)
    except ValueError:
        pass  # refused is as good as read, as long as it is in time
    assert time.perf_counter() - start < 10
