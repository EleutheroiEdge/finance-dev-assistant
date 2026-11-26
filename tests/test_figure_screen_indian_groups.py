"""The payload screen reads Indian digit grouping: groups of two before one last group of three, as `31,41,592.65`.

A listed figure written so is refused, and nothing that is not grouped that way is read as one. Every figure and text
here is synthetic.
"""

import pytest

from figure_source_cases import refused

from finassist import forbidden_tokens
from finassist.forbidden_tokens import TokenSnapshot, _readings, load_token_snapshot


def _snapshot(tmp_path, figure: str, match: str = "value", name: str = "figures.txt") -> TokenSnapshot:
    """The snapshot of a figure file that lists one figure."""
    path = tmp_path / name
    path.write_text(figure + "\n", encoding="utf-8", newline="\n")
    return load_token_snapshot({"forbidden_token_file": str(path), "forbidden_token_match": match}, ())


@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("text", [
    "31,41,592.65", "total 31,41,592.65 due", "(31,41,592.65)", "\u20b931,41,592.65", "INR 31,41,592.65 only",
    "x = (31,41,592.65)", '{"market_value": "31,41,592.65"}', "0031,41,592.650",
])
def test_a_listed_figure_written_in_indian_grouping_is_refused(tmp_path, match, text):
    snapshot = _snapshot(tmp_path, "3141592.65", match)
    assert refused(text, snapshot) and refused(text, snapshot, "notes.md") and refused(text, snapshot, "cash.py")


def test_a_long_whole_number_in_indian_grouping_is_refused(tmp_path):
    snapshot = _snapshot(tmp_path, "1234567891234")
    assert refused("12,34,56,78,91,234", snapshot)
    assert not refused("id 1,23,45,67,89,12,34 x", snapshot)  # The last group has two digits.


@pytest.mark.parametrize("text", [
    "31, 41, 592.65", "f(31, 41, 592.65)",   # separate arguments
    "31,41,59,2.65", "314,15,92.65",          # not groups of two before one group of three
    "31,41,592,65", "31.41.592,65",           # another separator after the last group, or groups joined by points
    "[3, 14, 15, 92, 65]", "31,41,593.65",
])
def test_indian_grouping_reads_nothing_that_is_not_grouped_that_way(tmp_path, text):
    # Matching by value: with digits, a row of digits is matched whatever joins it.
    snapshot = _snapshot(tmp_path, "3141592.65")
    assert not refused(text, snapshot)
    # The same holds for the western groups of the same figure.
    assert refused("3,141,592.65", snapshot) and not refused("3, 141, 592.65", snapshot)


def _wholes(text: str) -> set[str]:
    return {whole for whole, _fraction, exponent, _first, _last in forbidden_tokens._readings(text)
            if exponent is not None}


def test_indian_grouping_over_reads_code_no_more_than_western_grouping_does():
    # Arguments written with a space, versions and times are never joined, in either grouping.
    spaced = "call(1, 22, 333)\nrgb(12, 34, 567)\nversion = '10.12.345'\nwhen = '10:12:345'\nrange(12,34)\n"
    assert not {"122333", "1234567", "1012345", "1234"} & _wholes(spaced)
    # A list written without spaces is read as one number in either grouping, on purpose.
    assert "3224224" in _wholes("shape = [3,224,224]") and "322333" in _wholes("shape = [3,22,333]")
    # Only a row that ends in a group of three is read: `12,34` and `12,34,56` are not numbers.
    assert not {"1234", "123456"} & _wholes("pair = (12,34)\ntriple = (12,34,56)\n")


def test_a_long_row_of_two_digit_groups_is_read_in_bounded_work(tmp_path):
    snapshot = _snapshot(tmp_path, "3141592.65")
    row = ",".join(["12"] * 30_000)
    readings = sum(1 for _reading in forbidden_tokens._readings(row + ",345 and " + row + ",31,41,592.65"))
    assert readings < 40 * 60_000
    assert refused(row + ",31,41,592.65", snapshot) and not refused(row + ",345", snapshot)
    figure = "1," + ",".join(["23"] * 50) + ",456"  # 104 digits: a figure that starts its row is read whole.
    assert refused(figure, _snapshot(tmp_path, figure.replace(",", ""), name="long.txt"))


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
