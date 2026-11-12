"""The figure tests' helper: a number is found, its digits inside a hash, an identifier or a time stamp are not."""

import pytest

from conftest import holds_number


@pytest.mark.parametrize("text,expected", [
    ('{"claim": "Fictional value 6729102.50"}', True),
    ("approx(6729102.50)", True),
    (" 6729102 ", True),
    ("$6729102", True),
    ('{"hash": "a6729102f0"}', False),
    ('{"run": "16729102c4"}', False),
    ('{"at": 17945267291023}', False),
    ("", False),
])
def test_holds_number_finds_the_number_and_not_digits_inside_a_hash(text, expected):
    assert holds_number(text, "6729102") is expected
