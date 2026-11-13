"""The figure tests' helper: a number is found, also after an escaped currency sign or a currency code; its digits
inside a hash or an identifier are not."""

import json

import pytest

from conftest import holds_number
from finassist.security import canonical

# The hash in which a hosted run found the seven digits by chance (Windows, Python 3.12).
COLLIDED = "cb63d5f096b407ae16cf97b82a533ccff2163dc05d672910287177f61d932b2d"
EVENTS = [
    {"seq": 1, "previous": "0" * 64, "payload": {"event": "usage_settled"}, "hash": COLLIDED},
    {"seq": 2, "previous": COLLIDED, "payload": {"event": "command_finished"}, "hash": "1" * 64},
]


@pytest.mark.parametrize("text,expected", [
    ('{"claim": "Fictional value 6729102.50"}', True),
    ("approx(6729102.50)", True),
    (" 6729102 ", True),
    ("$6729102", True),
    ("6729102", True),
    (canonical({"amount": 6729102.5}).decode(), True),
    (canonical({"claim": "\u00a36729102.50"}).decode(), True),
    (canonical({"claim": "\u20ac6729102.50"}).decode(), True),
    (json.dumps({"claim": "\u00a36729102.50"}), True),
    (json.dumps(json.dumps({"claim": "\u00a36729102.50"})), True),
    (repr({"claim": "\u00a36729102.50"}), True),
    (canonical({"claim": "USD6729102.50"}).decode(), True),
    (canonical({"claim": "CAD6729102.50"}).decode(), True),
    (canonical({"claim": "CHF6729102.50"}).decode(), True),
    (canonical({"note": COLLIDED + " 6729102"}).decode(), True),
    (canonical({"path": "patches/" + COLLIDED + "6729102"}).decode(), True),
    (canonical(EVENTS).decode(), False),
    (canonical({"run_id": "0f1e2d3c4b5a6729102a9b8c7d6e5f40"}).decode(), False),
    (canonical({"id": "0f1e2d3c-4b5a-4a7b-9c0d-a6729102b3c4"}).decode(), False),
    (canonical({"container": "finassist-0f1e2d3c4b5a6729102a9b8c7d6e5f40"}).decode(), False),
    ('{"at": 17945267291023}', False),
    ("16729102", False),
    ("", False),
])
def test_holds_number_finds_the_number_and_not_digits_inside_a_hash(text, expected):
    assert holds_number(text, "6729102") is expected


def test_the_hosted_collision_holds_the_digits_only_inside_the_hash():
    text = canonical(EVENTS).decode()
    assert "6729102" in text and text.count("6729102") == text.count(COLLIDED)
