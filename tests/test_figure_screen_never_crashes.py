"""The screens answer every text with a pass or their own refusal, never another error.

Every figure and text here is made up.
"""

import hashlib
import random

import pytest

from finassist.errors import AssistantError
from finassist.forbidden_tokens import (TokenSnapshot, _spelled_out, load_token_snapshot, screen_lines,
                                        screen_source, screen_text)
from finassist.hidden_text import check_hidden, check_hidden_document
from finassist.python_source import python_tokens, python_tree
from finassist.security import check_text

BACKSLASH = chr(92)
SNAPSHOT = TokenSnapshot(frozenset({hashlib.sha256(b"48213.57").hexdigest()}))
REFUSALS = {"forbidden_token_present", "forbidden_token_python_unreadable"}


@pytest.mark.parametrize("escape", ["U00110000", "U7FFFFFFF", "U80000000", "UFFFFFFFF", "uD800", "xFF"])
def test_an_escape_that_is_no_character_is_read_as_text(escape):
    # Past the last code point chr() raises ValueError, or OverflowError before Python 3.13.
    text = BACKSLASH + escape + " total "
    screen_text(text + "1", SNAPSHOT)
    for path in (None, "notes.md", "module.py", "report.json"):
        with pytest.raises(AssistantError, match="^forbidden_token_present$"):
            screen_source(text + "48213.57", path, SNAPSHOT) if path else screen_text(text + "48213.57", SNAPSHOT)


PIECES = [
    "0", "1", "9", "48", "213", "57", "000", "48213.57", ".", ",", "_", " ", "'", "e", "E", "+", "-", "(", ")", "$",
    "%", BACKSLASH, BACKSLASH + "u", BACKSLASH + "U", BACKSLASH + "x", BACKSLASH + "N{", "00a0", "FFFFFFFF", "80000000",
    "0031", "D800", "&", "#", "x", ";", "nbsp", "&#", "&#x", "&#99999999999999999999;", "&#xFFFFFFFFF;",
    chr(0xFF11), chr(0x0661), chr(0xA0), chr(0x2009), chr(0x202E), chr(0), "\n", "\r", "\t", '"', "'''", "abc", "f",
    "a1", "= ", "def f():", "#", "[", "]", "{", "}", "0x", "0b", "0o", "1e", "1e999", "j", "rb'", "f'{", "}'",
    # Longer than Python will convert to an integer: 4,300 digits is the limit.
    "&#" + "9" * 5000 + ";", "&#x" + "F" * 5000, "&#" + "0" * 5000 + "49;", "9" * 5000, "0x" + "f" * 5000,
    # What the hidden-character screen reads: each kind it refuses, each it allows in its place, and what they stand beside.
    chr(0x200B), chr(0xFEFF), chr(0xE0041), chr(0x1B), chr(0x85), chr(0x3164), chr(0xFE0F), chr(0x200D), chr(0x200C),
    chr(0x200F), chr(0x061C), chr(0x05D0), chr(0x2764), chr(0x20E3), chr(0x1F468), chr(0xD800), chr(0x10FFFF),
]


@pytest.fixture(scope="module")
def by_digits(tmp_path_factory):
    """The same figure listed from a source file and matched by its digits."""
    source = tmp_path_factory.mktemp("figures") / "figures.csv"
    source.write_text("value\n48213.57\n", encoding="utf-8", newline="\n")
    return load_token_snapshot({"forbidden_token_sources": [str(source)], "forbidden_token_match": "digits"}, ())


@pytest.mark.parametrize("seed", range(8))
def test_random_text_gets_a_pass_or_a_refusal_never_another_error(seed, by_digits):
    generator = random.Random(20261111 + seed)
    for _ in range(150):
        text = "".join(generator.choice(PIECES) for _ in range(generator.randrange(1, 48)))
        for path in (None, "notes.md", "module.py", "report.json", "page.html"):
            for snapshot in (SNAPSHOT, by_digits):
                try:
                    screen_source(text, path, snapshot) if path else screen_text(text, snapshot)
                except AssistantError as refusal:
                    assert refusal.code in REFUSALS, (refusal.code, path)
                try:  # Related-context lines have their own tokenizer boundary.
                    screen_lines(text.splitlines(), path, snapshot)
                except AssistantError as refusal:
                    assert refusal.code in REFUSALS, (refusal.code, path)
            try:  # The credential screen reads the same text first, on every route.
                check_text(text, source_path=path)
            except AssistantError:
                pass
            for file in (False, True):
                try:  # And the hidden-character screen reads it last, as a file and as any other text.
                    check_hidden(text, file=file)
                except AssistantError as refusal:
                    assert refusal.code == "hidden_characters" and set(refusal.local_details) <= {"rule", "lines", "more_lines"}
        try:
            check_hidden_document({text: [text, {"nested": (text, 1, None)}]})
        except AssistantError as refusal:
            assert refusal.code == "hidden_characters" and not refusal.local_details


def test_a_nul_character_after_an_open_string_is_not_python_on_any_version():
    # CPython 3.12's tokenizer raises SystemError here, where other versions raise SyntaxError.
    text = "TOTAL = '''" + chr(0) + "= 1"
    assert python_tokens(text) is None and python_tree(text) is None
    with pytest.raises(AssistantError, match="^forbidden_token_python_unreadable$"):
        screen_source(text, "module.py", SNAPSHOT)
    with pytest.raises(AssistantError):
        check_text(text, source_path="module.py")


LONG = ["&#" + "9" * 5000 + ";", "&#x" + "F" * 5000 + ";", "&#" + "9" * 5000, "&#" + "0" * 5000 + "32;",
        "&#x" + "0" * 5000 + "20;"]


@pytest.mark.parametrize("entity", LONG)
@pytest.mark.parametrize("figure", ["48213.57", "48&nbsp;213.57", "48&#32;213.57", "48" + BACKSLASH + "u00a0213.57",
                                    "48&#" + "0" * 5000 + "32;213.57"])
def test_a_number_too_long_to_convert_never_hides_a_figure_beside_it(entity, figure):
    # html.unescape converts a numeric reference with int(), which refuses more than 4,300 digits.
    # A reference with no semicolon takes in any digits that follow it, so the figure stands apart.
    for text in (entity + " total " + figure, figure + " " + entity, entity + " " + figure + " " + entity):
        with pytest.raises(AssistantError, match="^forbidden_token_present$"):
            screen_text(text, SNAPSHOT)
        with pytest.raises(AssistantError, match="^forbidden_token_present$"):
            screen_source(text, "page.html", SNAPSHOT)
    screen_text(entity + " total 1", SNAPSHOT)


def test_a_long_reference_reads_as_the_character_it_names_or_as_none():
    assert _spelled_out("&#" + "0" * 5000 + "49;&#x" + "0" * 5000 + "32;") == "12"
    assert _spelled_out("a&#" + "9" * 5000 + ";b") == "a" + chr(0xFFFD) + "b"
    assert _spelled_out("a&#x" + "F" * 5000 + ";b") == "a" + chr(0xFFFD) + "b"
    assert _spelled_out("&#x;&#;&#xZ;") is None  # Not references: left as written.
    # The longest numbers that are still code points are converted, not treated as too long.
    assert _spelled_out("&#1114109;&#x10FFFD;&#128512;") == chr(0x10FFFD) * 2 + chr(0x1F600)
