"""The screens answer every text with a pass or their own refusal, never another error.

Every figure and text here is made up.
"""

import hashlib
import random

import pytest

from finassist.errors import AssistantError
from finassist.forbidden_tokens import TokenSnapshot, screen_source, screen_text
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
]


@pytest.mark.parametrize("seed", range(8))
def test_random_text_gets_a_pass_or_a_refusal_never_another_error(seed):
    generator = random.Random(20261111 + seed)
    for _ in range(600):
        text = "".join(generator.choice(PIECES) for _ in range(generator.randrange(1, 48)))
        for path in (None, "notes.md", "module.py", "report.json", "page.html"):
            try:
                screen_source(text, path, SNAPSHOT) if path else screen_text(text, SNAPSHOT)
            except AssistantError as refusal:
                assert refusal.code in REFUSALS, (refusal.code, path)
            try:  # The credential screen reads the same text first, on every route.
                check_text(text, source_path=path)
            except AssistantError:
                pass


def test_a_nul_character_after_an_open_string_is_not_python_on_any_version():
    # CPython 3.12's tokenizer raises SystemError here, where other versions raise SyntaxError.
    text = "TOTAL = '''" + chr(0) + "= 1"
    assert python_tokens(text) is None and python_tree(text) is None
    with pytest.raises(AssistantError, match="^forbidden_token_python_unreadable$"):
        screen_source(text, "module.py", SNAPSHOT)
    with pytest.raises(AssistantError):
        check_text(text, source_path="module.py")
