"""Find characters that a reviewer cannot see, or that change the order a line is shown in.

A person reads what is displayed and a model reads code points. Text that looks the same and is
not the same lets a change say one thing to its reviewer and another to the model, and lets
instructions travel where nobody looks. This module names the characters that do that.

The list is fixed data, so the answer is the same on every Python version: it does not ask the
interpreter's Unicode tables what a character is.
"""

from __future__ import annotations

import re

from .errors import AssistantError
from .path_alias_data import DEFAULT_IGNORABLE_RANGES

# Unicode calls a character default-ignorable when it is shown as nothing at all. Three kinds are
# allowed because ordinary text needs them, each only where that text puts it.
_SELECTORS = ((0xFE00, 0xFE0F),)  # variation selectors: emoji and text presentation
_JOINERS = ((0x200C, 0x200D),)  # zero width non-joiner and joiner: joined scripts and emoji sequences
_MARKS = ((0x061C, 0x061C), (0x200E, 0x200F))  # direction marks: right-to-left prose
_PLACED = (*_SELECTORS, *_JOINERS, *_MARKS)
# Controls other than tab, line feed, form feed and carriage return. NUL is not here: text that
# holds one is refused as binary input.
_CONTROLS = ((0x01, 0x08), (0x0B, 0x0B), (0x0E, 0x1F), (0x7F, 0x9F))
# Format characters that are not default-ignorable and are not shown either: interlinear
# annotation marks and Egyptian hieroglyph format controls. The format characters that print,
# such as the Arabic number signs, are left alone.
_NOT_SHOWN = ((0xFFF9, 0xFFFB), (0x13430, 0x1343F))
_BIDIRECTIONAL = ((0x202A, 0x202E), (0x2066, 0x2069))  # embedding, override, isolate and their ends
_TAGS = ((0xE0000, 0xE007F),)
# Scripts written right to left, by block. The Arabic letter mark is a mark, not a letter.
_RIGHT_TO_LEFT = ((0x0590, 0x061B), (0x061D, 0x08FF), (0xFB1D, 0xFDFF), (0xFE70, 0xFEFC), (0x10800, 0x10FFF),
                  (0x1E800, 0x1EFFF))
_KEYCAP = 0x20E3  # the box a digit, # or * is drawn in, after its selector
BYTE_ORDER_MARK = chr(0xFEFF)
NAMED_LINES = 20  # line numbers a refusal names in local output


def _without(ranges, holes):
    """The ranges with every hole cut out of them, merged and in order."""
    kept = []
    for first, last in ranges:
        pieces = [(first, last)]
        for hole_first, hole_last in holes:
            cut = []
            for start, end in pieces:
                if hole_last < start or hole_first > end:
                    cut.append((start, end))
                    continue
                if start < hole_first:
                    cut.append((start, hole_first - 1))
                if hole_last < end:
                    cut.append((hole_last + 1, end))
            pieces = cut
        kept.extend(pieces)
    merged: list[tuple[int, int]] = []
    for first, last in sorted(kept):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(last, merged[-1][1]))
        else:
            merged.append((first, last))
    return tuple(merged)


def _members(ranges) -> str:
    return "".join("\\U%08x-\\U%08x" % pair for pair in ranges)


def _within(code: int, ranges) -> bool:
    return any(first <= code <= last for first, last in ranges)


# Never allowed, wherever they stand.
HIDDEN_RANGES = _without((*DEFAULT_IGNORABLE_RANGES, *_CONTROLS, *_NOT_SHOWN), _PLACED)
# Allowed in their place only.
PLACED_RANGES = _without(_PLACED, ())

_HIDDEN = "[" + _members(HIDDEN_RANGES) + "]"
_SELECTOR = "[" + _members(_SELECTORS) + "]"
_JOINER = "[" + _members(_JOINERS) + "]"
# A character a reader sees that is not plain ASCII: what a selector varies and a joiner joins.
_SEEN = "[^\\x00-\\x7f" + _members((*HIDDEN_RANGES, *PLACED_RANGES)) + "]"
_SEEN_OR_SELECTOR = "[^\\x00-\\x7f" + _members((*HIDDEN_RANGES, *_JOINERS, *_MARKS)) + "]"
# One pass finds every character that breaks a rule except a direction mark, which is judged by
# its line. The pattern begins with one character class, so text that holds none is passed over
# at the speed of a search.
_BROKEN = re.compile(
    "[" + _members((*HIDDEN_RANGES, *_SELECTORS, *_JOINERS)) + "](?:"
    "(?<=" + _HIDDEN + ")"
    # A selector changes how the character before it is drawn. After a letter of plain ASCII it
    # draws nothing and makes a different word; a digit, # or * takes one only in a keycap.
    "|(?<=" + _SELECTOR + ")(?<!" + _SEEN + _SELECTOR + ")(?:(?<![0-9#*]" + _SELECTOR + ")|(?!\\U%08x))" % _KEYCAP +
    # Joined scripts and emoji sequences put a joiner after one of their own characters, or after
    # its selector. Inside a word of plain ASCII it makes a different word.
    "|(?<=" + _JOINER + ")(?<!" + _SEEN_OR_SELECTOR + _JOINER + ")"
    ")")
_MARK = re.compile("[" + _members(_MARKS) + "]")
_RIGHT_TO_LEFT_LETTER = re.compile("[" + _members(_RIGHT_TO_LEFT) + "]")


def _rule(character: str) -> str:
    code = ord(character)
    if character == BYTE_ORDER_MARK:
        return "byte_order_mark"
    if _within(code, _BIDIRECTIONAL):
        return "bidirectional_control"
    if _within(code, _TAGS):
        return "tag_character"
    if _within(code, _CONTROLS):
        return "control_character"
    if _within(code, _SELECTORS):
        return "misplaced_selector"
    return "misplaced_joiner" if _within(code, _JOINERS) else "invisible_character"


def _line_end(text: str, position: int) -> int:
    end = text.find("\n", position)
    return len(text) if end < 0 else end


def hidden(text: str, *, file: bool = False) -> tuple[str, list[int]] | None:
    """The first rule broken and the lines that break one: at most one more line than a refusal names.

    `file` is for the whole content of a file, which some editors begin with a byte order mark.
    Anywhere else that mark is a zero-width space. The work is linear in the text: a line that
    breaks a rule is not read again, and a line of direction marks is judged once.
    """
    broken: list[tuple[int, str]] = []  # where a line first breaks a rule, and the rule
    position = 0
    while len(broken) <= NAMED_LINES:
        found = _BROKEN.search(text, position)
        if found is None:
            break
        position = found.start()
        if file and position == 0 and found.group() == BYTE_ORDER_MARK:
            position = 1
            continue
        broken.append((position, _rule(found.group())))
        position = _line_end(text, position)
    # A direction mark belongs to a line that holds right-to-left text.
    position, marks = 0, 0
    while marks <= NAMED_LINES:
        found = _MARK.search(text, position)
        if found is None:
            break
        start = text.rfind("\n", 0, found.start()) + 1
        position = _line_end(text, found.start())
        if _RIGHT_TO_LEFT_LETTER.search(text, start, position) is None:
            broken.append((found.start(), "misplaced_direction_mark"))
            marks += 1
    if not broken:
        return None
    broken.sort()
    lines: list[int] = []
    line, counted = 1, 0
    for place, _name in broken:
        line += text.count("\n", counted, place)
        counted = place
        if not lines or lines[-1] != line:
            lines.append(line)
    return broken[0][1], lines[:NAMED_LINES + 1]


def check_hidden(text: str, *, file: bool = False) -> None:
    """Refuse text that holds a hidden or reordering character.

    The refusal names the rule and the lines for local output. It never holds the characters.
    """
    found = hidden(text, file=file)
    if found is None:
        return
    rule, lines = found
    error = AssistantError("hidden_characters")
    error.local_details["rule"] = rule
    error.local_details["lines"] = lines[:NAMED_LINES]
    if len(lines) > NAMED_LINES:
        error.local_details["more_lines"] = True
    raise error


def check_hidden_document(value, *, file_lines: bool = False) -> None:
    """Refuse a hidden character in any string of a JSON-shaped value, keys included.

    `file_lines` is for a request, whose strings include lines taken from files: the first line
    of a file may begin with a byte order mark, so a string there may too.
    """
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if hidden(item, file=file_lines) is not None:
                raise AssistantError("hidden_characters")
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
