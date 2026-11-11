"""The confidential-figure screen against generated cases: every notation, sign and surrounding.

Synthetic figures only. A failure prints a few labels, never a whole case list.
"""
import hashlib
import time

import pytest

from figure_cases import FIGURES, as_html, as_json, as_python, must_pass, must_refuse
from finassist.errors import AssistantError
from finassist.forbidden_tokens import TokenSnapshot, normalize_numeric_token, screen_source, screen_text


def _listing(figure: str) -> TokenSnapshot:
    return TokenSnapshot(frozenset({hashlib.sha256(normalize_numeric_token(figure).encode()).hexdigest()}))


LISTED = {figure: _listing(figure) for figure in FIGURES}
REFUSE, PASS = must_refuse(), must_pass()


def _refused(text: str, figure: str, path: str | None = None) -> bool:
    try:
        if path is None:
            screen_text(text, LISTED[figure])
        else:
            screen_source(text, path, LISTED[figure])
    except AssistantError as exc:
        assert exc.code == "forbidden_token_present", exc.code
        return True
    return False


def _labels(cases) -> str:
    return f"{len(cases)} cases, first: " + "; ".join(case.label for case in cases[:5])


def test_the_matrix_is_large_and_covers_every_axis():
    assert len(REFUSE) > 200_000 and len(PASS) > 5_000
    assert {case.figure for case in REFUSE} == set(FIGURES)


def test_every_notation_sign_and_surrounding_is_refused():
    missed = [case for case in REFUSE if not _refused(case.text, case.figure)]
    assert not missed, _labels(missed)


def test_near_misses_pass():
    alarms = [case for case in PASS if _refused(case.text, case.figure)]
    assert not alarms, _labels(alarms)


def test_the_same_cases_are_refused_inside_python_source():
    # Every fifth case: the stride shares no factor with the number of surroundings or
    # decorations, so every notation still meets every one of them.
    missed = []
    for case in REFUSE[::5]:
        for wrapper, source in as_python(case.text).items():
            if not _refused(source, case.figure, "src/module.py"):
                missed.append(f"{wrapper}: {case.label}")
    assert not missed, f"{len(missed)} cases, first: " + "; ".join(missed[:5])


def test_the_same_cases_are_refused_as_json_and_html_text():
    missed = [f"{kind}: {case.label}" for case in REFUSE[::3]
              for kind, path, text in (("json", "data/note.json", as_json(case.text)),
                                       ("html", "docs/page.html", as_html(case.text)))
              if not _refused(text, case.figure, path)]
    assert not missed, f"{len(missed)} cases, first: " + "; ".join(missed[:5])


def test_near_misses_pass_inside_python_json_and_html():
    alarms = []
    for case in PASS[::4]:
        for wrapper, source in as_python(case.text).items():
            # Two literals that split a near miss can show the listed figure itself in the source
            # text, as in `'9' '48213.57'`. Refusing that text is correct, so it is not counted.
            if wrapper != "joined literals" and _refused(source, case.figure, "src/module.py"):
                alarms.append(f"{wrapper}: {case.label}")
        if _refused(as_json(case.text), case.figure, "data/note.json") or _refused(as_html(case.text), case.figure):
            alarms.append(f"json or html: {case.label}")
    assert not alarms, f"{len(alarms)} cases, first: " + "; ".join(alarms[:5])


@pytest.mark.parametrize("text,refused", [
    ("73026.04", False),             # a listed whole number is not the whole part of another decimal
    ("1.73026", False),              # digits after a point are a fraction first
    ("v1.73,026", True),             # unless they carry their own groups
    ("973026", False),               # a longer run of digits is another number
    ("7,73026,9", True),             # number cells
    ("12 73 026", True),             # a grouped figure after another column
    ("73,026,000", True),            # over-read on purpose: the first two groups read as the figure
    ("\\u0037\\u0033026", True),     # digits spelled as escapes
    ("&#55;3026", True),             # and as character references
])
def test_documented_readings_of_a_whole_number(text, refused):
    assert _refused(text, "73026") is refused


@pytest.mark.alone
@pytest.mark.parametrize("text", [
    ",".join(["123"] * 400_000),                 # one row of three-digit groups, 1.6 MB
    "_".join(["7"] * 400_000),                   # one underscore-joined run
    "0." + "_".join(["12"] * 300_000),           # one long fraction
    " ".join(["1,234,567.89"] * 60_000),         # many grouped figures
    "1e2 " * 300_000,
    "0" * 1_500_000 + "5",
])
def test_dense_numeric_text_is_screened_in_bounded_time(text):
    started = time.perf_counter()
    assert not _refused(text, "48213.57")
    assert time.perf_counter() - started < 20
    assert _refused(text + " 48,213.57", "48213.57")
