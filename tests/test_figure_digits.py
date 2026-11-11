"""Digit matching and figure sources for the confidential-figure screen.

Every figure, file and repository here is synthetic.
"""

from dataclasses import replace
import hashlib
import random
import re

import pytest

from conftest import command
from figure_cases import SURROUNDINGS, _framed
from finassist.config import Config, load_config
from finassist.config_preflight import config_preflight
from finassist.errors import AssistantError
from finassist import forbidden_tokens
from finassist.forbidden_tokens import (MAX_SOURCE_FILES, TokenGuard, TokenSnapshot, load_token_snapshot,
                                        screen_source, screen_text, token_file_audit)
from finassist.scope import build_packet
from test_model_gate import change_policy, run

pytest_plugins = ("test_model_gate", "test_model_policy")

DIGITS = {"forbidden_token_match": "digits"}
CUSTODY = (
    "account,description,market_value,price,quantity,as_of,reference\n"
    '"SYN-0001","Synthetic Fund A","1,234,567.89",48213.5712,7.5,20261110,00012345\n'
    '"SYN-0002","Synthetic Fund B","(905.13)",$73026.00,250000,2026-11-10,"USD 6,729,102.50"\n'
)


@pytest.fixture
def custody(tmp_path):
    path = tmp_path / "custody" / "positions.csv"
    path.parent.mkdir()
    path.write_text(CUSTODY, encoding="utf-8", newline="\n")
    return str(path)


def _snapshot(source: str, match: str = "digits", **rules) -> TokenSnapshot:
    return load_token_snapshot({"forbidden_token_sources": [source], "forbidden_token_match": match, **rules}, ())


def _refused(text: str, snapshot: TokenSnapshot, path: str | None = None) -> bool:
    try:
        screen_source(text, path, snapshot) if path else screen_text(text, snapshot)
    except AssistantError as exc:
        assert exc.code == "forbidden_token_present", exc.code
        return True
    return False


def test_a_source_lists_every_numeric_cell_that_is_a_figure(custody):
    snapshot = _snapshot(custody)
    # 1234567.89, 48213.5712, 905.13, 73026, 6729102.5 and 12345: dates, text, 7.5 and 250000 are not figures.
    assert snapshot.source_figures == snapshot.listed == 6 and not snapshot.hashes
    assert len(_snapshot(custody, match="value").hashes) == 6
    assert snapshot.digit_lengths == {5, 7, 8, 9}  # 482135712 and its rounding 4821357 among them
    assert token_file_audit(snapshot) == {"event": "forbidden_token_file_screened", "file_path": None,
                                          "line_count": 0, "source_files": 1, "source_figures": 6}


@pytest.mark.parametrize("text", [
    "48213.5712", "48,213.5712", "48_213.5712",      # the value, in any notation
    "48213.57", "$48,213.57", "(48 213,57)",         # its two-place rounding
    "4821357", "0.4821357", "48.21357", "482135712e-4",  # the same digits at another scale
    "total 905.13 due", "905.125", "905.134",        # a longer decimal that rounds to a listed figure
    "x = 123456789", "1.23456789M",                  # 1,234,567.89 scaled
    "id_12345", "A12345", "12345x",                  # glued to letters
])
def test_digit_matching_refuses_the_same_digits_however_scaled_or_rounded(custody, text):
    assert _refused(text, _snapshot(custody))


@pytest.mark.parametrize("text", [
    "48213.58", "4821358", "482135713",              # another figure
    "905.135", "905.124",                            # rounds to another figure
    "20261110", "2026-11-10",                        # a date column is not listed
    "7.5", "75", "250000", "25",                     # too few significant digits
    "commit a1b2c12345f", "sha 0012345abcdef",       # digits inside a hexadecimal word
    "1234", "123456",                                # part of a listed row, not the row
])
def test_digit_matching_passes_other_numbers(custody, text):
    assert not _refused(text, _snapshot(custody))


def test_a_source_cell_with_an_exponent_or_a_leading_point_is_listed(tmp_path):
    # One ordinary cell beside each notation: a figure that was left out must not hide behind another.
    path = tmp_path / "mixed.csv"
    path.write_text("value\n48213.57\n1.23456789e6\n.4821399\n9.0513E+02\n6729102500e-3\n$ .7302604\n",
                    encoding="utf-8", newline="\n")
    listed = ("48213.57", "1234567.89", "0.4821399", "905.13", "6729102.5", "0.7302604")
    for match in ("digits", "value"):
        snapshot = _snapshot(str(path), match=match)
        assert snapshot.source_figures == len(listed)
        for value in listed:
            assert _refused("total " + value + " due", snapshot), (match, value)
    # A leading point is a fraction: the cell is not also listed as the whole number its digits spell.
    assert not _refused("4821399", _snapshot(str(path), match="value"))
    # An exponent too large to be a figure is not one, and the other cells still load.
    path.write_text("value\n48213.57\n123456e678\n", encoding="utf-8", newline="\n")
    assert _snapshot(str(path)).source_figures == 1


@pytest.mark.parametrize("text", [
    "9.05125e2", "905125e-3", "0.905125E3", "90512.5e-2", "9.05134e+2",  # 905.125 and 905.134 round to 905.13
    '{"market_value": 9.05125e2}', "total 0.0905125e4 due",
])
def test_a_number_with_an_exponent_is_rounded_as_its_value(custody, text):
    snapshot = _snapshot(custody)
    assert _refused(text, snapshot)
    assert _refused(text, snapshot, "notes.md") and _refused(text, snapshot, "report.json")


@pytest.mark.parametrize("text", ["9.05124e2", "9.05135e2", "905124e-3", "9.05136e2", "0.905124E3"])
def test_an_exponent_number_that_rounds_elsewhere_passes(custody, text):
    snapshot = _snapshot(custody)
    assert not _refused(text, snapshot) and not _refused(text, snapshot, "report.json")


def test_digit_matching_scans_each_word_once(custody, monkeypatch):
    """A word of many digit runs is examined once, not once a run: the work stays linear in the text."""
    class Counting(frozenset):
        calls = 0

        def __contains__(self, item):
            Counting.calls += 1
            return frozenset.__contains__(self, item)

    monkeypatch.setattr(forbidden_tokens, "_WORD", Counting(forbidden_tokens._WORD))
    text = "a1" * 20_000 + " " + "9f8e7d6c5b4a" * 2_000 + " x" + "7_" * 5_000
    assert not _refused(text, _snapshot(custody))
    assert 0 < Counting.calls <= 4 * len(text)


def test_value_matching_with_a_source_refuses_the_value_but_not_its_scalings(custody):
    snapshot = _snapshot(custody, match="value")
    assert not snapshot.digit_hashes
    assert _refused("(1 234 567,89)", snapshot) and _refused("48213.5712", snapshot)
    assert not _refused("48213.57", snapshot) and not _refused("123456789", snapshot)


def test_python_literals_are_matched_by_digits_too(custody):
    snapshot = _snapshot(custody)
    assert _refused("CENTS = 0x%X\n" % 4821357, snapshot, "src/cash.py")  # 4821357 as a hexadecimal literal
    assert _refused("TOTAL = 1_234_567.89e3\n", snapshot, "src/cash.py")
    assert not _refused("TOTAL = 0x%X\n" % 4821358, snapshot, "src/cash.py")


def test_the_minimum_number_of_digits_is_a_setting(custody):
    assert _refused("90513", _snapshot(custody))
    strict = _snapshot(custody, forbidden_token_min_digits=7)
    assert not _refused("90513", strict) and not _refused("905.13", strict) and _refused("4821357", strict)


def test_a_semicolon_file_with_decimal_commas_is_read(tmp_path):
    path = tmp_path / "export.csv"
    path.write_text("name;value;other\nSynthetic;48.213,57;1.234.567,89\n", encoding="utf-8", newline="\n")
    snapshot = _snapshot(str(path))
    assert _refused("48213.57", snapshot) and _refused("1,234,567.89", snapshot) and _refused("4821357", snapshot)


def test_a_list_file_gains_digit_forms_when_matching_by_digits(tmp_path):
    path = tmp_path / "figures.txt"
    path.write_text("48213.5712\n", encoding="utf-8", newline="\n")
    by_value = load_token_snapshot({"forbidden_token_file": str(path)}, ())
    by_digits = load_token_snapshot({"forbidden_token_file": str(path), "forbidden_token_match": "digits"}, ())
    assert not _refused("48,213.57", by_value) and _refused("48,213.57", by_digits)
    assert by_value != by_digits  # A recheck under another rule is another screen.


@pytest.mark.parametrize("rules", [
    {"forbidden_token_match": "fuzzy"}, {"forbidden_token_min_digits": 3}, {"forbidden_token_min_digits": 19},
    {"forbidden_token_min_digits": "5"}, {"forbidden_token_min_digits": True},
])
def test_invalid_matching_settings_are_refused(custody, rules):
    with pytest.raises(AssistantError, match="^forbidden_token_match_invalid$"):
        load_token_snapshot({"forbidden_token_sources": [custody], **rules}, ())


def test_unusable_sources_are_refused(custody, tmp_path, repository):
    repo, _base, _head = repository
    empty = tmp_path / "words.csv"
    empty.write_text("name,note\nSynthetic,none\n", encoding="utf-8", newline="\n")
    inside = repo / "positions.csv"
    inside.write_text(CUSTODY, encoding="utf-8", newline="\n")
    for sources, roots in [([str(empty)], ()), ([str(tmp_path / "missing.csv")], ()), (["relative.csv"], ()),
                           ([custody, custody], ()), ([str(inside)], (repo,)),
                           ([custody] * 0 + [f"{custody}{n}" for n in range(MAX_SOURCE_FILES + 1)], ()), ([7], ())]:
        with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
            load_token_snapshot({"forbidden_token_sources": sources}, roots)


def test_a_source_may_be_given_relative_to_the_home_directory(custody, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert _refused("48213.57", _snapshot("~/custody/positions.csv"))


def test_a_guard_parses_an_unchanged_source_once_and_refuses_a_changed_one(custody, monkeypatch):
    parses, real = [], forbidden_tokens._source_figures
    monkeypatch.setattr(forbidden_tokens, "_source_figures", lambda raw, minimum: parses.append(1) or real(raw, minimum))
    guard = TokenGuard.load({"forbidden_token_sources": [custody], **DIGITS}, ())
    for _ in range(3):
        guard.recheck({"files": []}, "synthetic instructions")
    assert len(parses) == 1
    with open(custody, "a", encoding="utf-8", newline="\n") as handle:
        handle.write('"SYN-0003","Synthetic Fund C",31415.92,1.00,3,2026-11-10,7\n')
    with pytest.raises(AssistantError, match="^forbidden_token_configuration_changed$"):
        guard.recheck({"files": []}, "synthetic instructions")


def test_plan_and_doctor_use_sources_and_digit_matching(repository, custody):
    repo, base, _head = repository
    (repo / "src/cash.py").write_text("OPENING = 48_213.57  # rounded\n", encoding="utf-8", newline="\n")
    command(repo, "commit", "-q", "-am", "Synthetic change with a rounded figure")
    head = command(repo, "rev-parse", "HEAD")
    config = replace(Config(), forbidden_token_sources=(custody,), **DIGITS)
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        build_packet(repo, base, head, config)
    assert build_packet(repo, base, head, replace(config, **{"forbidden_token_match": "value"}))["files"]
    report = config_preflight(repo, base, head, config)
    assert report["figure_screen"] == {"configured": True, "listed": 6, "match": "digits", "digit_forms": 7}
    assert [item["code"] for item in report["blockers"]] == ["forbidden_token_present"]
    loaded = load_config(content=('{"forbidden_token_sources": ["%s"], "forbidden_token_match": "digits", '
                                  '"forbidden_token_min_digits": 6}' % custody.replace("\\", "/")).encode())
    assert loaded.forbidden_token_rules["forbidden_token_min_digits"] == 6


def test_a_gate_uses_sources_and_digit_matching(gate_case, custody):
    change_policy(gate_case, forbidden_token_sources=[custody], **DIGITS)
    (gate_case["repo"] / "src/cash.py").write_text("OPENING = 4821357  # cents\n", encoding="utf-8", newline="\n")
    command(gate_case["repo"], "commit", "-q", "-am", "Synthetic change with a rescaled figure")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["forbidden_token_present"] and not calls


# --- Against a baseline guard --------------------------------------------------------------------
# A guard of the common kind: it lists the significant digits of every numeric cell and of its
# two-place rounding, five digits or more, and compares them with the same forms of every plain or
# comma-grouped number in a payload. Whatever that guard refuses, this screen must refuse too.

_BASELINE_NUMBER = re.compile(r"\d[\d,]*(?:\.\d+)?")


def _baseline_forms(token: str) -> set[str]:
    plain = token.replace(",", "")
    whole, _, fraction = plain.partition(".")
    forms = {(whole + fraction).strip("0")}
    if fraction.strip("0"):
        cents = int(whole + fraction[:2].ljust(2, "0")) + (len(fraction) > 2 and fraction[2] >= "5")
        forms.add(str(cents).strip("0"))
    return {form for form in forms if len(form) >= 5}


def _baseline_refuses(text: str, listed: set[str]) -> bool:
    for match in _BASELINE_NUMBER.finditer(text):
        token = match.group().rstrip(",")
        parts = [token] if re.fullmatch(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?", token) else token.split(",")
        if any(_baseline_forms(part) & listed for part in parts if part):
            return True
    return False


def _written(generator: random.Random, value: str) -> str:
    whole, _, fraction = value.partition(".")
    grouped = f"{int(whole):,}" + ("." + fraction if fraction else "")
    scaled = str(int(whole + fraction)) if fraction else whole + "00"
    choices = [value, grouped, "$" + grouped, "(" + grouped + ")", grouped + "%", "-" + value, scaled,
               "%s.%s" % (whole, (fraction + "00")[:2]), "0." + (whole + fraction).lstrip("0")]
    return generator.choice(choices)


def test_whatever_a_baseline_guard_refuses_this_screen_refuses(tmp_path):
    generator = random.Random(20261110)
    frames = [frame for frame in SURROUNDINGS.values() if frame.count("{}") == 1]
    escapes, both = [], 0
    for batch in range(40):
        values = ["%d.%s" % (generator.randrange(1000, 10**generator.randrange(5, 10)),
                             "".join(generator.choice("0123456789") for _ in range(generator.randrange(0, 5)))
                             ) for _ in range(25)]
        values = [value.rstrip(".") for value in values]
        path = tmp_path / f"custody-{batch}.csv"
        path.write_text("value\n" + "".join(f'"{value}"\n' for value in values), encoding="utf-8", newline="\n")
        listed = set().union(*(_baseline_forms(value) for value in values))
        snapshot = _snapshot(str(path))
        for _ in range(250):
            value = generator.choice(values)
            # Half the payloads hold a listed value, written some way; half hold a nearby number.
            shown = _written(generator, value) if generator.random() < 0.5 else str(int(value.partition(".")[0]) + generator.randrange(1, 9))
            text = _framed(generator.choice(frames), shown)
            baseline, ours = _baseline_refuses(text, listed), _refused(text, snapshot)
            both += baseline and ours
            if baseline and not ours:
                escapes.append(hashlib.sha256(text.encode()).hexdigest()[:8])
    assert not escapes, f"{len(escapes)} payloads the baseline refuses pass here"
    assert both > 2_000
