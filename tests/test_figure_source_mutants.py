"""The seeded mutant script (scripts/figure_source_mutants.py) on a small fixed run, and proof that its checks catch
a reader that reads a damaged file or lists part of a figure. The long run is the script's own. Synthetic only."""

import importlib.util
from pathlib import Path
import re
import sys

import pytest

from test_figure_source_known_misses import CASES, LAYOUTS

from finassist import figure_sources
from finassist.figure_sources import SourceLayout

ROOT = Path(__file__).parents[1]
_SPEC = importlib.util.spec_from_file_location("figure_source_mutants", ROOT / "scripts" / "figure_source_mutants.py")
mutants = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = mutants  # dataclasses look their module up by name
_SPEC.loader.exec_module(mutants)

SEED, COUNT = 20261125, 10_000


@pytest.fixture(scope="module")
def counts():
    return mutants.run(SEED, COUNT)


def test_a_fixed_run_of_mutants_has_no_failure(counts):
    assert counts["failures"] == []
    assert counts["mutants"] == COUNT == counts["noise"] + counts["any"] == counts["refused"] + counts["read"]


def test_the_run_damages_files_in_every_way_and_reads_some_of_each_family(counts):
    assert set(counts["by_damage"]) == {damage.__name__ for damage in mutants.NOISE} | {"piled", "any"}
    assert all(sum(row) >= 400 for row in counts["by_damage"].values())
    # Most damage must refuse the file; some leaves a file that is still its layout's, and that one is read.
    assert 0.8 < counts["refused"] / COUNT < 0.97 and counts["noise_read"] > 300 and counts["read"] > 500
    assert counts["unchanged"] < COUNT // 50


def test_the_same_seed_makes_the_same_mutants():
    assert mutants.run(7, 400) == mutants.run(7, 400) != mutants.run(8, 400)


def test_the_script_runs_two_hundred_thousand_mutants_by_default():
    assert len(mutants.SEEDS) * mutants.MUTANTS_PER_SEED == 200_000 and SEED in mutants.SEEDS


def test_the_second_reader_agrees_with_the_reader_on_the_known_shapes():
    # The shapes an earlier reader listed in part, under a spread of layouts: refused by both, or read alike.
    for name, raw, _figures in CASES:
        for declared in LAYOUTS[::7]:
            case = mutants.Case(declared, "", False, set())
            assert mutants.check("any", case, raw)[1] is None, (name, tuple(declared))


def test_a_generated_file_holds_its_planted_amounts_in_declared_columns():
    generator = mutants.random.Random(3)
    for _ in range(200):
        case = mutants.generate(generator)
        assert figure_sources.layout_valid(case.layout) and case.planted and case.amounts
        assert mutants.check("noise", case, case.raw()) == ("read", None)
        for start, end, whole, fraction in case.amounts:
            assert re.sub("[^0-9]", "", case.text[start:end]) == whole + fraction


# --- The checks have teeth: each reader below is wrong in one way an earlier reader was. ---

def _run_with(monkeypatch, **changed):
    for name, value in changed.items():
        monkeypatch.setattr(mutants, name, value)
    return mutants.run(SEED, 1500)


def test_a_reader_that_drops_invisible_characters_is_caught(monkeypatch):
    real_amounts, real_read = mutants.source_amounts, mutants.read_source

    def strip(raw: bytes) -> bytes:
        for mark in ("\u200b", "\u200c", "\u200d", "\u2060", "\xad", "\u200e", "\u200f"):
            raw = raw.replace(mark.encode(), b"")
        return raw

    counts = _run_with(monkeypatch, source_amounts=lambda raw, declared: real_amounts(strip(raw), declared),
                       read_source=lambda raw, declared, *rest: real_read(strip(raw), declared, *rest))
    assert {failure["what"] for failure in counts["failures"]} == {"read a file the second reader refuses"}


def test_a_reader_that_reads_the_number_at_the_end_of_a_cell_is_caught(monkeypatch):
    # `98<mark>765.43`, `"98` then `765,43"` and `12345.67 1)` were each listed by their last number.
    real = figure_sources._amount
    tail = re.compile(r"[0-9]+(?:[.,][0-9]+)?(?=[^0-9]*$)")

    def lenient(cell, declared, line, column):
        try:
            return real(cell, declared, line, column)
        except figure_sources.CellSource:
            found = tail.search(cell)
            if found is None:
                raise
            return real(found.group(), declared, line, column)

    monkeypatch.setattr(figure_sources, "_amount", lenient)
    counts = mutants.run(SEED, 1500)
    assert "read a file the second reader refuses" in {failure["what"] for failure in counts["failures"]}
    assert len(counts["failures"]) >= 10


def test_a_reader_that_takes_a_quote_anywhere_is_caught(monkeypatch):
    real = figure_sources._cells

    def lenient(line, delimiter, number):  # quotes dropped wherever they stand, as a tolerant reader's did
        return real(line.replace('"', ""), delimiter, number)

    monkeypatch.setattr(figure_sources, "_cells", lenient)
    assert mutants.run(SEED, 1500)["failures"]


CASE = mutants.Case(SourceLayout(";", ",", ".", True, (1,)), "", False, {"98765.43"})


@pytest.mark.parametrize("listed,what", [
    ({"765.43"}, "listed an amount that is not a planted one"),
    ({"98765.43", "765.43"}, "listed an amount that is not a planted one"),
    (set(), "read the file and left a planted amount out"),
    ({"98765.43"}, None),
], ids=["a-part", "the-whole-and-a-part", "nothing", "the-whole"])
def test_the_planted_amounts_are_checked_even_where_both_readers_agree(monkeypatch, listed, what):
    # A flaw in the rules themselves would be shared by both readers: the planted amounts are checked apart from them.
    amounts = [(2, 2, value) for value in sorted(listed)]
    monkeypatch.setattr(mutants, "reference", lambda raw, declared: (amounts, [], set(), ""))
    monkeypatch.setattr(mutants, "source_amounts", lambda raw, declared: amounts)
    monkeypatch.setattr(mutants, "read_source", lambda raw, declared, minimum, rounds: (set(listed), set(), set()))
    raw = b'Konto;Betrag\nSYN-1; "98\n765,43"\n'
    assert mutants.check("noise", CASE, raw) == ("read", what)
    assert mutants.check("any", CASE, raw) == ("read", None)  # where a damage may make another honest file


def test_the_second_reader_refuses_to_lose_a_digit_of_a_cell(monkeypatch):
    monkeypatch.setattr(mutants, "_reference_amount", lambda cell, declared: ("765", "43") if "9" in cell else None)
    with pytest.raises(AssertionError, match="dropped a digit"):
        mutants.reference(b"Konto;Betrag\nSYN-1;98.765,43\n", CASE.layout)
