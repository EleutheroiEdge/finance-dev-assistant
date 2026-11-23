"""Later starts after a grouping point, quoted fields that no comma cuts, Indian groups in a record's width, and the
figures one read of a source may list.

Every figure, file and name here is synthetic.
"""

from pathlib import Path
import random
import subprocess
import sys
import time

import pytest

import finassist
from finassist import figure_sources
from finassist.errors import AssistantError
from finassist.forbidden_tokens import load_token_snapshot, screen_text


def _listed(text: str) -> set[str]:
    return figure_sources._source_figures(text.encode("utf-8"), 5)[0]


def _screened(tmp_path, text: str, payload: str) -> str:
    path = tmp_path / "positions.csv"
    path.write_text(text, encoding="utf-8", newline="")
    snapshot = load_token_snapshot({"forbidden_token_sources": [str(path)]}, ())
    try:
        screen_text(payload, snapshot)
    except AssistantError as error:
        return error.code
    return "passed"


GAPS = pytest.mark.parametrize("gap", [".", " ", "'"], ids=["points", "spaces", "apostrophes"])


@GAPS
def test_each_later_start_of_a_cut_decimal_comma_amount_is_listed_whatever_groups_it(gap):
    # The screen reads 222.333.444,56 in `1.222.333.444,56` as it does 222 333 444,56 in `1 222 333 444,56`.
    row = gap.join(["1", "222", "333", "444"]) + ",56"
    assert {"1222333444.56", "222333444.56", "333444.56", "444.56"} <= _listed(f"X,{row}\n")


@GAPS
def test_a_change_writing_a_later_start_of_a_cut_amount_is_refused(tmp_path, gap):
    row = gap.join(["1", "222", "333", "444"]) + ",56"
    payload = "total " + gap.join(["222", "333", "444"]) + ",56 due"
    assert _screened(tmp_path, f"X,{row}\n", payload) == "forbidden_token_present"


@GAPS
def test_a_later_start_is_read_up_to_nine_groups_and_one_of_more_refuses_the_source(gap):
    nine = gap.join(["1", "111", "222", "333", "444", "555", "666", "777", "888", "999"]) + ",56"
    assert "111222333444555666777888999.56" in _listed(f"X,{nine}\n")
    ten = gap.join(["1", "111", "222", "333", "444", "555", "666", "777", "888", "999", "000"]) + ",56"
    with pytest.raises(ValueError, match="past what is read from a later start"):
        _listed(f"X,{ten}\n")


@pytest.mark.parametrize("cell,value", [
    ('"(2.104.963,90) EUR"', "2104963.9"),
    ('"EUR 1 234 567,89"', "1234567.89"),
    ('"7 111 222 333 444 555 666 777 888 999 000,56"', "7111222333444555666777888999000.56"),
], ids=["point-groups", "space-groups", "eleven-groups"])
def test_a_quoted_field_is_one_cell_and_lists_its_one_number(cell, value):
    # No comma cut the amount inside the quotes, so it has no later start, and a long one refuses nothing.
    assert _listed(f"Account,Value,Type\nAccount W,{cell},IRA\n") == {value}


def test_a_decimal_comma_inside_a_quoted_field_is_passed_over_and_one_outside_is_not():
    text = 'A,B\n"1.222.333,44",1.222.333,44\n'
    quoted = figure_sources._quoted_spans(text)
    assert list(figure_sources._decimal_comma_cuts(text, quoted=quoted)) == ["1.222.333,44", "222.333,44", "333,44"]
    assert len(list(figure_sources._decimal_comma_cuts(text))) == 6  # without the quoted fields, both rows are cuts


@pytest.mark.parametrize("amount,piece", [("31,41,592.65", "592.65"), ("1,234,567.89", "567.89")],
                         ids=["indian", "western"])
@pytest.mark.parametrize("account", ["SYN-0001", "SYN-1", "SYN-A"])
def test_an_unquoted_amount_beside_an_account_is_listed_whole_and_in_pieces_or_refused(account, amount, piece):
    # Under a two-cell header, the comma groups count as one cell of the row, Indian ones too: the comma reading is
    # kept, and its cells, as the last piece, are listed, or the readings disagree and the source is refused.
    try:
        listed = _listed(f"account,mv\n{account},{amount}\n")
    except ValueError:
        return
    assert {amount.replace(",", ""), piece} <= listed


@pytest.mark.parametrize("row,width", [
    (["SYN-0001", "31", "41", "592.65"], 2),
    (["SYN", "12", "34", "56", "789.01"], 2),
    (["Balance carried forward 60", "927", "718.98"], 1),
    (["SYN", "12", "34", "5"], 4),  # groups of two that no group of three ends are no amount
    (["SYN", "12", "345", "67"], 3),
], ids=["indian", "longer-indian", "western", "no-end", "western-then-two"])
def test_a_record_counts_an_amount_that_comma_groups_cut_as_one_cell(row, width):
    assert figure_sources._record_width(row) == width


def test_a_record_of_many_two_digit_cells_is_counted_in_one_pass():
    row = ["SYN", *["12"] * 50_000, "345.67"]
    assert figure_sources._record_width(row) == 2


def _figure_rows(count: int) -> str:
    generator = random.Random(20261114)
    return "".join(f"abcde {' '.join(str(generator.randrange(100, 1000)) for _ in range(9))},"
                   f"{generator.randrange(10, 99)}\n" for _ in range(count))


def test_a_read_stops_as_soon_as_a_reading_lists_more_figures_than_a_snapshot_holds(monkeypatch):
    monkeypatch.setattr(figure_sources, "MAX_SOURCE_FIGURES", 1_000)
    calls = []
    read_cell = figure_sources._read_cell
    monkeypatch.setattr(figure_sources, "_read_cell", lambda cell: calls.append(cell) or read_cell(cell))
    text = _figure_rows(2_000)
    with pytest.raises(ValueError, match="more figures than one snapshot holds"):
        _listed(text)
    # The first reading stops within its first few dozen rows of some forty figures each: no other reading starts.
    assert len(calls) < 200, len(calls)


def test_a_source_within_the_limit_is_read_whole(monkeypatch):
    monkeypatch.setattr(figure_sources, "MAX_SOURCE_FIGURES", 1_000)
    text = "".join(f"SYN-{number:04d};{10_000 + 7 * number},25\n" for number in range(900))
    assert len(_listed("Konto;Betrag\n" + text)) == 900


def _positions(rows: int) -> str:
    generator = random.Random(20261115)
    return "".join(f'SYN-{n:06d},USD,{generator.randrange(1, 9999)},"{generator.randrange(10**6, 10**9):,}.'
                   f'{generator.randrange(100):02d}"\n' for n in range(rows))


def test_the_one_column_check_lists_nothing_and_so_is_never_refused_for_how_many_it_holds(monkeypatch):
    # A custody export whose comma reading lists one amount a row is read whole under the limit, although the line
    # cells of the one-column check, which lists nothing, hold several numbers each.
    monkeypatch.setattr(figure_sources, "MAX_SOURCE_FIGURES", 1_000)
    text = _positions(600)
    held = set().union(*(figure_sources._inner_numbers(line, 5, round_figures=True)[0] for line in text.splitlines()))
    assert len(held) > 1_000  # what the line cells of the one-column check hold together
    assert len(_listed(text)) == 600


def test_the_one_column_check_stops_reading_figures_once_it_holds_one(monkeypatch):
    # It only needs to know whether the source holds a figure, so its line cells' numbers are read once, not per line.
    calls = []
    inner_numbers = figure_sources._inner_numbers
    monkeypatch.setattr(figure_sources, "_inner_numbers",
                        lambda text, *rest, **settings: calls.append(text) or inner_numbers(text, *rest, **settings))
    assert len(_listed(_positions(300))) == 300
    lines = [text for text in calls if "," in text]  # the check's cells are whole lines; the comma reading's hold none
    assert len(lines) < 10, len(lines)


def test_the_one_column_check_still_finds_a_leading_decimal_comma(monkeypatch):
    monkeypatch.setattr(figure_sources, "MAX_SOURCE_FIGURES", 1_000)
    with pytest.raises(figure_sources.UnscreenableSource):
        _listed("Betrag\n0,12345\nCash dividend,57891 units\n")


def test_round_figures_count_against_the_limit_only_where_they_are_listed(monkeypatch):
    # Under skip, the default, round figures are neither listed nor kept, so a source of more of them than one snapshot
    # holds lists its other figures; under list the same source is refused.
    monkeypatch.setattr(figure_sources, "MAX_SOURCE_FIGURES", 1_000)
    rounds = [f"{significant}0" for significant in range(1001, 2400) if significant % 10]
    assert len(rounds) > 1_000 and all(figure_sources._round_figure(value, "", 5) for value in rounds)
    raw = ("".join(f"{value}\n" for value in rounds) + "12345.67\n").encode()
    assert figure_sources._source_figures(raw, 5) == ({"12345.67"}, figure_sources._source_figures(b"12345.67\n", 5)[1],
                                                       set())
    with pytest.raises(ValueError, match="more figures than one snapshot holds"):
        figure_sources._source_figures(raw, 5, None, True)
    few = ("".join(f"{value}\n" for value in rounds[:10]) + "12345.67\n").encode()
    assert figure_sources._source_figures(few, 5, None, True)[2] == set(rounds[:10])  # listed under list


@pytest.mark.parametrize("line", ["{}", "Note {} held", "a,{},b"], ids=["cells", "text-cells", "cut-amounts"])
def test_each_path_counts_round_figures_only_where_they_are_listed(monkeypatch, line):
    # Line cells, a text cell's numbers (`_inner_numbers`) and amounts a comma cut (`_cut_cell_figures`): under skip
    # none of them counts a round figure against the limit, and under list each does.
    monkeypatch.setattr(figure_sources, "MAX_SOURCE_FIGURES", 1_000)
    values = [f"{significant}0" for significant in range(1001, 2400) if significant % 10]
    if line == "a,{},b":
        values = [f"{value[:-3]},{value[-3:]}" for value in values]  # 10,010: cut into two cells by the comma
    raw = ("".join(line.format(value) + "\n" for value in values) + "12345.67\n").encode()
    assert figure_sources._source_figures(raw, 5)[0] == {"12345.67"}
    with pytest.raises(ValueError, match="more figures than one snapshot holds"):
        figure_sources._source_figures(raw, 5, None, True)


def test_one_text_cell_of_round_figures_counts_against_the_limit_only_where_they_are_listed(monkeypatch):
    # The one-column check reads that cell too, to its first number only, so under skip nothing counts it.
    monkeypatch.setattr(figure_sources, "MAX_SOURCE_FIGURES", 1_000)
    values = [f"{significant}0" for significant in range(1001, 2400) if significant % 10]
    raw = ("Note " + " / ".join(values) + " held\n12345.67\n").encode()
    assert figure_sources._source_figures(raw, 5)[0] == {"12345.67"}
    with pytest.raises(ValueError, match="more figures than one snapshot holds"):
        figure_sources._source_figures(raw, 5, None, True)


def test_the_one_column_check_stops_at_a_round_figure_too(monkeypatch):
    calls = []
    inner_numbers = figure_sources._inner_numbers
    monkeypatch.setattr(figure_sources, "_inner_numbers", lambda text, *rest, **settings: calls.append(
        settings.get("first")) or inner_numbers(text, *rest, **settings))
    assert len(_listed("Note 347300 held\n" + _positions(300))) == 300
    assert calls.count(True) == 1  # its first text cell holds a round figure, which settles it


@pytest.mark.parametrize("module", ["figure_source_entries", "figure_sources", "forbidden_tokens", "config",
                                    "model_policy"])
def test_each_module_can_be_the_first_one_imported(module):
    # The source-entry module, the reader and the screen import one another in one direction only: no cycle. The
    # child imports the very package these tests import, from the folder it was loaded from, ahead of anything else on
    # its path, and checks that it did: never a stale installed copy, and never none.
    package = Path(next(iter(finassist.__path__))).resolve()
    code = (f"import sys; sys.path.insert(0, {str(package.parent)!r}); import finassist.{module} as loaded; "
            f"from pathlib import Path; "
            f"assert Path(loaded.__file__).resolve().is_relative_to({str(package)!r}), loaded.__file__")
    subprocess.run([sys.executable, "-c", code], check=True, timeout=60)


def test_the_helpers_find_round_figures_only_with_the_setting():
    assert figure_sources._inner_numbers("Note 10010 held", 5, round_figures=True)[2] == {"10010"}
    assert figure_sources._inner_numbers("Note 10010 held", 5, round_figures=False)[2] == set()
    assert figure_sources._cut_cell_figures("a,10,010,b\n", 5, round_figures=True)[2] == {"10010"}
    assert figure_sources._cut_cell_figures("a,10,010,b\n", 5, round_figures=False)[2] == set()
    with pytest.raises(TypeError):
        figure_sources._inner_numbers("Note 10010 held", 5)  # the setting is never assumed


def test_the_limit_counts_a_text_cells_own_figures_too(monkeypatch):
    monkeypatch.setattr(figure_sources, "MAX_SOURCE_FIGURES", 100)
    with pytest.raises(ValueError, match="more figures than one snapshot holds"):
        figure_sources._inner_numbers(" ".join(str(10_000 + number) for number in range(200)), 5, round_figures=True)


def test_a_line_longer_than_a_csv_field_may_be_refuses_the_source_before_any_cell_is_read(monkeypatch):
    calls = []
    read_cell = figure_sources._read_cell
    monkeypatch.setattr(figure_sources, "_read_cell", lambda cell: calls.append(cell) or read_cell(cell))
    with pytest.raises(ValueError, match="longer than a csv field may be"):
        _listed("Konto;Betrag\n" + "1," * 70_000 + "\n")
    assert not calls


def test_a_long_line_that_every_reading_splits_is_left_to_the_readings():
    line = ";\t|".join(["12345,67"] * 20_000)  # longer than a csv field, but no reading's field is
    try:
        _listed(line + "\n")
    except ValueError as error:
        assert "longer than a csv field may be" not in str(error)


def test_each_cell_and_cut_amount_is_classified_once_in_a_reading(monkeypatch):
    calls = []
    classify = figure_sources._classify
    monkeypatch.setattr(figure_sources, "_classify", lambda readings, *rest: calls.append(1) or classify(readings, *rest))
    _listed("1,2,3,4,5,6,7,8,9,10\n" * 1_000)
    # Ten distinct cells and nine distinct cut amounts, in each of the six readings: never once per line.
    assert len(calls) <= 6 * (10 + 9), len(calls)


def test_each_cell_of_a_source_is_read_once_however_many_readings_and_checks_share_it(monkeypatch):
    calls = []
    read_cell = figure_sources._read_cell
    monkeypatch.setattr(figure_sources, "_read_cell", lambda cell: calls.append(cell) or read_cell(cell))
    try:
        _listed("SYN-1,12,345,678.90\n" * 2_000)
    except ValueError:
        pass  # refused is as good as read here: what counts is how often each cell was read
    assert calls and len(calls) == len(set(calls))


@pytest.mark.parametrize("cell", ["x" + " " * 120_000 + "y", " " * 120_000 + "y)", "x" + " \t" * 60_000 + "[12"])
def test_a_long_run_of_spaces_in_a_cell_is_passed_over_in_one_pass(cell):
    # A footnote mark is looked for only from the start of a run of spaces, so the time grows with the cell, not
    # with its square: tried from every space of the run, a cell this long took most of a minute.
    began = time.monotonic()
    assert figure_sources._FOOTNOTE.sub("", cell) == cell
    assert time.monotonic() - began < 5


@pytest.mark.parametrize("cell, kept", [("1,234.56 1)", "1,234.56"), ("1,234.56  [12] ", "1,234.56"),
                                        ("1,234.56[3]", "1,234.56"), ("1,234.56 1234)", "1,234.56 1234)"),
                                        ("(1,234.56)", "(1,234.56)"), ("12 [1] [2]", "12 [1]")])
def test_a_footnote_mark_is_still_taken_off_the_end_of_a_cell(cell, kept):
    assert figure_sources._FOOTNOTE.sub("", cell) == kept
