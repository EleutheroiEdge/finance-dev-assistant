"""An unquoted comma file cuts a grouped amount into cells, and those cells may hold more than one amount: under
`Account,Quantity,Cost`, `SYN-1,12,345,678.90` holds 12 and 345,678.90 as well as one amount. Every amount the cut
cells may hold is listed, up to a bounded run; an amount inside a quoted field is in one cell. Synthetic only."""

import csv
from decimal import Decimal
import io
import random
import time

import pytest

from conftest import command
from test_figure_source_formats import _refused, _source
from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration

from finassist import figure_sources
from finassist.errors import AssistantError
from finassist.figure_sources import (_MAX_RUN_PIECES, SOURCE_RULE, _cell_readings, _cut_runs, _quoted_spans,
                                      _run_readings)
from finassist.forbidden_tokens import load_token_snapshot

# The reader's own tests: figure sources are not available in this release, so they turn them on, as only
# code can.
pytestmark = pytest.mark.usefixtures("sources_available")

HEAD, TAIL = "Account,Quantity,Cost\n", "SYN-2,15,98.7654\n"


def _snapshot(tmp_path, text, **rules):
    return load_token_snapshot({"forbidden_token_sources": [_source(tmp_path, text)], **rules}, ())


@pytest.mark.parametrize("amount,runs", [
    ("12,345,678.90", ["12345", "345678.90"]),
    ("1,674,123,456.78", ["1674", "1674123", "674123", "674123456.78", "123456.78"]),
    ("1,234", []),
    ("1,234,567.89e2", ["1234", "234567.89e2"]),
], ids=["three-pieces", "four-pieces", "two-pieces", "exponent"])
def test_every_shorter_run_of_cut_pieces_is_read(amount, runs):
    assert sorted(_cut_runs(amount)) == sorted(runs)


def test_a_run_is_read_as_the_cell_reader_reads_it():
    rng = random.Random(20261114)
    for _ in range(3000):
        pieces = [str(rng.randrange(1, 1000))] + [f"{rng.randrange(1000):03d}" for _ in range(rng.randrange(1, 9))]
        tail = rng.choice(("", "", ".5", ".00", ".1250", "e2", ".75e-3", "E+04"))
        for piece_run in _cut_runs(",".join(pieces) + tail):
            assert _run_readings(piece_run) == _cell_readings(piece_run), piece_run


def _long(pieces, tail=".90"):
    return ",".join(["345"] + ["678"] * (pieces - 1)) + tail


def test_an_amount_cut_into_the_most_cells_lists_every_run(tmp_path):
    assert len(_cut_runs(_long(_MAX_RUN_PIECES))) == sum(range(2, _MAX_RUN_PIECES))
    snapshot = _snapshot(tmp_path, HEAD + "SYN-1,12," + _long(_MAX_RUN_PIECES - 1) + "\n" + TAIL)
    for value in ("345678678678678678.90", "12345678678678678678.90", "678678678678678.90"):
        assert _refused(value, snapshot), value


@pytest.mark.parametrize("cells,tail", [(_MAX_RUN_PIECES + 1, ".90"), (_MAX_RUN_PIECES + 2, ".90"),
                                        (_MAX_RUN_PIECES + 1, ".90e-18"), (40, ".25")],
                         ids=["one-more", "two-more", "scaled", "forty"])
@pytest.mark.parametrize("declared", [False, True], ids=["automatic", "declared"])
def test_an_amount_cut_into_more_cells_refuses_the_file_never_a_part_of_it(tmp_path, cells, tail, declared):
    path = tmp_path / "lots.csv"
    path.write_text(HEAD + "SYN-1," + _long(cells, tail) + "\n" + TAIL, encoding="utf-8", newline="")
    entry = {"path": str(path), "delimiter": ",", "decimal_mark": "."} if declared else str(path)
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        load_token_snapshot({"forbidden_token_sources": [entry]}, ())


def test_a_quoted_amount_of_many_groups_is_one_cell_and_reads(tmp_path):
    snapshot = _snapshot(tmp_path, HEAD + 'SYN-1,12,"' + _long(_MAX_RUN_PIECES + 2) + '"\n' + TAIL)
    assert _refused("345678678678678678678678678.90", snapshot)


@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("declared", [False, True], ids=["automatic", "declared"])
@pytest.mark.parametrize("quoted", [False, True], ids=["cut", "quoted"])
@pytest.mark.parametrize("pieces,exponent", [(6, 0), (7, 0), (8, 0), (8, -18)],
                         ids=["six", "seven", "eight", "eight-scaled"])
def test_a_long_cut_cost_never_reaches_a_request(gate_case, tmp_path, match, declared, quoted, pieces,  # noqa: F811
                                                 exponent):
    amount = _long(pieces) + (f"e{exponent}" if exponent else "")
    source = tmp_path / "synthetic.csv"
    source.write_text(HEAD + "SYN-1,12," + (f'"{amount}"' if quoted else amount) + "\n" + TAIL, encoding="utf-8")
    entry = {"path": str(source), "delimiter": ",", "decimal_mark": "."} if declared else str(source)
    change_policy(gate_case, forbidden_token_sources=[entry], forbidden_token_source_rule=SOURCE_RULE,
                  forbidden_token_match=match)
    value = format(Decimal(amount.replace(",", "")), "f")
    (gate_case["repo"] / "src/cash.py").write_text(f"def balance():\n    return {value}  # synthetic\n",
                                                   encoding="utf-8", newline="\n")
    command(gate_case["repo"], "commit", "-q", "-am", "Synthetic change writing a long cut cost")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and report["spend"]["reserved_usd"] is None
    refused_whole = not quoted and 1 + pieces > _MAX_RUN_PIECES  # the quantity's cell and the cost's
    expected = "forbidden_token_source_invalid" if refused_whole else "forbidden_token_present"
    # A bare path is read every way, which no policy reaches: refused before any source is read.
    assert report["reasons"] == [expected if declared else "forbidden_token_source_layout_required"]


@pytest.mark.parametrize("text,expected", [
    ('"1,234,567.89"', True), ('a,"1,234,567.89",b', True), ('a,"1,234,567.89"\r\nb', True),
    ('a,"Total 1,234,567.89",b', True), ('a,"1,234,567.89""",b', True), ('a,"x\n1,234,567.89",b', True),
    ('a,"unclosed 1,234,567.89', True), ('ab"1,234,567.89",b', False), ('a, "1,234,567.89",b', False),
    ('a,"b"c,1,234,567.89', False), ("a,1,234,567.89,b", False),
], ids=["alone", "between-commas", "line-end", "text-cell", "doubled-quote", "multi-line", "unclosed",
        "quote-mid-field", "space-before-quote", "after-a-closed-field", "unquoted"])
def test_an_amount_inside_a_quoted_field_is_found_as_the_csv_reader_quotes(text, expected):
    start = text.index("1,234")
    assert any(first <= start < last for first, last in _quoted_spans(text)) is expected


def test_quoted_spans_agree_with_the_csv_reader_on_every_comma():
    rng, checked = random.Random(20261114), 0
    for _ in range(4000):
        text = "".join(rng.choice('a1,, ""\n\r') for _ in range(rng.randrange(1, 30)))
        try:
            rows = list(csv.reader(io.StringIO(text, newline="")))
        except csv.Error:
            continue
        spans = _quoted_spans(text)
        breaks = sum(char == "," and not any(first <= index < last for first, last in spans)
                     for index, char in enumerate(text))
        assert breaks == sum(len(row) - 1 for row in rows if row), repr(text)
        checked += 1
    assert checked > 3000


@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("text,held", [
    (HEAD + "SYN-1,12,345,678.90\n" + TAIL, ["345678.90", "12345", "12345678.90"]),
    (HEAD + "SYN-1,674,123,456.78\n" + TAIL, ["123456.78", "674123456.78"]),
    ("Account,Quantity,Cost per share,Basis\nSYN-1,674,123,456.7800,83,207,870.40\n", ["123456.78", "83207870.40"]),
    (HEAD + 'Pipe 5",12,345,678.90\n' + TAIL, ["345678.90", "12345678.90"]),
], ids=["quantity-then-cost", "account-quantity-cost", "two-amounts", "stray-quote"])
def test_an_amount_cut_after_a_small_number_is_listed(tmp_path, match, text, held):
    snapshot = _snapshot(tmp_path, text, forbidden_token_match=match)
    for value in held:
        assert _refused(value, snapshot), value


@pytest.mark.parametrize("declared", [False, True], ids=["automatic", "declared"])
@pytest.mark.parametrize("row,held,not_held", [
    ("SYN-1,-12,345,678.90", ["345678.90", "-345678.90", "12345678.90"], []),
    ("SYN-1,12,-345,678.90", ["345678.90"], ["12345678.90"]),
    ("SYN-1,0,345,678.90", ["345678.90"], []),
    ("SYN-1,7,000,123.45", ["7000123.45", "123.45"], ["123.4"]),
    ("SYN-1,12,345,678.90e2", ["34567890", "1234567890"], ["345678.90"]),
    ('SYN-1,"12",345,678.90', ["345678.90"], ["12345678.90"]),
    ('SYN-1,12,"345,678.90"', ["345678.90"], ["12345", "12345678.90"]),
    ('SYN-1,12,345,"678.90"', ["12345"], ["345678.90"]),
    ('SYN-1,12,"Cost 345,678.90"', ["345678.90"], ["45678.90"]),
], ids=["sign-before", "sign-inside", "zero-quantity", "zero-group", "exponent", "quoted-quantity", "quoted-cost",
        "quoted-tail", "quoted-text"])
def test_signs_zeros_exponents_and_quotes_around_cut_cells(tmp_path, declared, row, held, not_held):
    path = tmp_path / "lots.csv"
    path.write_text(HEAD + row + "\n" + TAIL, encoding="utf-8", newline="")
    entry = {"path": str(path), "delimiter": ",", "decimal_mark": "."} if declared else str(path)
    snapshot = load_token_snapshot({"forbidden_token_sources": [entry]}, ())
    for value in held:
        assert _refused(value, snapshot), value
    for value in not_held:
        assert not _refused(value, snapshot), value


def test_a_wrong_group_whose_last_piece_is_a_figure_refuses_the_source(tmp_path):
    # No reading fits: the comma reading's row is wider than its header, and 789.01 glued to the line rules the
    # others out. With .00 the last piece is no figure, and a one-cell reading lists `3456,789.00` as written.
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _snapshot(tmp_path, HEAD + "SYN-1,12,3456,789.01\n" + TAIL)
    written = _snapshot(tmp_path, HEAD + "SYN-1,12,3456,789.00\n")
    assert _refused("3456,789.00", written)


@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("rows,layout", [
    ("SYN-1,12,345,678.90\nSYN-9,1.2.3\n", None),
    ("SYN-1,12,345,678.90\n", (";", ".")),
    ("SYN-1,12,345,678.90\nSYN-9,1.2.3\n", (None, ".")),
], ids=["a-cell-elsewhere-rules-the-comma-reading-out", "declared-semicolon", "declared-one-column"])
def test_the_cut_cells_amounts_are_listed_whichever_reading_is_the_files(tmp_path, match, rows, layout):
    path = tmp_path / "lots.csv"
    path.write_text(HEAD + rows, encoding="utf-8", newline="")
    entry = str(path) if layout is None else {"path": str(path), "delimiter": layout[0], "decimal_mark": layout[1]}
    snapshot = load_token_snapshot({"forbidden_token_sources": [entry], "forbidden_token_match": match}, ())
    for value in ("12345", "345678.90"):
        assert _refused(value, snapshot), value


@pytest.mark.parametrize("layout", [None, (";", ".")], ids=["automatic", "declared-semicolon"])
def test_an_amount_cut_into_more_cells_refuses_the_file_whatever_else_it_holds(tmp_path, layout):
    path = tmp_path / "lots.csv"
    path.write_text(HEAD + "SYN-1,12,345,678,901,234,567,890,123.40\nSYN-9,1.2.3\n", encoding="utf-8", newline="")
    entry = str(path) if layout is None else {"path": str(path), "delimiter": layout[0], "decimal_mark": layout[1]}
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        load_token_snapshot({"forbidden_token_sources": [entry]}, ())


@pytest.mark.alone
def test_a_cell_of_many_numbers_is_read_in_time():
    raw = ("x " + "1 " * 20_000 + "\n").encode("utf-8")
    start = time.perf_counter()
    figure_sources._source_figures(raw, 5)
    assert time.perf_counter() - start < 20  # a scan of every span against every other took about 95 s


def test_a_quoted_amount_is_one_cell_and_lists_no_shorter_run(tmp_path):
    quoted = _snapshot(tmp_path, 'Account,Cost,Note\nSYN-1,"1,234,567.89","USD 6,729,102.50"\nSYN-2,"98,765.4321",x\n')
    assert _refused("1234567.89", quoted) and _refused("98765.4321", quoted) and _refused("6729102.50", quoted)
    assert not _refused("234567.89", quoted) and not _refused("729102.50", quoted)
    unquoted = _snapshot(tmp_path, "Account,Cost\nSYN-1,1,234,567.89\nSYN-2,98,765.4321\n")
    assert _refused("234567.89", unquoted)  # cut, it may be 1 and 234,567.89


@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("declared,quoted,reason", [
    (False, False, "forbidden_token_source_layout_required"), (True, False, "forbidden_token_present"),
    (False, True, "forbidden_token_source_layout_required"), (True, True, "forbidden_token_present"),
], ids=["automatic", "declared", "quoted", "declared-quoted"])
def test_a_change_writing_the_cut_cost_stops_the_gate_before_any_request(gate_case, tmp_path, match, declared,  # noqa: F811
                                                                        quoted, reason):
    source = tmp_path / "synthetic.csv"
    source.write_text(HEAD + ('SYN-1,12,"345,678.90"' if quoted else "SYN-1,12,345,678.90") + "\n", encoding="utf-8")
    entry = {"path": str(source), "delimiter": ",", "decimal_mark": "."} if declared else str(source)
    change_policy(gate_case, forbidden_token_sources=[entry], forbidden_token_source_rule=SOURCE_RULE,
                  forbidden_token_match=match)
    (gate_case["repo"] / "src/cash.py").write_text("def balance():\n    return 345678.90  # synthetic\n",
                                                   encoding="utf-8", newline="\n")
    command(gate_case["repo"], "commit", "-q", "-am", "Synthetic change writing a cut cost")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and report["reasons"] == [reason]
    assert report["spend"]["reserved_usd"] is None


def test_a_round_figure_cut_after_a_small_number_is_listed_under_list_only(tmp_path):
    text = HEAD + "SYN-1,674,225,900.0000\n" + TAIL
    assert _refused("225900", _snapshot(tmp_path, text, **{"forbidden_token_round_figures": "list"}))
    assert not _refused("225900", _snapshot(tmp_path, text))
    with pytest.raises(AssistantError, match="^forbidden_token_round_figures_invalid$"):
        _snapshot(tmp_path, text, **{"forbidden_token_round_figures": "lists"})
