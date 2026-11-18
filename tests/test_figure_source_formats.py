"""Figure sources in the formats custody exports come in: every amount is listed as it is, or the source is refused.

Exports that separate columns with semicolons and write amounts with decimal commas used to be split on the comma
when commas outnumbered semicolons, which listed fragments of the amounts and left the amounts themselves unscreened.
Synthetic exports only.
"""

import random

import pytest

from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration

from finassist.errors import AssistantError
from finassist.figure_sources import SOURCE_RULE
from finassist.forbidden_tokens import TokenSnapshot, load_token_snapshot, screen_text


def _source(tmp_path, text: str) -> str:
    path = tmp_path / "exports" / "positions.csv"
    path.parent.mkdir(exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return str(path)


def _snapshot(source: str) -> TokenSnapshot:
    return load_token_snapshot({"forbidden_token_sources": [source]}, ())


def _refused(text: str, snapshot: TokenSnapshot) -> bool:
    try:
        screen_text(text, snapshot)
    except AssistantError as exc:
        assert exc.code == "forbidden_token_present", exc.code
        return True
    return False


@pytest.mark.parametrize("text,amounts", [
    ("Betrag;Saldo\n1.234,56;98.765,43\n2.345,67;87.654,32\n", ["1234.56", "98765.43", "2345.67", "87654.32"]),
    ("Betrag;Saldo\n12.345,67;98.765,43\n23.456,78;87.654,32\n", ["12345.67", "98765.43", "23456.78", "87654.32"]),
    ("Datum;Betrag;Saldo\n02.01.2026;1.234,56;98.765,43\n", ["1234.56", "98765.43"]),
    ("Konto;Symbol;Menge;Kurs;Wert\nA1;XYZ;150;1.234,56;185.184,00\n", ["1234.56", "185184"]),
    ("Id,Note,Amount\n1,a;b;c,12345.67\n2,d;e;f,98765.43\n", ["12345.67", "98765.43"]),
    ("Date,Amount,Balance\n2026-01-02,1234.56,98765.43\n2026-01-03,2345.67,87654.32\nTotal,3580.23\n",
     ["1234.56", "98765.43", "2345.67", "87654.32", "3580.23"]),
    ("Datum\tBetrag\tSaldo\n02.01.2026\t1.234,56\t98.765,43\n", ["1234.56", "98765.43"]),
    ("12.345,67;98.765,43\n23.456,78;87.654,32\n", ["12345.67", "98765.43", "23456.78", "87654.32"]),
    ("12.345,67;98.765,43\n", ["12345.67", "98765.43"]),
    ('Id,Note,Amount\n1,"first line\nsecond line",12345.67\n2,plain,98765.43\n', ["12345.67", "98765.43"]),
], ids=["semicolon-4", "semicolon-5", "semicolon-date", "semicolon-wide", "comma-text-semicolons", "comma-ragged", "tab",
        "headerless-semicolon", "headerless-one-row", "quoted-multiline"])
def test_every_amount_is_listed_as_it_is(tmp_path, text, amounts):
    snapshot = _snapshot(_source(tmp_path, text))
    for amount in amounts:
        assert _refused("value = " + amount, snapshot), amount


@pytest.mark.parametrize("text", ["Betrag\n12.345,67\n98.765,43\n", "12.345,67\n98.765,43\n"],
                         ids=["header", "no-header"])
def test_a_comma_split_that_cuts_decimal_comma_amounts_is_refused(tmp_path, text):
    # One column: splitting on the comma would list 12345 and 12.345; neither is the amount 12345.67.
    with pytest.raises(AssistantError, match="^forbidden_token_source_ambiguous$"):
        _snapshot(_source(tmp_path, text))


def test_a_format_that_changes_beyond_the_first_lines_is_not_read(tmp_path):
    # The whole file is read with each delimiter, not only its first 8 KiB: comma rows, then semicolon rows with
    # decimal commas, leave a fragment under every reading, so the source is refused rather than read in part.
    rows = ["Konto,Symbol,Wert"] + [f"SYN{n:04d},FUND,{n}2345.67" for n in range(1, 400)]
    rows += [f"{n}2.345,67;9{n}.765,43" for n in range(1, 20)]
    text = "\n".join(rows) + "\n"
    assert len(text.encode()) > 9000
    with pytest.raises(AssistantError, match="^forbidden_token_source_invalid$"):
        _snapshot(_source(tmp_path, text))


def test_the_parse_cache_depends_on_the_digit_minimum(tmp_path):
    # A source's figures depend on the digit minimum as well as its bytes: a cache keyed by bytes alone would reuse
    # a parse made under another minimum.
    source = _source(tmp_path, "Name,Small,Large\nSYN,123456,987654321\n")
    parsed = {}
    five = load_token_snapshot({"forbidden_token_sources": [source], "forbidden_token_min_digits": 5}, (), parsed)
    eight = load_token_snapshot({"forbidden_token_sources": [source], "forbidden_token_min_digits": 8}, (), parsed)
    assert _refused("123456", five) and _refused("987654321", five)
    assert not _refused("123456", eight) and _refused("987654321", eight)


def test_a_source_that_could_be_read_more_than_one_way_stops_the_gate_before_any_request(gate_case, tmp_path):  # noqa: F811
    source = _source(tmp_path, "Betrag\n12.345,67\n98.765,43\n")
    change_policy(gate_case, forbidden_token_sources=[source], forbidden_token_source_rule=SOURCE_RULE)
    report, calls = run(gate_case)
    # Read every way it is ambiguous; a policy can't ask for that reading, so it names the layout it needs.
    assert not calls and report["verdict"] == "BLOCKED"
    assert report["reasons"] == ["forbidden_token_source_layout_required"]
    assert report["outcome_class"] == "incomplete"  # a setup to fix, not a rule the change broke
    assert report["spend"]["reserved_usd"] is None  # refused before any budget is reserved


def test_a_comma_file_with_an_occasional_point_grouped_price_is_still_read(tmp_path):
    # One row in ten holds a three-place price beside a two-digit quantity, which reads like a cut amount; the file
    # is a comma file all the same, and is not refused.
    rows = ["Symbol,Price,Quantity,Value"] + [f"SYN{n},{n}0.25,{n}00,{n}2345.67" for n in range(1, 10)]
    rows.append("SYN10,1.234,56,69.10")
    snapshot = _snapshot(_source(tmp_path, "\n".join(rows) + "\n"))
    assert _refused("12345.67", snapshot) and _refused("92345.67", snapshot)


@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("declared", [False, True], ids=["read-every-way", "declared"])
@pytest.mark.parametrize("convention", ["decimal-comma", "decimal-point"])
def test_a_thousand_row_export_lists_every_amount_in_either_convention(tmp_path, convention, declared, match):
    generator = random.Random(20261113)
    amounts = [generator.randrange(1_000_000, 99_999_999) for _ in range(1000)]  # cents: 10,000.00 to 999,999.99
    rows = ["Konto;Symbol;Wert;Kosten" if convention == "decimal-comma" else "Account,Symbol,Value,Cost"]
    for index, cents in enumerate(amounts):
        whole, fraction = divmod(cents, 100)
        if convention == "decimal-comma":
            grouped = f"{whole:,}".replace(",", ".")
            rows.append(f"SYN{index:04d};FUND;{grouped},{fraction:02d};{grouped},{fraction:02d}")
        else:
            rows.append(f"SYN{index:04d},FUND,{whole}.{fraction:02d},{whole}.{fraction:02d}")
    source = _source(tmp_path, "\n".join(rows) + "\n")
    delimiter, mark = (";", ",") if convention == "decimal-comma" else (",", ".")
    entry = {"path": source, "delimiter": delimiter, "decimal_mark": mark} if declared else source
    snapshot = load_token_snapshot({"forbidden_token_sources": [entry], "forbidden_token_match": match}, ())
    swapped = str.maketrans(",.", ".,")
    figures = {cents for cents in amounts if len(str(cents).strip("0")) >= 5}
    assert snapshot.source_figures == len(figures)  # a round amount, such as 347300.00, has too few digits
    for cents in figures:
        whole, fraction = divmod(cents, 100)
        for spelling in (f"{whole}.{fraction:02d}", f"{whole:,}.{fraction:02d}",
                         f"{whole:,}.{fraction:02d}".translate(swapped)):
            assert _refused(f"total = {spelling}", snapshot), spelling
        # The same digits at another scale: refused when digits are matched, and no listed value otherwise.
        assert _refused(f"total = {cents}", snapshot) == (match == "digits")
