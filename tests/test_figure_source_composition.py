"""How a figure source is composed must never hide what its cells hold. Each file below holds a cost cut into cells
after a short quantity, under `Account,Quantity,Cost`, beside rows, exponents, layouts, quotes and encodings that
rule one reading or another out, or after a decimal quantity or a label, or a text cell holds an amount beside a
number that a longer reading runs into it. Whatever reading the file is read by, each amount its cells hold is
refused, or the whole source is. The values held are stated here, never taken from the parser. Synthetic only."""

import pytest

from conftest import command
from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration

from finassist.errors import AssistantError
from finassist.figure_sources import SOURCE_RULE
from finassist.forbidden_tokens import load_token_snapshot, screen_text

HEAD = "Account,Quantity,Cost\n"
CUT = "SYN-1,12,345,678.90\n"
FRAGMENT = "SYN-9,1.2.3\n"  # rules the comma reading out: 1.2.3 reads as no one number
HELD = ("345678.90", "12345", "12345678.90")  # 12 and 345,678.90; 12,345 and 678.90; or one amount
REFUSED_SOURCE = {"forbidden_token_source_invalid", "forbidden_token_source_ambiguous",
                  "forbidden_token_source_unscreenable"}

# (file text, layout declared or None, the amounts a reader can take the cut cells to hold)
COMPOSITIONS = {
    "plain": (HEAD + CUT, None, HELD),
    "fragment-row-after": (HEAD + CUT + "SYN-9,1.2.3\n", None, HELD),
    "fragment-row-before": (HEAD + "SYN-9,1.2.3\n" + CUT, None, HELD),
    "exponent-cell-elsewhere": (HEAD + CUT + "SYN-9,1e200\n", None, HELD),
    "exponent-on-the-amount-at-the-bound": (HEAD + "SYN-1,12,345,678.90e128\n", None, ("12345", "345678.90e128")),
    "exponent-on-the-amount-past-the-bound": (HEAD + "SYN-1,12,345,678.90e129\n", None, ("12345",)),
    "exponent-on-the-amount-far-past": (HEAD + "SYN-1,12,345,678.90e200\n", None, ("12345",)),
    "declared-comma": (HEAD + CUT, (",", "."), HELD),
    "declared-one-column": (HEAD + CUT + "SYN-9,1.2.3\n", (None, "."), HELD),
    "declared-semicolon": (HEAD + CUT, (";", "."), HELD),
    "declared-tab": (HEAD + CUT, ("\t", "."), HELD),
    "declared-bar-with-fragment": (HEAD + CUT + "SYN-9,1.2.3\n", ("|", "."), HELD),
    "quoted-cost": (HEAD + 'SYN-1,12,"345,678.90"\n' + "SYN-9,1.2.3\n", None, ("345678.90",)),
    "crlf": ((HEAD + CUT + "SYN-9,1.2.3\n").replace("\n", "\r\n"), None, HELD),
    "lone-cr": ((HEAD + CUT + "SYN-9,1.2.3\n").replace("\n", "\r"), None, HELD),
    # 1.5 and 345,678.90: no amount starts on the fraction's 5, and 5,345,678.90 must not hide the cost.
    "decimal-quantity-beside-a-fragment": (HEAD + "SYN-1,1.5,345,678.90\n" + FRAGMENT, None, ("345678.90",)),
    "longer-decimal-quantity": (HEAD + "SYN-1,12.5,345,678.90\n" + FRAGMENT, None, ("345678.90",)),
    "decimal-quantity-declared-semicolon": (HEAD + "SYN-1,1.5,345,678.90\n", (";", "."), ("345678.90",)),
    "decimal-quantity-declared-one-column": (HEAD + "SYN-1,1.5,345,678.90\n" + FRAGMENT, (None, "."), ("345678.90",)),
    "decimal-quantity-declared-comma": (HEAD + "SYN-1,1.5,345,678.90\n", (",", "."), ("345678.90",)),
    "seven-cell-cost-after-a-decimal-quantity": (HEAD + "SYN-1,1.5,345,678,901,234,567,890,123.40\n" + FRAGMENT, None,
                                                 ("345678901234567890123.40", "345678", "890123.40")),
    "label-before-the-cut": ("Rate:12,345,678.90\n" + FRAGMENT, None, ("345678.90", "12345", "12345678.90")),
    "label-before-the-cut-declared-comma": ("Rate:12,345,678.90\n", (",", "."), ("345678.90", "12345", "12345678.90")),
    "text-cell-after-a-decimal-semicolon": ("Account;Note\nSYN-1;Lot 1.5 345 678.90\n", None, ("345678.90",)),
    "text-cell-after-a-decimal-tab": ("Account\tNote\nSYN-1\tLot 1.5 345 678.90\n", None, ("345678.90",)),
    "text-cell-after-a-decimal-one-column": ("Note\nLot 1.5 345 678.90\n", None, ("345678.90",)),
    "text-cell-after-a-leading-point": ("Account;Note\nSYN-1;Lot .5 345 678.90\n", None, ("345678.90",)),
    "text-cell-after-a-glued-decimal": ("Account;Note\nSYN-1;Total1.5 345 678.90\n", None, ("345678.90",)),
    "text-cell-after-a-code-and-point": ("Account|Note\nSYN-1|USD .5 345 678.90\n", None, ("345678.90",)),
    "text-cell-with-no-break-spaces": ("Account;Note\nSYN-1;Lot 1.5 345\u00a0678.90\n", None, ("345678.90",)),
    "slash-before-the-cut": ("Ref A/12,345,678.90\n" + FRAGMENT, None, ("345678.90", "12345", "12345678.90")),
    "text-after-a-short-leading-comma": ("Note\nLot ,5 345 678.90\n", None, ("345678.90",)),
    # A mark glued to the cut's first cell, beside a cell that rules every reading out but the comma one.
    "letter-glued-before-the-cut": (HEAD + "SYN-1,x12,345,678.90\nSYN-2,99999.99,1\n1.2,3\n", None,
                                    ("12345678.90", "12345", "345678.90")),
    "letter-glued-before-the-cut-declared": (HEAD + "SYN-1,x12,345,678.90\nSYN-2,99999.99,1\n", (",", "."),
                                             ("12345678.90", "12345", "345678.90")),
    "two-letters-glued-before-the-cut": (HEAD + "SYN-1,ab12,345,678.90\n1.2,3\n", None, ("12345678.90", "12345")),
    "letter-glued-decimal-comma": (HEAD + "SYN-1,x1234567,89\n1.2,3\n", None, ("1234567.89",)),
    "letter-glued-decimal-comma-declared": (HEAD + "SYN-1,x1234567,89\nSYN-2,99999.99,1\n", (",", "."),
                                            ("1234567.89",)),
    "letter-glued-spaced-decimal-comma": (HEAD + "SYN-1,x1 234,56\n1.2,3\n", None, ("1234.56",)),
    "letter-glued-pointed-decimal-comma": (HEAD + "SYN-1,x1.234.567,89\n1.2,3\n", None, ("1234567.89",)),
    "letter-glued-apostrophe-decimal-comma": (HEAD + "SYN-1,x1'234'567,89\n1.2,3\n", None, ("1234567.89",)),
    # Numbers the screen reads up to MAX_FIGURE_DIGITS digits, and an exponent another spelling brings within 128.
    "a-129-digit-figure-in-text": ("Account;Note\nSYN-1;Total " + "9" * 129 + " EUR\nSYN-2;99999.99\n", None,
                                   ("9" * 129,)),
    "a-260-digit-figure-quoted": ('Account,Note\nSYN-1,"Total ' + "8" * 200 + "." + "7" * 60 + ' EUR"\nSYN-2,99999.99\n',
                                  None, ("8" * 200 + "." + "7" * 60,)),
    "exponent-past-the-bound-respelled": (HEAD + "SYN-1,12,345,678.90e129\n" + FRAGMENT, None,
                                          ("123456789e128", "12345678.90e129", "12345")),
    # Underscores, which the screen reads as joining digits, beside a row that leaves only the comma reading whole.
    "underscore-after-a-code-before-the-cut": (HEAD + "Alice,12345\nSYN-1,EUR_12,345,678.90\n", None,
                                               ("12345678.90",)),
    "underscore-joined-decimal-comma": (HEAD + "Alice,12345\nSYN-1,1_234,56\n", None, ("1234.56",)),
    "underscore-joined-decimals": (HEAD + "Alice,12345\nSYN-1,1234,5_6\n", None, ("1234.56",)),
    "underscore-glued-decimal-comma": (HEAD + "Alice,12345\nSYN-1,EUR_1234567,89\n", None, ("1234567.89",)),
    # Indian groups and currency signs.
    "indian-groups-in-a-cell": ("Account;Amount\nSYN-1;12,34,567.89\n", None, ("1234567.89", "12,34,567.89")),
    "indian-groups-quoted": ('Account,Amount\nSYN-1,"12,34,567.89"\n', None, ("1234567.89",)),
    "indian-groups-in-text": ("Account;Note\nSYN-1;Total 12,34,567.89 paid\n", None, ("1234567.89",)),
    "indian-groups-cut": (HEAD + "SYN-1,7,12,34,567.89\n" + FRAGMENT, None, ("1234567.89",)),
    "a-rupee-sign": ("Account;Amount\nSYN-1;\u20b91,234,567.89\n", None, ("1234567.89",)),
    "a-rupee-sign-and-indian-groups": ("Account;Amount\nSYN-1;\u20b912,34,567.89\n", None, ("1234567.89",)),
    "other-currency-signs": ("Account;Amount\nSYN-1;\u20a91,234,567\nSYN-2;\u20bd98,765.43\n", None,
                             ("1234567", "98765.43")),
    # A quantity and an amount of eight space groups with a decimal comma, which a comma cut: as far as the screen
    # reads from a later start.
    "eight-groups-after-a-quantity": (HEAD + "wei,7 123 456 789 012 345 678 901 234,56\nSYN-2,99999.99,1\n1.2,3\n",
                                      None, ("123456789012345678901234.56",)),
}
ENCODINGS = {"utf-8": "utf-8", "utf-8-bom": "utf-8-sig", "utf-16": "utf-16", "cp1252": "cp1252"}


def _entry(path, layout):
    return str(path) if layout is None else {"path": str(path), "delimiter": layout[0], "decimal_mark": layout[1]}


def _screened(snapshot, value):
    try:
        screen_text(f"total {value} today", snapshot)
    except AssistantError as error:
        return error.code == "forbidden_token_present"
    return False


@pytest.mark.parametrize("round_figures", ["skip", "list"])
@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("name", sorted(COMPOSITIONS))
def test_what_the_cut_cells_hold_is_refused_or_the_source_is(tmp_path, name, match, round_figures):
    text, layout, held = COMPOSITIONS[name]
    path = tmp_path / "source.csv"
    path.write_text(text, encoding="utf-8", newline="")
    try:
        snapshot = load_token_snapshot({"forbidden_token_sources": [_entry(path, layout)], "forbidden_token_match": match,
                                        "forbidden_token_round_figures": round_figures}, ())
    except AssistantError as error:
        assert error.code in REFUSED_SOURCE, error.code
        return
    missed = [value for value in held if not _screened(snapshot, value)]
    assert not missed, missed


@pytest.mark.parametrize("encoding", sorted(ENCODINGS))
def test_the_encoding_never_hides_what_the_cut_cells_hold(tmp_path, encoding):
    path = tmp_path / "source.csv"
    path.write_bytes((HEAD + CUT + "SYN-9,1.2.3\n").encode(ENCODINGS[encoding]))
    snapshot = load_token_snapshot({"forbidden_token_sources": [str(path)]}, ())
    assert [value for value in HELD if not _screened(snapshot, value)] == []


@pytest.mark.parametrize("match", ["value", "digits"])
@pytest.mark.parametrize("name", ["fragment-row-after", "exponent-on-the-amount-far-past", "declared-semicolon",
                                  "declared-one-column", "decimal-quantity-beside-a-fragment", "label-before-the-cut",
                                  "text-cell-after-a-decimal-semicolon"])
def test_a_change_writing_what_the_cut_cells_hold_never_reaches_a_request(gate_case, tmp_path, name, match):  # noqa: F811
    text, layout, held = COMPOSITIONS[name]
    source = tmp_path / "source.csv"
    source.write_text(text, encoding="utf-8", newline="")
    change_policy(gate_case, forbidden_token_sources=[_entry(source, layout)], forbidden_token_source_rule=SOURCE_RULE,
                  forbidden_token_match=match)
    (gate_case["repo"] / "src/cash.py").write_text(f"def balance():\n    return {held[0]}  # synthetic\n",
                                                   encoding="utf-8", newline="\n")
    command(gate_case["repo"], "commit", "-q", "-am", "Synthetic change writing what cut cells hold")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and report["spend"]["reserved_usd"] is None
    # A bare path is read every way, which no policy reaches: refused before any source is read.
    allowed = {"forbidden_token_present", *REFUSED_SOURCE} if layout else {"forbidden_token_source_layout_required"}
    assert report["reasons"][0] in allowed


def test_an_amount_cut_into_more_cells_beside_a_fragment_never_reaches_a_request(gate_case, tmp_path):  # noqa: F811
    source = tmp_path / "source.csv"
    source.write_text(HEAD + "SYN-1,12,345,678,901,234,567,890,123.40\nSYN-9,1.2.3\n", encoding="utf-8", newline="")
    change_policy(gate_case, forbidden_token_sources=[_entry(source, (",", "."))], forbidden_token_source_rule=SOURCE_RULE)
    (gate_case["repo"] / "src/cash.py").write_text("def balance():\n    return 345678  # synthetic\n",
                                                   encoding="utf-8", newline="\n")
    command(gate_case["repo"], "commit", "-q", "-am", "Synthetic change writing a run of a long cut")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and report["spend"]["reserved_usd"] is None
    assert report["reasons"] == ["forbidden_token_source_invalid"]
