"""The seeded finance suite's labels hold by execution, not by assertion.

Each routine appears twice with the same `before`: once with one seeded defect, once as a behaviour-preserving
twin. Both sides of every case are executed on probe inputs, at the default decimal precision and at three digits:
a defect must change at least one result, and a twin must change none, to the exact representation of each value
and the type of each exception. Probes sample behaviour; they do not prove equivalence for every input, so each
twin also keeps the original expressions and only renames or extracts them. The probes live here, never in the
suite, so nothing in a review packet hints at the answer. Synthetic code written for this suite only.
"""

from datetime import date
import decimal
from decimal import Decimal as D
import json
import math
from pathlib import Path

import pytest

from finassist.evaluation import validate_suite

SUITE = Path(__file__).resolve().parents[1] / "examples" / "seeded-finance-cases.json"


def _quote(symbol):
    return {"AAA": D("12"), "BBB": D("7")}[symbol]  # an unknown symbol raises KeyError, a LookupError


_LOTS = [{"id": "a", "cost": D("10"), "qty": D("10")}, {"id": "b", "cost": D("12"), "qty": D("4")},
         {"id": "c", "cost": D("12"), "qty": D("6")}, {"id": "d", "cost": D("9"), "qty": D("0")}]
_KEYED = [{"symbol": "AAA", "ref": "L1", "cost": D("100"), "qty": D("10")},
          {"symbol": "BBB", "ref": "L1", "cost": D("300"), "qty": D("10")},
          {"symbol": "AAA", "ref": "L2", "cost": D("90"), "qty": D("3")}]

PROBES = {
    "bps": ("bps_to_fraction", [(25,), (100,), (0,), (-5,), (D("12.5"),)]),
    "cents": ("round_cents", [("1.005",), ("2.675",), ("-1.005",), ("3",), ("0.004",)]),
    "hifo": ("sale_order", [(_LOTS,), (list(reversed(_LOTS)),), ([],),
                            ([{"id": "a", "cost": D("10.01")}, {"id": "b", "cost": D("10.02")}],)]),
    "cap": ("buy_allowed", [(D("100"), D("50"), D("1000"), D("0.12")), (D("100"), D("20"), D("1000"), D("0.12")),
                            (D("100"), D("0"), D("1000"), D("0.1"))]),
    "wash": ("in_wash_window", [(date(2026, 3, 1), date(2026, 2, 20)), (date(2026, 3, 1), date(2026, 3, 20)),
                                (date(2026, 3, 1), date(2026, 5, 1)), (date(2026, 3, 1), date(2026, 1, 30))]),
    "weight": ("weight", [(D("50"), D("200")), (D("0"), D("0")), (D("5"), 0), (1, 3)]),
    "tie": ("same_overweight", [("0.3", "0.1", "3", "1"), ("2", "1", "4", "3"), ("1", "2", "2", "4")]),
    "lotkey": ("unit_cost", [(_KEYED, "AAA", "L1"), (_KEYED, "BBB", "L1"), (_KEYED, "AAA", "L2"),
                             (_KEYED, "BBB", "L2")]),
    "unpriced": ("sale_gain", [({"symbol": "ZZZ", "cost": D("10"), "qty": D("5")}, _quote),
                               ({"symbol": "AAA", "cost": D("10"), "qty": D("5")}, _quote)]),
    "restricted": ("buy_candidates", [(["AAA", "BBB", "CCC"], ["BBB"], ["CCC"]), (["AAA"], [], []),
                                      (["AAA", "BBB"], {"AAA"}, set())]),
    "mintrade": ("order_shares", [(D("1000"), D("300"), D("950")), (D("1000"), D("300"), D("900")),
                                  (D("50"), D("300"), D("10")), (1000.0, 300.0, float("nan"))]),
    "fees": ("ending_cash", [(D("1000"), D("500"), D("700"), D("5")), (D("0"), D("0"), D("0"), D("0"))]),
    "longterm": ("is_long_term", [(date(2025, 3, 1), date(2026, 3, 1)), (date(2025, 3, 1), date(2026, 3, 2)),
                                  (date(2025, 3, 1), date(2025, 12, 31)), (date(2023, 12, 31), date(2025, 1, 1))]),
    "gaintax": ("estimated_tax", [(D("150"), D("100"), D("0.2")), (D("90"), D("100"), D("0.2")),
                                  (D("100"), D("100"), D("0.2"))]),
    "percent": ("drift", [(D("0.27"), D("25")), (D("0"), D("0")), (D("0.5"), D("50"))]),
    "annual": ("annualized", [(0.21, 2), (0.0, 3), (1.0, 1)]),
    "daycount": ("accrued", [(D("1000000"), D("0.05"), 30), (D("250"), D("0.031"), 91), (D("0"), D("0.05"), 30)]),
    "fx": ("to_usd", [(D("100"), D("0.9")), (D("100"), D("1")), (D("0"), D("1.1"))]),
    "period": ("in_period", [(date(2026, 1, 31), date(2026, 1, 1), date(2026, 1, 31)),
                             (date(2026, 1, 15), date(2026, 1, 1), date(2026, 1, 31)),
                             (date(2026, 1, 1), date(2026, 1, 1), date(2026, 1, 31)),
                             (date(2025, 12, 31), date(2026, 1, 1), date(2026, 1, 31))]),
    "fill": ("fill", [(_LOTS, D("15")), (_LOTS, D("4")), (_LOTS, D("0")), (_LOTS, D("100")), (_LOTS, D("NaN"))]),
}
PRECISIONS = (None, 3)  # the default context, then three digits: a refactor must not depend on the context


def _same(value):
    """A value for comparing defects: NaN equals NaN, so only a real change in result counts."""
    if isinstance(value, float) and math.isnan(value) or isinstance(value, D) and value.is_nan():
        return "NaN"
    return value


def _suite():
    return json.loads(SUITE.read_text(encoding="utf-8"))


def _outcomes(source: str, function: str, probes: list) -> list:
    namespace: dict = {}
    exec(compile(source, "<seeded case>", "exec"), namespace)  # noqa: S102 - this suite's own synthetic code
    results = []
    for precision in PRECISIONS:
        with decimal.localcontext() as context:
            if precision is not None:
                context.prec = precision
            for args in probes:
                try:
                    results.append(("value", namespace[function](*args)))
                except Exception as exc:  # noqa: BLE001 - the exception's type is part of the behaviour compared
                    results.append(("raises", type(exc).__name__))
    return results


def test_the_suite_is_valid_and_each_routine_has_one_defect_and_one_twin():
    suite = _suite()
    validate_suite(suite)
    routines = {}
    for case in suite["cases"]:
        name, kind = case["id"].rsplit("-", 1)
        assert kind == ("defect" if case["expected_defect"] else "twin")
        routines.setdefault(name, []).append(case)
    assert set(routines) == set(PROBES) and len(suite["cases"]) == 2 * len(PROBES)
    for pair in routines.values():
        assert len(pair) == 2 and pair[0]["before"] == pair[1]["before"] and pair[0]["path"] == pair[1]["path"]
        assert pair[0]["after"] != pair[0]["before"] and pair[1]["after"] != pair[1]["before"]


@pytest.mark.parametrize("case", _suite()["cases"], ids=lambda case: case["id"])
def test_a_defect_changes_a_result_and_a_twin_changes_none(case):
    function, probes = PROBES[case["id"].rsplit("-", 1)[0]]
    before, after = _outcomes(case["before"], function, probes), _outcomes(case["after"], function, probes)
    assert any(kind == "value" for kind, _ in before), "the probes exercise the correct routine"
    if case["expected_defect"]:
        assert [(k, _same(v)) for k, v in before] != [(k, _same(v)) for k, v in after], "the defect is observable"
    else:
        assert [(k, repr(v)) for k, v in before] == [(k, repr(v)) for k, v in after], "the twin preserves every result"
