from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, localcontext

import pytest

from finassist.demo import run_demo
from finassist.errors import AssistantError
from finassist.finance import cash_check, number, tax_estimate, weights_check, observation_check
from finassist.ledger import Ledger


def test_offline_demo_finds_mutated_cases():
    result = run_demo()
    assert result["status"] == "PASS" and result["model_called"] is False
    assert len(result["counterexamples_detected"]) == 4


@pytest.mark.parametrize("value", [True, 0.1, "NaN", "Infinity", "invalid"])
def test_decimal_inputs_fail_closed(value):
    with pytest.raises(AssistantError):
        number(value)


def test_cash_reconciles_to_the_cent_and_detects_fee_omission():
    values = dict(opening="100.00", deposits="0", sells="50", buys="30", fees="0.01", ending="119.99")
    assert cash_check(**values)["passed"]
    assert not cash_check(**{**values, "ending": "120.00"})["passed"]
    assert weights_check(["0.3", "0.7"])["passed"]
    assert not weights_check(["0.3", "0.6"])["passed"]


def test_money_arithmetic_does_not_inherit_low_precision():
    with localcontext() as context:
        context.prec = 4
        result = cash_check(
            opening="1000000000000.01",
            deposits="0.02",
            sells="0",
            buys="0",
            fees="0",
            ending="1000000000000.03",
            tolerance="0",
        )
        assert result["passed"] and result["residual"] == "0.00"


def test_tax_method_and_rates_are_explicit():
    values = dict(short_term="-40", long_term="140", short_rate="0.3", long_rate="0.2")
    assert tax_estimate(**values, method="offset-characters")["estimated_tax"] == "20.0"
    assert tax_estimate(**values, method="separate-positive")["estimated_tax"] == "28.0"
    with pytest.raises(AssistantError, match="explicit_tax_method_required"):
        tax_estimate(**values, method="assume")


def test_evidence_rejects_missing_metadata():
    with pytest.raises(AssistantError, match="observation_fields_missing"):
        observation_check({"value": "100"}, decision_time="2026-01-01T00:00:00Z")


def test_reservations_are_serialized_and_unknown_costs_remain_held(tmp_path):
    path = tmp_path / "audit.db"
    with Ledger(path):
        pass

    def reserve(_):
        with Ledger(path) as ledger:
            try:
                return ledger.reserve(Decimal("0.4"), Decimal("1"), Decimal("1"))
            except AssistantError:
                return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = [item for item in pool.map(reserve, range(12)) if item]
    assert len(ids) == 2
    with Ledger(path) as ledger:
        assert len(ledger.open_reservations()) == 2
        ledger.settle(ids[0], Decimal("0.1"))
        assert len(ledger.open_reservations()) == 1
        assert ledger.verify() == 3
        with pytest.raises(AssistantError, match="reservation_not_open"):
            ledger.settle(ids[0], Decimal("0"))


def test_audit_detects_accidental_tampering(tmp_path):
    with Ledger(tmp_path / "audit.db") as ledger:
        ledger.append({"event": "fictional"})
        ledger.db.execute("UPDATE events SET payload='{}' WHERE seq=1")
        with pytest.raises(AssistantError, match="audit_integrity_failed"):
            ledger.verify()
