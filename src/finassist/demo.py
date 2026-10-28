"""Offline demonstration with fictional values and deliberately broken counterexamples."""

from .finance import cash_check, observation_check, tax_estimate, weights_check


def run_demo() -> dict:
    cash = dict(opening="1000", deposits="0", sells="2500", buys="3000", fees="5", ending="495")
    observation = {
        "entity": "Fictional Example",
        "metric": "revenue",
        "value": "1000",
        "unit": "USD",
        "period_start": "2025-01-01T00:00:00Z",
        "period_end": "2025-12-31T00:00:00Z",
        "published_at": "2026-02-01T00:00:00Z",
        "retrieved_at": "2026-02-02T00:00:00Z",
        "source": "fictional-filing",
        "status": "approved",
        "period_kind": "annual",
    }
    checks = [
        cash_check(**cash),
        weights_check(["0.6", "0.4"]),
        observation_check(observation, decision_time="2026-02-03T00:00:00Z"),
    ]
    counterexamples = [
        cash_check(**{**cash, "ending": "500"}),
        weights_check(["0.6", "0.3"]),
        observation_check({**observation, "status": "draft"}, decision_time="2026-02-03T00:00:00Z"),
        observation_check(observation, decision_time="2026-01-15T00:00:00Z"),
    ]
    tax = tax_estimate(
        short_term="-40", long_term="140", short_rate="0.3", long_rate="0.2", method="offset-characters"
    )
    return {
        "status": "PASS"
        if all(x["passed"] for x in checks) and all(not x["passed"] for x in counterexamples)
        else "FAIL",
        "checks": checks,
        "counterexamples_detected": counterexamples,
        "tax_example": tax,
        "model_called": False,
        "data_class": "synthetic",
        "trade_execution": False,
        "qualification": "Demonstrates deterministic oracles, not measured model review quality.",
    }
