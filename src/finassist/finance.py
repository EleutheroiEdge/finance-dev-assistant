"""Deterministic review oracles with explicit assumptions, never trading authority."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation, localcontext
from functools import wraps

from .errors import AssistantError


def _exact_math(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        # Input magnitude/scale are bounded by number(); leave ample precision
        # and do not inherit a caller's low-precision Decimal context.
        with localcontext() as context:
            context.prec = 100
            return function(*args, **kwargs)

    return wrapped


def number(value) -> Decimal:
    # Reject binary floats rather than hide their origin behind string conversion.
    if type(value) not in {str, int, Decimal}:
        raise AssistantError("exact_decimal_required")
    if len(str(value)) > 200:
        raise AssistantError("decimal_limit_exceeded")
    try:
        result = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise AssistantError("invalid_decimal") from exc
    if not result.is_finite():
        raise AssistantError("nonfinite_decimal")
    if abs(result.adjusted()) > 30 or abs(result.as_tuple().exponent) > 18:
        raise AssistantError("decimal_limit_exceeded")
    return result


@_exact_math
def cash_check(*, opening, deposits, sells, buys, fees, ending, tolerance="0") -> dict:
    tolerance = number(tolerance)
    if tolerance < 0:
        raise AssistantError("invalid_tolerance")
    expected = number(opening) + number(deposits) + number(sells) - number(buys) - number(fees)
    residual = number(ending) - expected
    return {
        "check": "cash-conservation",
        "passed": abs(residual) <= tolerance,
        "expected_ending": str(expected),
        "residual": str(residual),
        "tolerance": str(tolerance),
    }


@_exact_math
def tax_estimate(*, short_term, long_term, short_rate, long_rate, method: str) -> dict:
    """A selectable synthetic arithmetic oracle, not a jurisdiction's tax implementation."""
    st, lt, sr, lr = map(number, (short_term, long_term, short_rate, long_rate))
    if not 0 <= sr <= 1 or not 0 <= lr <= 1:
        raise AssistantError("invalid_rate")
    if method == "offset-characters":
        if st > 0 and lt < 0:
            st, lt = max(Decimal(0), st + lt), min(Decimal(0), st + lt)
        elif lt > 0 and st < 0:
            st, lt = min(Decimal(0), st + lt), max(Decimal(0), st + lt)
    elif method != "separate-positive":
        raise AssistantError("explicit_tax_method_required")
    amount = max(st, Decimal(0)) * sr + max(lt, Decimal(0)) * lr
    return {
        "estimated_tax": str(amount),
        "method": method,
        "short_rate": str(sr),
        "long_rate": str(lr),
        "qualification": "Explicit simplified arithmetic; omits jurisdiction-specific rules and carryforwards.",
    }


@_exact_math
def weights_check(weights: list, *, total="1", tolerance="0.000001") -> dict:
    values = [number(v) for v in weights]
    tol = number(tolerance)
    if not values or tol < 0:
        raise AssistantError("invalid_weight_check")
    actual = sum(values, Decimal(0))
    return {
        "check": "weight-conservation",
        "passed": all(v >= 0 for v in values) and abs(actual - number(total)) <= tol,
        "actual": str(actual),
        "expected": str(number(total)),
    }


def _instant(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("timezone required")
        return result
    except (ValueError, TypeError, AttributeError) as exc:
        raise AssistantError("explicit_timestamp_required") from exc


def observation_check(
    observation: dict, *, decision_time: str, max_age_days: int = 90, require_approved: bool = True
) -> dict:
    if type(max_age_days) is not int or max_age_days < 0 or type(require_approved) is not bool:
        raise AssistantError("invalid_evidence_policy")
    required = {
        "entity",
        "metric",
        "value",
        "unit",
        "period_start",
        "period_end",
        "published_at",
        "retrieved_at",
        "source",
        "status",
        "period_kind",
    }
    if not required <= observation.keys():
        raise AssistantError("observation_fields_missing")
    number(observation["value"])
    decision, published, retrieved = map(
        _instant, (decision_time, observation["published_at"], observation["retrieved_at"])
    )
    start, end = map(_instant, (observation["period_start"], observation["period_end"]))
    issues = []
    if any(
        not isinstance(observation[k], str) or not observation[k].strip()
        for k in ("entity", "metric", "unit", "source")
    ):
        issues.append("source_identity_or_units_missing")
    if start > end or end > published:
        issues.append("period_order_invalid")
    if published > decision:
        issues.append("look_ahead")
    if retrieved < published:
        issues.append("retrieval_before_publication")
    if require_approved and observation["status"] != "approved":
        issues.append("unapproved_input")
    if observation["period_kind"] not in {"quarter", "annual", "year-to-date", "trailing", "annual-stub"}:
        issues.append("period_kind_missing")
    if (decision - published).total_seconds() > max_age_days * 86400:
        issues.append("stale")
    return {
        "check": "point-in-time-evidence",
        "passed": not issues,
        "issues": issues,
        "decision_time": decision_time,
        "qualification": "A valid record does not prove the source statement true.",
    }
