"""Seed a NEW temporary demo directory with fictional metadata, never real keys."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import sys
from unittest.mock import patch

from finassist.auditing import command_audit
from finassist.config import Config, save_config
from finassist.ledger import Ledger

root = Path(sys.argv[1])
root.mkdir(exist_ok=False)
config = Config()
save_config(root / "configuration.json", config)
path = root / "state/audit.sqlite"


class DemoClock:
    value = datetime.now(timezone.utc)

    @classmethod
    def now(cls, tz):
        return cls.value.astimezone(tz)


# Fixture-only clock controls: records are fictional, not real provider usage.
for index in range(5):
    DemoClock.value = datetime.now(timezone.utc) - timedelta(days=4 - index)
    with patch("finassist.ledger.datetime", DemoClock), command_audit(path, "synthetic-review", config):
        with Ledger(path) as ledger:
            reservation = ledger.reserve(Decimal("0.1"), Decimal(5), Decimal(1))
            ledger.append({"event": "review_requested", "reservation": reservation})
            ledger.append({"event": "model_usage", "reservation": reservation, "input_tokens": 1200 + index * 200, "output_tokens": 240})
            ledger.settle(reservation, Decimal("0.02") + Decimal(index) / 100)
            ledger.append({"event": "review_completed", "profile": "general", "findings_by_severity": {"low": 2, "medium": 1}})
            ledger.append({"event": "check_completed", "recipe": "synthetic-unit", "passed": True})
            ledger.append({"event": "readiness_evaluated", "status": "blocked", "reasons": ["synthetic_missing_evidence"]})
