"""Verified reduced audit statistics. Source, prompts and run output are excluded."""

from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path

from .config import Config
from .ledger import Ledger
from .workflow_state import replay_workflows, run_phase


def statistics(path: Path, config: Config, *, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    today, month = now.date().isoformat(), now.strftime("%Y-%m")
    costs, tokens, booked = {}, {}, {}
    severity, profiles, finding_profiles, reasons = Counter(), Counter(), Counter(), Counter()
    classified_readiness = set()
    recipes, runs = {}, {}
    reviews = offline = requests = unknown_findings = legacy_checks = usage_known = usage_unknown = (
        eligible
    ) = blocked = 0
    open_rows, workflow_events = [], []
    if path.exists():
        with Ledger(path) as ledger, ledger.transaction():
            ledger.verify()
            open_rows = ledger.open_reservations()
            for seq, raw in ledger.db.execute("SELECT seq,payload FROM events ORDER BY seq"):
                event = json.loads(raw)
                workflow_events.append((seq, event))
                kind = event.get("event")
                day = event.get("recorded_at", "")[:10]
                if kind == "reserved":
                    booked[event["id"]] = event["day"]
                elif kind == "review_requested":
                    requests += 1
                elif kind == "settled":
                    day = booked[event["id"]]
                    costs[day] = costs.get(day, Decimal(0)) + Decimal(event["actual"])
                elif kind == "model_usage":
                    day = booked.get(event["reservation"], day)
                    entry = tokens.setdefault(day, {"input": 0, "output": 0, "unknown": 0})
                    if type(event.get("input_tokens")) is int and type(event.get("output_tokens")) is int:
                        entry["input"] += event["input_tokens"]
                        entry["output"] += event["output_tokens"]
                        usage_known += 1
                    else:
                        entry["unknown"] += 1
                        usage_unknown += 1
                elif kind == "review_completed":
                    reviews += 1
                    profiles[event.get("profile", "unrecorded")] += 1
                    counts = event.get("findings_by_severity")
                    if isinstance(counts, dict):
                        severity.update(counts)
                        finding_profiles[event.get("profile", "unrecorded")] += sum(counts.values())
                    else:
                        unknown_findings += 1
                elif kind == "offline_review_completed":
                    offline += 1
                elif kind == "readiness_evaluated":
                    classified_readiness.add(event.get("run_id"))
                    eligible += event.get("status") == "eligible-for-human-review"
                    blocked += event.get("status") == "blocked"
                    reasons.update(event.get("reasons", []))
                elif kind == "check_completed" and isinstance(event.get("passed"), bool):
                    entry = recipes.setdefault(event.get("recipe", "unrecorded"), {"passed": 0, "total": 0})
                    entry["total"] += 1
                    entry["passed"] += event["passed"]
                elif kind == "check_completed":
                    legacy_checks += 1
                if kind == "command_started":
                    runs[event["run_id"]] = {
                        "id": event["run_id"],
                        "command": event["command"],
                        "started_at": event["recorded_at"],
                        "status": "unknown",
                    }
                elif kind in {"command_completed", "command_failed"} and event.get("run_id") in runs:
                    runs[event["run_id"]].update(
                        status=("completed" if event.get("exit_code") == 0 else "blocked-or-failed")
                        if kind == "command_completed"
                        else "failed",
                        exit_code=event.get("exit_code"),
                        duration_ms=event.get("duration_ms"),
                    )
    workflows = replay_workflows(workflow_events)
    reserved = sum((Decimal(row["reserved"]) for row in open_rows), Decimal(0))
    actual_day = costs.get(today, Decimal(0))
    actual_month = sum((value for day, value in costs.items() if day[:7] == month), Decimal(0))
    daily = [
        {
            "date": day,
            "usd": str(costs.get(day, Decimal(0))),
            **tokens.get(day, {"input": 0, "output": 0, "unknown": 0}),
        }
        for day in sorted(set(costs) | set(tokens))[-90:]
    ]
    return {
        "as_of": now.isoformat(),
        "limits": {"daily_usd": str(config.daily_budget_usd), "monthly_usd": str(config.monthly_budget_usd)},
        "spend": {
            "today_usd": str(actual_day),
            "month_usd": str(sum((value for day, value in costs.items() if day[:7] == month), Decimal(0))),
            "open_reserved_usd": str(reserved),
            "available_today_usd": str(
                max(Decimal(0), Decimal(str(config.daily_budget_usd)) - actual_day - reserved)
            ),
            "available_month_usd": str(
                max(Decimal(0), Decimal(str(config.monthly_budget_usd)) - actual_month - reserved)
            ),
        },
        "daily": daily,
        "open_reservations": open_rows,
        "reviews": {
            "total": reviews,
            "offline": offline,
            "findings": dict(severity),
            "by_profile": dict(profiles),
            "findings_by_profile": dict(finding_profiles),
            "unknown_findings": unknown_findings,
        },
        "usage": {
            "known_calls": usage_known,
            "unknown_calls": max(requests - usage_known, usage_unknown),
            "qualification": "Older or failed calls can lack usage metadata. Missing counts are not zero.",
        },
        "readiness": {
            "eligible": eligible,
            "blocked": blocked,
            "reasons": dict(reasons),
            "unclassified": sum(
                run["command"] == "verify-gate"
                and run["status"] != "unknown"
                and run["id"] not in classified_readiness
                for run in runs.values()
            ),
        },
        "recipes": [{"name": name, **value} for name, value in sorted(recipes.items())],
        "legacy_checks": legacy_checks,
        "recent_runs": list(runs.values())[-50:][::-1],
        "workflows": [
            {"workflow_run_id": identifier, "status": run_phase(run), "plan_hash": run["plan_hash"]}
            for identifier, run in list(workflows.items())[-50:][::-1]
        ],
        "qualification": "Spend is grouped by the UTC date when funds were set aside. These verified local records may differ from your provider's bill and do not approve a merge or deployment.",
    }
