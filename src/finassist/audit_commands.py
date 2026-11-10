"""Arguments and execution for the audit summary, closing an unfinished run and settling spend."""

from decimal import Decimal
import json
from pathlib import Path

from .errors import AssistantError
from .ledger import Ledger
from .security import canonical, check_text, write_private
from .workflow_state import abandoned_workflows, unfinished_workflows


def add_audit_commands(commands) -> None:
    audit = commands.add_parser(
        "audit", help="Verify audit-chain integrity, list unresolved state, or close an unfinished run")
    audit.add_argument("audit_action", nargs="?", choices=["close-run"],
                       help="close-run records that an unfinished command's outcome is unknown, so it stops blocking")
    audit.add_argument("--state-dir", type=Path, default=Path(".finassist"))
    audit.add_argument("--export", help="Export verified metadata events as private JSON Lines")
    audit.add_argument("--after", type=int, default=0)
    audit.add_argument("--limit", type=int, default=1000)
    # Their own names: args.command is the subcommand.
    audit.add_argument("--run", dest="closed_run", help="With close-run: a run_id from incomplete_runs")
    audit.add_argument("--command", dest="closed_command", help="With close-run: the command recorded for that run")
    settle = commands.add_parser(
        "reconcile-budget", help="Record operator-verified spend for one unresolved call"
    )
    settle.add_argument("--state-dir", type=Path, default=Path(".finassist"))
    settle.add_argument("--reservation", required=True)
    settle.add_argument("--actual-usd", required=True)


def run_audit(args, config, state_dir: Path) -> dict:
    """The audit summary, after the one change the command asked for, if any."""
    closing = args.command == "audit" and args.audit_action == "close-run"
    if args.command == "audit":
        if closing and (not args.closed_run or not args.closed_command or args.export):
            raise AssistantError("audit_close_run_arguments_invalid")
        if not closing and (args.closed_run is not None or args.closed_command is not None):
            raise AssistantError("audit_close_run_arguments_invalid")
    with Ledger(Path(state_dir) / "audit.sqlite") as ledger:
        closed = None
        if args.command == "reconcile-budget":
            ledger.settle(args.reservation, Decimal(args.actual_usd))
        elif closing:
            closed = ledger.close_run(args.closed_run, args.closed_command)
        elif args.export:
            events = ledger.events(after=args.after, limit=args.limit)
            data = b"".join(canonical(event) + b"\n" for event in events)
            check_text(data.decode(), extra_patterns=config.extra_sensitive_patterns)
            write_private(Path(args.export), data)
        workflow_events = [(seq, json.loads(payload)) for seq, payload in ledger.db.execute(
            "SELECT seq,payload FROM events ORDER BY seq")]
        summary = {
            "events_verified": ledger.verify(),
            "unresolved": ledger.open_reservations(),
            "incomplete_runs": ledger.incomplete_runs(),
            "unfinished_workflows": unfinished_workflows(workflow_events),
        }
        # Recoveries stay visible: neither list is ever emptied.
        if reconciled := ledger.reconciled_runs():
            summary["reconciled_runs"] = reconciled
        if abandoned := abandoned_workflows(workflow_events):
            summary["abandoned_workflows"] = abandoned
        if closed is not None:
            summary["closed_run"] = closed
        return summary
