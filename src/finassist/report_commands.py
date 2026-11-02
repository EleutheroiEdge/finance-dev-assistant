"""Argument definitions for offline report traces and adjudication scoring."""
from pathlib import Path


def add_report_commands(commands) -> None:
    scoring = commands.add_parser("score", help="Score an evaluation with independent operator judgments")
    scoring_source = scoring.add_mutually_exclusive_group(required=True)
    scoring_source.add_argument("--evaluation")
    scoring_source.add_argument("--report", help="Private model gate report for finding disposition counts")
    scoring.add_argument("--labels")
    scoring.add_argument("--adjudications", help="Local finding-id to outcome/note mapping")
    scoring.add_argument("--compare", help="Second history evaluation over the same frozen cases")
    scoring.add_argument("--compare-labels", help="Independent judgments bound to the second evaluation")
    scoring.add_argument("--output", required=True)
    reporting = commands.add_parser("report", help="Render a private advisory finding trace")
    reporting_commands = reporting.add_subparsers(dest="report_action", required=True)
    trace = reporting_commands.add_parser("trace", help="Write escaped Markdown without posting it")
    trace.add_argument("--report", required=True, type=Path)
    trace.add_argument("--adjudications", type=Path)
    trace.add_argument("--output", required=True, type=Path)
