"""The command-line parser: every subcommand, option and help text of `finassist`.

Kept apart from cli.py, which runs the commands, so that adding a command does not have to fit into
one file's size limit. cli.py imports `parser` from here.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import installed_version
from .error_hints import add_explain_command

WORKFLOW_STATE_ACTIONS = {
    "run": "Execute approved checks in dependency order with durable checkpoints",
    "resume": "Resume remaining checks; hold uncertain attempts for reconciliation",
    "status": "Inspect stored workflow state without executing checks",
    "reconcile": "Adopt a verified result or confirm cleanup of an uncertain attempt",
    "retry": "Make an approved failed attempt eligible for a later explicit resume",
    "cancel": "Close an inactive run while preserving evidence",
    "abandon": "Close a run whose files are missing or changed; nothing is deleted",
}


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="finassist", description="Start here: demo -> init -> doctor -> plan -> review. "
        "Run finassist guide first-run for the offline walkthrough."
    )
    root.add_argument("--version", action="version", version=installed_version())
    root.add_argument("--config", type=Path, help="Explicit reviewed JSON configuration; default is offline")
    root.add_argument(
        "--audit-dir",
        type=Path,
        help="Private command audit directory; default is the operation state directory",
    )
    commands = root.add_subparsers(dest="command", required=True)
    guide = commands.add_parser("guide", help="List or print bundled guides offline")
    guide.add_argument("topic", nargs="?", help="Topic from the guide index; omit to list topics")
    guide.add_argument("--json", action="store_true", help="Print the topic index as JSON")
    config_command = commands.add_parser("config", help="Print schemas or preview and apply reversible configuration migrations")
    config_actions = config_command.add_subparsers(dest="config_action", required=True)
    from .document_schemas import add_schema_command
    add_schema_command(config_actions)
    migrate = config_actions.add_parser("migrate", help="Keep exact backup bytes before applying reviewed key renames")
    migrate.add_argument("--path", type=Path, help="Configuration file; otherwise --config or finassist.json")
    migrate.add_argument("--dry-run", action="store_true")
    from .onboarding_commands import add_onboarding_commands
    add_onboarding_commands(commands)
    add_explain_command(commands)
    update = commands.add_parser("update", help="Inspect installation or explicitly upgrade; never migrate project data")
    update.add_argument("update_action", nargs="?", choices=["status"])
    update.add_argument("--json", action="store_true", help="Emit JSON (also the default output contract)")
    update_mode = update.add_mutually_exclusive_group()
    update_mode.add_argument("--dry-run", action="store_true", help="Print the exact upgrade argv/command without installing")
    update_mode.add_argument("--yes", action="store_true", help="Explicitly run the detected package manager once")
    demo = commands.add_parser("demo", help="Run fictional finance checks offline")
    demo.add_argument("--output")
    triage_command = commands.add_parser("triage", help="Validate advisory data or calculate offline routing metrics")
    triage_actions = triage_command.add_subparsers(dest="triage_action", required=True)
    triage_validate = triage_actions.add_parser("validate", help="Validate an exact request/model-bound result offline")
    triage_validate.add_argument("--request", type=Path, required=True)
    triage_validate.add_argument("--result", type=Path, required=True)
    triage_evaluate = triage_actions.add_parser("evaluate", help="Score separate request, gold and prediction collections")
    triage_evaluate.add_argument("--requests", type=Path, required=True)
    triage_evaluate.add_argument("--gold", type=Path, required=True)
    triage_evaluate.add_argument("--predictions", type=Path, required=True)
    for operation in (triage_validate, triage_evaluate):
        operation.add_argument("--model-manifest", type=Path, required=True)
        operation.add_argument("--output", type=Path, required=True, help="New private report; never overwritten")
    model_gate = commands.add_parser("gate", help="Run an explicitly policy-approved model review component")
    gate_actions = model_gate.add_subparsers(dest="gate_action", required=True)
    gate_run = gate_actions.add_parser("run", help="Review immutable source with a pinned base policy")
    gate_run.add_argument("--repo", type=Path, default=Path.cwd())
    gate_run.add_argument("--base", required=True)
    gate_run.add_argument("--head", required=True)
    gate_run.add_argument("--policy", required=True)
    gate_run.add_argument("--policy-sha256", required=True)
    gate_run.add_argument("--state-dir", type=Path, required=True, help="Private caller-retained budget ledger directory")
    gate_run.add_argument("--output", required=True, help="New private JSON report path")

    ci = commands.add_parser("ci", help="Run isolated CI checks under a pinned base-revision policy")
    ci_actions = ci.add_subparsers(dest="ci_action", required=True)
    ci_gate_parser = ci_actions.add_parser("gate", help="Evaluate a GitHub PR without calling or approving models")
    ci_gate_parser.add_argument("--repo", type=Path, default=Path.cwd())
    ci_gate_parser.add_argument("--event", type=Path, required=True)
    ci_gate_parser.add_argument("--event-name", required=True)
    ci_gate_parser.add_argument("--repository", required=True)
    ci_gate_parser.add_argument("--policy", default="finassist-ci.json")
    ci_gate_parser.add_argument("--policy-sha256", required=True)
    ci_gate_parser.add_argument("--state-dir", type=Path)
    ci_gate_parser.add_argument("--output")
    for command in ("plan", "watch"):
        plan = commands.add_parser(
            command, help="Inspect source changes without running models or candidate code"
        )
        plan.add_argument("--repo", type=Path, default=Path.cwd())
        plan.add_argument("--base", required=True)
        plan.add_argument("--head", default="HEAD")
        if command == "plan":
            plan.add_argument("--output", required=True)
        else:
            plan.add_argument("--iterations", type=int, default=1)
            plan.add_argument("--interval", type=float, default=5)
    for command in ("review", "propose"):
        request = commands.add_parser(
            command, help="Call the configured model only after exact packet approval"
        )
        request.add_argument("--packet", required=True)
        request.add_argument("--repo", type=Path, default=Path.cwd(),
                             help="Repository checkout; used only when the configuration lists confidential "
                                  "figures, whose list must sit outside it (default: current directory)")
        request.add_argument("--approve-packet")
        request.add_argument("--allow-network", action="store_true")
        request.add_argument("--state-dir", type=Path, default=Path(".finassist"))
        request.add_argument("--output", required=True)
    workflow = commands.add_parser("workflow", help="Plan, execute approved checks and reconcile durable workflows")
    actions = workflow.add_subparsers(dest="workflow_action", required=True)
    resolver = actions.add_parser("resolve", help="Preview pinned local packs as configuration and a workflow template")
    resolver.add_argument("--repo", type=Path, default=Path.cwd())
    resolver.add_argument("--bundle", required=True)
    resolver.add_argument("--output", type=Path, required=True, help="New private output directory")
    for action in ("plan", "preflight"):
        operation = actions.add_parser(action)
        operation.add_argument("--repo", type=Path, default=Path.cwd())
        operation.add_argument("--packet", required=True)
        if action == "plan":
            operation.add_argument("--template", required=True)
            operation.add_argument("--resolution", help="Bind this pack-resolution provenance to the plan's audit event")
        else:
            operation.add_argument("--plan", required=True)
        operation.add_argument("--output", required=action == "plan")
    for action in sorted(WORKFLOW_STATE_ACTIONS):
        operation = actions.add_parser(action, help=WORKFLOW_STATE_ACTIONS[action])
        operation.add_argument("--state-dir", type=Path)
        operation.add_argument("--repo", type=Path, default=Path.cwd())
        operation.add_argument("--output")
        if action != "run":
            operation.add_argument("--run-id", required=action != "status")
        if action in {"run", "resume"}:
            operation.add_argument("--max-steps", type=int, default=64, help="Maximum checks this invocation (1-64)")
            operation.add_argument("--approve-local", action="store_true",
                                   help="Allow trusted local execution without OS isolation")
        if action in {"run", "resume", "retry", "cancel", "abandon"}:
            operation.add_argument("--approve-plan", required=True, help="Exact hash of the inspected workflow plan")
        if action == "run":
            operation.add_argument("--packet", required=True)
            operation.add_argument("--plan", required=True)
            operation.add_argument("--backend", choices=["docker", "podman", "local"], default="docker")
        if action in {"reconcile", "retry"}:
            operation.add_argument("--step-id", required=True)
            operation.add_argument("--approve-attempt", required=True, help="Exact ID of the attempt being resolved")
        if action == "reconcile":
            choice = operation.add_mutually_exclusive_group(required=True)
            choice.add_argument("--approve-artifact", help="Exact hash of the inspected saved result")
            choice.add_argument("--confirm-cleanup", action="store_true",
                                help="Confirm processes are stopped and cleanup is complete; records failure")
        if action == "abandon":
            operation.add_argument("--confirm-cleanup", action="store_true",
                                   help="Confirm an interrupted step's processes are stopped and cleaned up")
    timeline = actions.add_parser("timeline", help="Inspect verified historical workflow transitions without acting")
    timeline.add_argument("--repo", type=Path, default=Path.cwd())
    timeline.add_argument("--state-dir", type=Path)
    timeline.add_argument("--run-id", required=True)
    timeline.add_argument("--after", type=int, default=0)
    timeline.add_argument("--limit", type=int, default=100)
    timeline.add_argument("--through", type=int, help="Pin the historical ledger prefix; use with --anchor")
    timeline.add_argument("--anchor", help="Exact ledger hash at --through")
    timeline.add_argument("--output")
    apply = commands.add_parser("apply", help="Apply an inspected proposal on a clean feature branch")
    apply.add_argument("--repo", type=Path, default=Path.cwd())
    apply.add_argument("--proposal", required=True)
    apply.add_argument("--approve-hash", required=True)
    rollback = commands.add_parser("rollback", help="Restore a patch only if later work is unchanged")
    rollback.add_argument("--repo", type=Path, default=Path.cwd())
    rollback.add_argument("--patch-hash", required=True)
    check = commands.add_parser("check", help="Run an operator-configured recipe on committed source")
    check.add_argument("--repo", type=Path, default=Path.cwd())
    check.add_argument("--head", default="HEAD")
    check.add_argument("--recipe", required=True)
    check.add_argument("--backend", choices=["docker", "podman", "local"], default="docker")
    check.add_argument("--approve-local", action="store_true")
    check.add_argument("--output", required=True)
    finance = commands.add_parser(
        "finance-check", help="Local deterministic numeric/evidence checks; never sent to a provider"
    )
    finance.add_argument("--kind", choices=["cash", "tax", "weights", "observation"], required=True)
    finance.add_argument("--input", required=True)
    finance.add_argument("--output")
    from .audit_commands import add_audit_commands
    add_audit_commands(commands)
    render = commands.add_parser("render", help="Render escaped static HTML from an existing JSON report")
    render.add_argument("--input", required=True)
    render.add_argument("--output", required=True)
    scan = commands.add_parser("scan", help="Screen tracked publication files; does not upload anything")
    scan.add_argument("--repo", type=Path, default=Path.cwd())
    scan.add_argument(
        "--forbid", action="append", default=[], help="Additional text to exclude, case-insensitively"
    )
    evaluation = commands.add_parser(
        "evaluate", help="Run frozen synthetic or local history cases; labels stay out of context"
    )
    suites = evaluation.add_mutually_exclusive_group(required=True)
    suites.add_argument("--suite")
    suites.add_argument("--history-suite", help="Local frozen revisions and held-out expected findings")
    evaluation.add_argument("--trials", type=int, default=1, help="History trials per case (1-20)")
    evaluation.add_argument("--approve-suite")
    evaluation.add_argument("--allow-network", action="store_true")
    evaluation.add_argument("--state-dir", type=Path, default=Path(".finassist"))
    evaluation.add_argument("--output", required=True)
    from .report_commands import add_report_commands
    add_report_commands(commands)
    evidence = commands.add_parser(
        "evidence", help="Append local analyst evidence and record explicit approval"
    )
    evidence.add_argument("action", choices=["add", "approve", "reject", "latest", "verify", "migrate"])
    evidence.add_argument("--dry-run", action="store_true", help="Preview evidence migration without writes")
    evidence.add_argument("--state-dir", type=Path, default=Path(".finassist"))
    evidence.add_argument("--input")
    evidence.add_argument("--supersedes", type=int)
    evidence.add_argument("--id", type=int)
    evidence.add_argument("--approve-hash")
    evidence.add_argument("--entity")
    evidence.add_argument("--metric")
    evidence.add_argument("--period-end")
    evidence.add_argument("--period-start")
    evidence.add_argument("--period-kind")
    evidence.add_argument("--unit")
    export = commands.add_parser(
        "export-kit", help="Export portable skill and native role templates without installation"
    )
    export.add_argument("--output", type=Path, required=True)
    gate = commands.add_parser(
        "verify-gate",
        help="Check source-bound review/test evidence without authorizing a merge or deployment",
    )
    gate.add_argument("--repo", type=Path, default=Path.cwd())
    gate.add_argument("--expected-head", required=True)
    gate.add_argument("--packet", required=True)
    gate.add_argument("--review", required=True)
    gate.add_argument("--receipt", action="append", default=[])
    gate.add_argument("--workflow-plan", help="Also require this plan's canon, bindings and check evidence")
    gate.add_argument("--state-dir", type=Path)
    gate.add_argument("--output")
    github = commands.add_parser(
        "github-audit", help="Inspect GitHub branch controls using metadata GETs only"
    )
    github.add_argument("--repository", required=True)
    github.add_argument("--branch", default="main")
    github.add_argument("--allow-network", action="store_true")
    github.add_argument("--output")
    dashboard = commands.add_parser("dashboard", help="Serve the offline local configuration/audit dashboard")
    dashboard.add_argument("--state-dir", type=Path)
    dashboard.add_argument("--port", type=int, default=0)
    return root
