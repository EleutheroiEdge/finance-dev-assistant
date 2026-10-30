"""Explicit commands: inspect, review, propose, apply and verify are separate actions."""

from __future__ import annotations

from .platform_support import read_utf8

import argparse
from dataclasses import asdict, replace
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time

from . import installed_version
from .auditing import command_audit
from .config import Config, PROVIDERS, load_config, save_config
from .demo import run_demo
from .health import doctor_report
from .errors import AssistantError
from .evaluation import evaluate, score
from .evidence_store import EvidenceStore
from .finance import cash_check, observation_check, tax_estimate, weights_check
from .ledger import Ledger
from .integrations import export_kit
from .guides import guide_index, guide_text
from .github_audit import inspect_github
from .patching import apply_patch_artifact, rollback_patch
from .proposal import propose
from .render import report_html
from .readiness import verify_gate
from .review import review_packet
from .runner import run_recipe
from .scope import build_packet, git, resolve, triage
from .security import canonical, check_text, digest, regular_path, write_private
from .workspace import export_snapshot
from .workflow import build_workflow_plan, preflight_workflow, verify_workflow_gate
from .workflow_execution import cancel_run, create_run, execute_run, inspect_run, reconcile_run, retry_step, validate_run
from .workflow_state import MAX_WORKFLOW_ARTIFACT_BYTES, WorkflowStore, run_phase, unfinished_workflows
from .workflow_packs import export_resolution, read_bundle, resolve_bundle, verify_resolution

WORKFLOW_STATE_ACTIONS = {
    "run": "Execute approved checks in dependency order with durable checkpoints",
    "resume": "Resume remaining checks; hold uncertain attempts for reconciliation",
    "status": "Inspect stored workflow state without executing checks",
    "reconcile": "Adopt a verified result or confirm cleanup of an uncertain attempt",
    "retry": "Make an approved failed attempt eligible for a later explicit resume",
    "cancel": "Close an inactive run while preserving evidence",
}


def _read_json(path: str, *, max_bytes: int = 2_000_000) -> dict:
    file = regular_path(Path(path))
    if file.stat().st_size > max_bytes:
        raise AssistantError("input_limit_exceeded")
    value = json.loads(read_utf8(file))
    if not isinstance(value, dict):
        raise AssistantError("input_object_required")
    return value


def _emit(value, output: str | None = None) -> None:
    data = canonical(value) + b"\n"
    if output:
        write_private(Path(output), data)
    else:
        print(data.decode(), end="")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="finassist", description="Evidence-first developer assistance for finance software"
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
    guide.add_argument("topic", nargs="?", help="Topic from the guide index; omit to list topics as JSON")
    config_command = commands.add_parser("config", help="Preview or explicitly apply reversible configuration migrations")
    config_actions = config_command.add_subparsers(dest="config_action", required=True)
    migrate = config_actions.add_parser("migrate", help="Keep exact backup bytes before applying reviewed key renames")
    migrate.add_argument("--path", type=Path, help="Configuration file; otherwise --config or finassist.json")
    migrate.add_argument("--dry-run", action="store_true")
    init = commands.add_parser("init", help="Create offline-by-default configuration")
    init.add_argument("--output", default="finassist.json")
    init.add_argument("--provider", choices=sorted(PROVIDERS), default="offline")
    init.add_argument("--model", default="")
    init.add_argument("--profile", help="Name in the configured profile registry")
    doctor = commands.add_parser(
        "doctor", help="Check runtime, provider setup and container availability without network"
    )
    doctor.add_argument("--fix", action="store_true", help="Apply only explicit safe reversible local migrations")
    doctor.add_argument("--state-dir", type=Path)
    doctor.add_argument("--check-updates", action="store_true", help="Check PyPI once when project network use is allowed")
    update = commands.add_parser("update", help="Inspect installation or explicitly upgrade; never migrate project data")
    update.add_argument("update_action", nargs="?", choices=["status"])
    update.add_argument("--json", action="store_true", help="Emit JSON (also the default output contract)")
    update_mode = update.add_mutually_exclusive_group()
    update_mode.add_argument("--dry-run", action="store_true", help="Print the exact upgrade argv/command without installing")
    update_mode.add_argument("--yes", action="store_true", help="Explicitly run the detected package manager once")
    demo = commands.add_parser("demo", help="Run fictional finance checks offline")
    demo.add_argument("--output")
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
        if action in {"run", "resume", "retry", "cancel"}:
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
    audit = commands.add_parser("audit", help="Verify audit-chain integrity or list unreconciled spend")
    audit.add_argument("--state-dir", type=Path, default=Path(".finassist"))
    audit.add_argument("--export", help="Export verified metadata events as private JSON Lines")
    audit.add_argument("--after", type=int, default=0)
    audit.add_argument("--limit", type=int, default=1000)
    settle = commands.add_parser(
        "reconcile-budget", help="Record operator-verified spend for one unresolved call"
    )
    settle.add_argument("--state-dir", type=Path, default=Path(".finassist"))
    settle.add_argument("--reservation", required=True)
    settle.add_argument("--actual-usd", required=True)
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
    scoring = commands.add_parser("score", help="Score an evaluation with independent operator judgments")
    scoring.add_argument("--evaluation", required=True)
    scoring.add_argument("--labels", required=True)
    scoring.add_argument("--compare", help="Second history evaluation over the same frozen cases")
    scoring.add_argument("--compare-labels", help="Independent judgments bound to the second evaluation")
    scoring.add_argument("--output", required=True)
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


def audit_directory(args) -> Path:
    return (
        args.audit_dir
        or getattr(args, "state_dir", None)
        or (getattr(args, "repo", Path.cwd()) / ".finassist")
    )


def _execute_workflow(args, config: Config) -> int:
    action = args.workflow_action
    if action in {"run", "resume"} and not 1 <= args.max_steps <= 64:
        raise AssistantError("workflow_step_limit_invalid")
    if action == "run":
        plan, packet = _read_json(args.plan), _read_json(args.packet)
        validate_run(plan, packet, args.repo, config, approved_plan=args.approve_plan,
                     backend=args.backend, approve_local=args.approve_local)
    with WorkflowStore(audit_directory(args), create=action == "run") as store:
        if action == "run":
            identifier = create_run(
                store, plan, packet, args.repo, config,
                approved_plan=args.approve_plan, backend=args.backend, approve_local=args.approve_local,
            )
            # Preserve discovery of the new run even if execution is interrupted.
            _emit({"workflow_run_id": identifier, "status": "created"})
            result = execute_run(store, identifier, args.repo, config, approved_plan=args.approve_plan,
                                 approve_local=args.approve_local, max_steps=args.max_steps)
        elif action == "resume":
            result = execute_run(store, args.run_id, args.repo, config, approved_plan=args.approve_plan,
                                 approve_local=args.approve_local, max_steps=args.max_steps)
        elif action == "status":
            if args.run_id:
                result = inspect_run(store, args.run_id)
            else:
                result = {"schema_version": 1, "artifacts_verified": False, "workflows": [
                    {"workflow_run_id": identifier, "status": run_phase(state), "plan_hash": state["plan_hash"]}
                    for identifier, state in store.states().items()
                ]}
        elif action == "reconcile":
            result = reconcile_run(store, args.run_id, args.step_id, args.approve_attempt, config,
                                   approved_artifact=args.approve_artifact, confirm_cleanup=args.confirm_cleanup)
        elif action == "retry":
            result = retry_step(store, args.run_id, args.step_id, args.approve_attempt,
                                approved_plan=args.approve_plan)
        else:
            result = cancel_run(store, args.run_id, approved_plan=args.approve_plan)
        _emit(result, args.output)
        if args.output:
            _emit({"workflow_run_id": result.get("workflow_run_id"), "status": result.get("status"),
                   "output": args.output})
        return 1 if result.get("blocking_reasons") else 0


def execute(args, config: Config | None = None) -> int:
    config = config or load_config(args.config)
    if args.command == "init":
        save_config(
            Path(args.output),
            replace(
                config,
                provider=args.provider,
                model=args.model,
                profile=args.profile or config.profile,
                profile_files=(),
                profiles=dict(config.profiles),
            ),
        )
        _emit({"created": args.output, "network_enabled": False})
    elif args.command == "doctor":
        from .update_check import check_once

        checked = check_once(network_allowed=config.allow_network) if args.check_updates else None
        _emit(doctor_report(config, update_check=checked))
    elif args.command == "demo":
        result = run_demo()
        _emit(result, args.output)
        return 0 if result["status"] == "PASS" else 1
    elif args.command == "plan":
        packet = build_packet(args.repo, args.base, args.head, config)
        _emit(packet, args.output)
        _emit({"packet_hash": packet["packet_hash"], "output": args.output, "triage": triage(packet, config)})
    elif args.command == "workflow" and args.workflow_action in WORKFLOW_STATE_ACTIONS:
        return _execute_workflow(args, config)
    elif args.command == "workflow" and args.workflow_action == "resolve":
        result = resolve_bundle(read_bundle(Path(args.bundle)), args.repo, config)
        saved = export_resolution(result, args.output)
        with Ledger(audit_directory(args) / "audit.sqlite") as ledger:
            ledger.append({"event": "workflow_bundle_resolved", "resolution_hash": saved["resolution_hash"],
                           "config_hash": saved["config_hash"], "template_hash": saved["template_hash"]})
        _emit(saved)
    elif args.command == "workflow":
        packet = _read_json(args.packet)
        if args.workflow_action == "plan":
            template = _read_json(args.template)
            provenance = {}
            if args.resolution:
                provenance["resolution_hash"] = verify_resolution(_read_json(args.resolution), template, config)
            result = build_workflow_plan(template, packet, args.repo, config)
            event = {"event": "workflow_plan_bound", "plan_hash": result["plan_hash"]}
            event.update(provenance)
        else:
            result = preflight_workflow(_read_json(args.plan), packet, args.repo, config)
            event = {
                "event": "workflow_preflight_evaluated", "plan_hash": result["plan_hash"],
                "status": result["status"], "reasons": result["blocking_reasons"],
            }
        with Ledger(audit_directory(args) / "audit.sqlite") as ledger:
            ledger.append({**event, "head": result["head"], "config_hash": digest(canonical(asdict(config)))})
        _emit(result, args.output)
        if args.output:
            _emit({"output": args.output, "plan_hash": result.get("plan_hash"),
                   "status": result.get("status", "plan-bound")})
        return 1 if result.get("blocking_reasons") else 0
    elif args.command == "watch":
        if not 1 <= args.iterations <= 1000 or not 0.1 <= args.interval <= 300:
            raise AssistantError("invalid_watch_bounds")
        last = None
        for index in range(args.iterations):
            current = resolve(args.repo, args.head)
            if current != last:
                packet = build_packet(args.repo, args.base, current, config)
                _emit({"head": current, "triage": triage(packet, config), "network_called": False})
                last = current
            if index + 1 < args.iterations:
                time.sleep(args.interval)
    elif args.command in {"review", "propose"}:
        packet = _read_json(args.packet)
        method = review_packet if args.command == "review" else propose
        result = method(
            packet,
            config,
            audit_directory(args) / "audit.sqlite",
            network_approved=args.allow_network,
            approved_packet_hash=args.approve_packet,
        )
        if args.command == "review" and config.provider == "offline":
            with Ledger(audit_directory(args) / "audit.sqlite") as ledger:
                ledger.append({"event": "offline_review_completed", "profile": config.profile})
        _emit(result, args.output)
        _emit({"output": args.output, "status": result.get("status", "proposal-only")})
    elif args.command == "apply":
        data = _read_json(args.proposal)
        artifact = data.get("artifact", data)
        receipt = apply_patch_artifact(args.repo, artifact, args.approve_hash, config)
        with Ledger(audit_directory(args) / "audit.sqlite") as ledger:
            ledger.append(
                {"event": "patch_applied", "head": receipt["head"], "patch_hash": receipt["patch_hash"]}
            )
        _emit(receipt)
    elif args.command == "rollback":
        receipt = rollback_patch(args.repo, args.patch_hash, config)
        with Ledger(audit_directory(args) / "audit.sqlite") as ledger:
            ledger.append(
                {
                    "event": "patch_rolled_back",
                    "head": resolve(args.repo, "HEAD"),
                    "patch_hash": args.patch_hash,
                }
            )
        _emit(receipt)
    elif args.command == "check":
        with tempfile.TemporaryDirectory(prefix="finassist-check-") as temporary:
            snapshot = Path(temporary) / "source"
            manifest = export_snapshot(args.repo, args.head, snapshot, config)
            result = run_recipe(
                config, args.recipe, snapshot, backend=args.backend, approve_local=args.approve_local
            )
            result["snapshot"] = manifest
            result["receipt"].update(
                head=manifest["head"],
                snapshot_hash=digest(canonical(manifest)),
                config_hash=digest(canonical(asdict(config))),
            )
            with Ledger(audit_directory(args) / "audit.sqlite") as ledger:
                ledger.append(
                    {
                        "event": "check_completed",
                        "head": manifest["head"],
                        "receipt_hash": digest(canonical(result["receipt"])),
                        "config_hash": result["receipt"]["config_hash"],
                        "recipe": args.recipe,
                        "passed": result["receipt"]["passed"],
                    }
                )
            _emit(result, args.output)
            _emit(result["receipt"])
            return 0 if result["receipt"]["passed"] else 1
    elif args.command == "finance-check":
        method = {
            "cash": cash_check,
            "tax": tax_estimate,
            "weights": weights_check,
            "observation": observation_check,
        }[args.kind]
        result = method(**_read_json(args.input))
        _emit(result, args.output)
        return 0 if result.get("passed", True) else 1
    elif args.command in {"audit", "reconcile-budget"}:
        with Ledger(audit_directory(args) / "audit.sqlite") as ledger:
            if args.command == "reconcile-budget":
                ledger.settle(args.reservation, Decimal(args.actual_usd))
            if args.command == "audit" and args.export:
                events = ledger.events(after=args.after, limit=args.limit)
                data = b"".join(canonical(event) + b"\n" for event in events)
                check_text(data.decode(), extra_patterns=config.extra_sensitive_patterns)
                write_private(Path(args.export), data)
            _emit(
                {
                    "events_verified": ledger.verify(),
                    "unresolved": ledger.open_reservations(),
                    "incomplete_runs": ledger.incomplete_runs(),
                    "unfinished_workflows": unfinished_workflows([
                        (seq, json.loads(payload)) for seq, payload in ledger.db.execute(
                            "SELECT seq,payload FROM events ORDER BY seq"
                        )
                    ]),
                }
            )
    elif args.command == "render":
        write_private(Path(args.output), report_html(_read_json(args.input)).encode())
        _emit({"output": args.output})
    elif args.command == "scan":
        entries = git(args.repo, "ls-files", "--stage", "-z", binary=True).decode().split("\0")
        modes = {}
        for row in filter(None, entries):
            metadata, name = row.split("\t", 1)
            mode, _blob, stage = metadata.split()
            if stage != "0":
                raise AssistantError("publication_index_unmerged")
            modes[name] = mode
        names = list(modes)
        from .publication import public_images, verify_public_image

        images = public_images(args.repo, set(names))
        findings = []
        for name in filter(None, names):
            try:
                if modes[name] not in {"100644", "100755"}:
                    raise AssistantError("linked_or_special_git_object")
                config.check_path(name, source_only=False, metadata_only=name in images)
            except AssistantError as exc:
                findings.append({"path": name, "code": exc.code})
                continue
            try:
                path = regular_path(args.repo / name)
                if not path.is_file():
                    raise AssistantError("publication_file_missing")
                if path.stat().st_size > (3_000_000 if name == "docs/images/hero.gif" and name in images else 2_000_000):
                    findings.append({"path": name, "code": "publication_file_too_large"})
                    continue
                if name in images:
                    if args.forbid and any(value.casefold() in name.casefold() for value in args.forbid):
                        raise AssistantError("forbidden_publication_text")
                    verify_public_image(path, images[name])
                    continue
                content = read_utf8(path)
                check_text(content, extra_patterns=config.extra_sensitive_patterns)
                if any(value.casefold() in (name + "\n" + content).casefold() for value in args.forbid):
                    findings.append({"path": name, "code": "forbidden_publication_text"})
            except AssistantError as exc:
                findings.append({"path": name, "code": exc.code})
            except UnicodeError:
                findings.append({"path": name, "code": "non_text_publication_file"})
        _emit(
            {
                "files": len(list(filter(None, names))),
                "findings": findings,
                "passed": not findings,
                "qualification": "Supplementary scan; inspect staged bytes and full history before publication.",
            }
        )
        return 1 if findings else 0
    elif args.command == "evaluate":
        if args.history_suite:
            from .history_evaluation import evaluate_history
            from .history_suite import history_approval_hash

            suite_file = regular_path(Path(args.history_suite))
            suite = _read_json(str(suite_file), max_bytes=1_000_000)
            _emit({"suite_hash": history_approval_hash(suite, args.trials), "trials": args.trials,
                   "mode": "model" if args.allow_network else "offline"})
            # A failed final output must not be the first discovery that a paid
            # evaluation was written somewhere unusable. The retained journal
            # also survives interruption/output races after this preflight.
            output = regular_path(Path(args.output))
            if output.exists():
                raise AssistantError("output_exists")
            result = evaluate_history(suite, suite_file.parent, config, audit_directory(args),
                                      trials=args.trials, approved_suite_hash=args.approve_suite,
                                      network_approved=args.allow_network)
        else:
            if args.trials != 1:
                raise AssistantError("history_trials_require_history_suite")
            suite = _read_json(args.suite)
            _emit({"suite_hash": digest(canonical(suite)), "provider": config.provider})
            result = evaluate(suite, config, audit_directory(args), approved_suite_hash=args.approve_suite,
                              network_approved=args.allow_network)
        _emit(result, args.output)
        _emit({"output": args.output, "model_quality_measured": False})
        if result.get("kind") == "history-evaluation" and any(
            run["status"] == "blocked" for case in result["cases"] for run in case["runs"]
        ):
            return 2
    elif args.command == "score":
        if bool(args.compare) != bool(args.compare_labels):
            raise AssistantError("history_comparison_labels_required")
        if args.compare:
            from .history_scoring import compare_history

            result = compare_history(_read_json(args.evaluation), _read_json(args.labels),
                                     _read_json(args.compare), _read_json(args.compare_labels))
        else:
            result = score(_read_json(args.evaluation), _read_json(args.labels))
        _emit(result, args.output)
    elif args.command == "evidence":
        if args.action in {"verify", "migrate"}:
            from .evidence_schema import migrate_evidence_store, verify_evidence_store

            path = audit_directory(args) / "evidence.sqlite"
            result = verify_evidence_store(path) if args.action == "verify" else migrate_evidence_store(path, dry_run=args.dry_run)
            if args.action == "migrate" and not args.dry_run:
                with Ledger(audit_directory(args) / "audit.sqlite") as ledger:
                    ledger.append({"event": "evidence_migrated", "changed": result["written"],
                                   "source_sha256": result.get("source_sha256"),
                                   "destination_sha256": result.get("destination_sha256")})
            _emit(result)
            return 0
        with EvidenceStore(
            audit_directory(args) / "evidence.sqlite",
            extra_sensitive_patterns=config.extra_sensitive_patterns,
        ) as store:
            if args.action == "add":
                if not args.input:
                    raise AssistantError("evidence_input_required")
                _emit(store.add(_read_json(args.input), supersedes=args.supersedes))
            elif args.action in {"approve", "reject"}:
                if args.id is None or args.approve_hash is None:
                    raise AssistantError("evidence_identity_and_hash_required")
                _emit(
                    store.decide(
                        args.id,
                        args.approve_hash,
                        status="approved" if args.action == "approve" else "rejected",
                    )
                )
            else:
                if not args.entity or not args.metric:
                    raise AssistantError("evidence_lookup_required")
                _emit(
                    store.latest_approved(
                        args.entity,
                        args.metric,
                        period_end=args.period_end,
                        unit=args.unit,
                        period_start=args.period_start,
                        period_kind=args.period_kind,
                    )
                )
    elif args.command == "export-kit":
        _emit(export_kit(args.output))
    elif args.command == "verify-gate":
        head = resolve(args.repo, "HEAD")
        if args.expected_head != head:
            raise AssistantError("readiness_head_changed")
        dirty_before = git(
            args.repo, "status", "--porcelain", "--untracked-files=normal", "--", ".", ":(exclude).finassist"
        )
        evidence = (
            _read_json(args.packet), _read_json(args.review),
            [_read_json(path, max_bytes=MAX_WORKFLOW_ARTIFACT_BYTES) for path in args.receipt],
            config, head, audit_directory(args) / "audit.sqlite",
        )
        if args.workflow_plan:
            report = verify_workflow_gate(_read_json(args.workflow_plan), *evidence, args.repo)
        else:
            report = verify_gate(*evidence)
        if resolve(args.repo, "HEAD") != head:
            raise AssistantError("readiness_head_changed")
        if dirty_before or git(
            args.repo, "status", "--porcelain", "--untracked-files=normal", "--", ".", ":(exclude).finassist"
        ):
            report["status"] = "blocked"
            report["blocking_reasons"] = sorted(set(report["blocking_reasons"]) | {"clean_worktree_required"})
        with Ledger(audit_directory(args) / "audit.sqlite") as ledger:
            ledger.append(
                {
                    "event": "readiness_evaluated",
                    "head": head,
                    "status": report["status"],
                    "reasons": report["blocking_reasons"],
                    **({"workflow_plan_hash": report["workflow_plan_hash"]} if args.workflow_plan else {}),
                }
            )
        _emit(report, args.output)
        return 1 if report["blocking_reasons"] else 0
    elif args.command == "github-audit":
        report = inspect_github(args.repository, args.branch, config, network_approved=args.allow_network)
        _emit(report, args.output)
        return 1 if report["issues"] else 0
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.command == "update":
            from .updater import run_upgrade, update_status

            if args.config:
                raise AssistantError("update_does_not_accept_project_config")
            if args.update_action and (args.dry_run or args.yes):
                raise AssistantError("update_status_action_conflict")
            if not args.yes:
                _emit({**update_status(), "dry_run": args.dry_run})
                return 0
            state = audit_directory(args)
            with command_audit(state / "audit.sqlite", "update", Config()) as outcome:
                result = run_upgrade(confirmed=True)
                with Ledger(state / "audit.sqlite") as ledger:
                    ledger.append({"event": "package_upgrade_finished", "install_method": result["install_method"],
                                   "installer_exit_code": result["installer_exit_code"], "status": result["status"]})
                _emit(result)
                outcome["exit_code"] = 0 if result["installer_exit_code"] == 0 else 1
                return outcome["exit_code"]
        if args.command == "doctor" and args.fix and args.check_updates:
            raise AssistantError("doctor_fix_must_remain_offline")
        if args.command == "evidence" and args.dry_run and args.action != "migrate":
            raise AssistantError("evidence_dry_run_requires_migrate")
        if args.command == "doctor" and args.fix:
            from .maintenance import fix_local_state

            path = args.config
            if path is None and Path("finassist.json").exists():
                path = Path("finassist.json")
            _emit(fix_local_state(path, audit_directory(args)))
            return 0
        if args.command == "config":
            from .config_compat import apply_config_migration, preview_config_migration

            if args.path and args.config and regular_path(args.path) != regular_path(args.config):
                raise AssistantError("config_migration_path_ambiguous")
            path = args.path or args.config or Path("finassist.json")
            plan = preview_config_migration(path)
            if args.dry_run:
                _emit({**plan.report(), "written": False, "backup": None})
                return 0
            config = load_config(path, content=plan.after)
            state = audit_directory(args)
            with command_audit(state / "audit.sqlite", "config-migrate", config) as outcome:
                result = apply_config_migration(plan)
                with Ledger(state / "audit.sqlite") as ledger:
                    ledger.append({"event": "config_migrated", "source_sha256": digest(plan.before),
                                   "target_sha256": digest(plan.after), "changed": result["written"]})
                _emit(result)
                outcome["exit_code"] = 0
                return 0
        if args.command == "guide":
            if args.topic is None:
                _emit(guide_index())
            else:
                text = guide_text(args.topic)
                stream = getattr(sys.stdout, "buffer", None)
                if stream is None:
                    sys.stdout.write(text)
                else:
                    stream.write(text.encode("utf-8"))
            return 0
        if args.command == "dashboard":
            from .dashboard import serve_dashboard

            return serve_dashboard(args.config or Path("finassist.json"), audit_directory(args), args.port)
        if args.command == "workflow" and args.workflow_action == "timeline":
            from .workflow_inspection import workflow_timeline

            report = workflow_timeline(audit_directory(args) / "audit.sqlite", args.run_id,
                                       after=args.after, limit=args.limit, through=args.through, anchor=args.anchor)
            _emit(report, args.output)
            if args.output:
                _emit({"output": args.output, "report_hash": report["report_hash"]})
            return 0
        if args.command == "gate":
            from .model_gate import EXIT_CODES, model_gate

            if args.config:
                raise AssistantError("gate_configuration_must_come_from_policy")
            if regular_path(Path(args.output)).exists():
                raise AssistantError("output_exists")
            report = model_gate(args.repo, args.base, args.head, args.policy, args.policy_sha256, args.state_dir)
            _emit(report, args.output)
            _emit({"verdict": report["verdict"], "report_hash": report["report_hash"]})
            return EXIT_CODES[report["verdict"]]
        if args.command == "ci":
            from .ci_gate import ci_gate
            from .ci_policy import read_document
            from .github_context import pull_request_context

            if args.config:
                raise AssistantError("ci_configuration_must_come_from_policy")
            if args.audit_dir is None and args.state_dir is None:
                raise AssistantError("ci_state_directory_required")
            context = pull_request_context(read_document(args.event), args.event_name, args.repository)
            report = ci_gate(args.repo, context, args.policy, args.policy_sha256, audit_directory(args))
            _emit(report, args.output)
            if args.output:
                _emit({"output": args.output, "status": report["status"], "report_hash": report["report_hash"]})
            return 0 if report["status"] == "passed" else 1
        config = load_config(args.config)
        if not (args.command == "doctor" and args.check_updates):
            from .update_check import maybe_notify

            maybe_notify(network_allowed=config.allow_network, command=args.command)
        if args.command == "evidence" and (args.action == "verify" or (args.action == "migrate" and args.dry_run)):
            return execute(args, config)
        if args.command == "workflow" and args.workflow_action in WORKFLOW_STATE_ACTIONS:
            # These actions have their own replayable workflow lifecycle. A crash
            # leaves a checkpoint/unknown attempt, not an unclosable generic run.
            return execute(args, config)
        if args.command in {"doctor", "demo", "audit", "scan", "render"}:
            return execute(args, config)
        state = audit_directory(args)
        with command_audit(state / "audit.sqlite", args.command, config) as outcome:
            outcome["exit_code"] = execute(args, config)
            return outcome["exit_code"]
    except AssistantError as exc:
        from .config_compat import ConfigCompatibilityError
        from .evidence_schema import EvidenceSchemaError

        details = exc.public_details if isinstance(exc, (ConfigCompatibilityError, EvidenceSchemaError)) else {}
        print(json.dumps({"status": "error", "code": exc.code, **details}), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, InvalidOperation, sqlite3.Error) as exc:
        # Report a stable class, never raw provider errors, source or private paths.
        print(
            json.dumps({"status": "error", "code": "invalid_input", "kind": type(exc).__name__}),
            file=sys.stderr,
        )
        return 2
