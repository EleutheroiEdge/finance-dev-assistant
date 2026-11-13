"""Explicit commands: inspect, review, propose, apply and verify are separate actions."""

from __future__ import annotations

from .platform_support import read_utf8

from decimal import InvalidOperation
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time

from .auditing import command_audit
from .config import Config, config_hash, load_config, PACKET_FILE_BYTES
from .demo import run_demo
from .errors import AssistantError, error_record
from .state_location import state_location
from .error_hints import error_fields, explain_arguments, explain_parser, run_explain
from .evaluation import evaluate, score
from .evidence_store import EvidenceStore
from .finance import cash_check, observation_check, tax_estimate, weights_check
from .ledger import Ledger
from .integrations import export_kit
from .guides import guide_index, guide_listing, guide_text
from .github_audit import inspect_github
from .patching import apply_patch_artifact, rollback_patch
from .proposal import propose
from .render import report_html
from .readiness import verify_gate
from .review import review_packet
from .runner import run_recipe
from .scope import build_packet, config_token_guard, git, plan_packet, resolve, triage
from .security import canonical, check_text, digest, regular_path, write_private
from .workspace import export_snapshot
from .workflow import build_workflow_plan, preflight_workflow, verify_workflow_gate
from .workflow_execution import abandon_run, cancel_run, create_run, execute_run, inspect_run, reconcile_run, retry_step, validate_run
from .workflow_state import MAX_WORKFLOW_ARTIFACT_BYTES, WorkflowStore, run_phase
from .workflow_packs import export_resolution, read_bundle, resolve_bundle, verify_resolution
from .cli_parser import parser, WORKFLOW_STATE_ACTIONS


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


def audit_directory(args) -> Path:
    return state_location(args)[0]


def _execute_workflow(args, config: Config) -> int:
    action = args.workflow_action
    if action in {"run", "resume"} and not 1 <= args.max_steps <= 64:
        raise AssistantError("workflow_step_limit_invalid")
    if action == "run":
        plan, packet = _read_json(args.plan), _read_json(args.packet, max_bytes=PACKET_FILE_BYTES)
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
        elif action == "abandon":
            result = abandon_run(store, args.run_id, approved_plan=args.approve_plan,
                                 confirm_cleanup=args.confirm_cleanup)
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
        from .detect import run_init

        return run_init(args, config)
    elif args.command == "doctor":
        from .doctor_commands import doctor_result

        report, exit_code = doctor_result(args, config)
        if getattr(args, "format", "json") == "text":
            from .text_view import doctor_output

            print(doctor_output(report, args))
        else:
            _emit(report)
        return exit_code
    elif args.command == "demo":
        result = run_demo()
        _emit(result, args.output)
        return 0 if result["status"] == "PASS" else 1
    elif args.command == "plan":
        packet, summary = plan_packet(args.repo, args.base, args.head, config, args.config, args.output)
        _emit(packet, args.output)
        _emit(summary)
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
        packet = _read_json(args.packet, max_bytes=PACKET_FILE_BYTES)
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
            ledger.append({**event, "head": result["head"], "config_hash": config_hash(config)})
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
        packet = _read_json(args.packet, max_bytes=PACKET_FILE_BYTES)
        method = review_packet if args.command == "review" else propose
        result = method(
            packet,
            config,
            audit_directory(args) / "audit.sqlite",
            network_approved=args.allow_network,
            approved_packet_hash=args.approve_packet,
            token_guard=config_token_guard(config, args.repo),
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
                config_hash=config_hash(config),
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
        from .audit_commands import run_audit

        _emit(run_audit(args, config, audit_directory(args)))
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
                check_text(content, extra_patterns=config.extra_sensitive_patterns, source_path=name,
                           placeholders=config.placeholder_credential_paths)
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
    elif args.command == "report":
        from .report_trace import read_trace_input, trace_markdown
        report = read_trace_input(args.report)
        judgments = read_trace_input(args.adjudications) if args.adjudications else None
        write_private(args.output, trace_markdown(report, judgments).encode("utf-8"))
        _emit({"report_hash": report["report_hash"], "written": True, "advisory_only": True})
    elif args.command == "score":
        if args.report:
            from .report_trace import read_trace_input, score_gate_report
            if args.labels or args.compare or args.compare_labels:
                raise AssistantError("score_input_mode_conflict")
            report = read_trace_input(Path(args.report))
            judgments = read_trace_input(Path(args.adjudications)) if args.adjudications else None
            _emit(score_gate_report(report, judgments), args.output)
            return 0
        if args.adjudications:
            raise AssistantError("score_input_mode_conflict")
        if not args.labels:
            raise AssistantError("score_labels_required")
        if bool(args.compare) != bool(args.compare_labels):
            raise AssistantError("history_comparison_labels_required")
        if args.compare:
            from .history_scoring import compare_history

            result = compare_history(_read_json(args.evaluation, max_bytes=64_000_000),
                                     _read_json(args.labels, max_bytes=16_000_000),
                                     _read_json(args.compare, max_bytes=64_000_000),
                                     _read_json(args.compare_labels, max_bytes=16_000_000))
        else:
            result = score(_read_json(args.evaluation, max_bytes=64_000_000),
                           _read_json(args.labels, max_bytes=16_000_000))
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
            _read_json(args.packet, max_bytes=PACKET_FILE_BYTES), _read_json(args.review),
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
    """One command. Within it, a text already screened under the same rules is not screened again."""
    from .security import screening_cache

    with screening_cache():
        return _main(argv)


def _main(argv: list[str] | None) -> int:
    command = None
    try:
        root, argv = parser(), sys.argv[1:] if argv is None else list(argv)
        if (rest := explain_arguments(root, argv)) is not None:  # Parsed without echoing input.
            return run_explain(explain_parser().parse_args(rest))
        args = root.parse_args(argv)
        command = args.command
        if args.command == "init" and args.detect and not args.write:
            from .detect import run_init  # A proposal only: no state is written.

            return run_init(args, load_config(args.config))
        if args.command == "triage":
            from .triage_cli import execute_triage

            if args.config or args.audit_dir:
                raise AssistantError("triage_configuration_or_audit_not_supported")
            report, exit_code = execute_triage(args)
            _emit({"report_hash": digest(canonical(report)), "advisory_only": True,
                   "default_matrix_required": True, "model_called": False})
            return exit_code
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
        if args.command == "state":
            # status and a clean dry run write nothing, so they stay ahead of configuration, the update
            # notice and the command audit. clean --apply records a removal only from run_state_clean.
            if args.state_action == "clean":
                from .state_clean import run_state_clean

                return run_state_clean(args)
            from .state_report import run_state

            return run_state(args)
        if args.command == "doctor" and any(
            value is not None
            for value in (args.policy, args.policy_file, args.policy_sha256, args.repo, args.base, args.head)
        ):
            from .onboarding import run_policy_doctor

            return run_policy_doctor(args)
        if args.command == "doctor" and args.fix and args.check_updates:
            raise AssistantError("doctor_fix_must_remain_offline")
        if args.command == "evidence" and args.dry_run and args.action != "migrate":
            raise AssistantError("evidence_dry_run_requires_migrate")
        if args.command == "doctor" and args.fix:
            from .doctor_commands import fix_doctor

            _emit(fix_doctor(args, audit_directory(args)))
            return 0
        if args.command == "config" and args.config_action == "schema":
            from .document_schemas import installed_document_schema

            _emit(installed_document_schema(args.kind))
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
                _emit(guide_index()) if args.json else print(guide_listing(), end="")
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
        print(json.dumps(error_record(exc, command, error_fields(exc.code))), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, InvalidOperation, sqlite3.Error) as exc:
        # Report a stable class, never raw provider errors, source or private paths.
        print(
            json.dumps({"status": "error", "code": "invalid_input", "kind": type(exc).__name__,
                        **error_fields("invalid_input")}),
            file=sys.stderr,
        )
        return 2
