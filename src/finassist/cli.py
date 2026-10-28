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

from . import __version__
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


def _read_json(path: str) -> dict:
    file = regular_path(Path(path))
    if file.stat().st_size > 2_000_000:
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
    root.add_argument("--version", action="version", version=__version__)
    root.add_argument("--config", type=Path, help="Explicit reviewed JSON configuration; default is offline")
    root.add_argument(
        "--audit-dir",
        type=Path,
        help="Private command audit directory; default is the operation state directory",
    )
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create offline-by-default configuration")
    init.add_argument("--output", default="finassist.json")
    init.add_argument("--provider", choices=sorted(PROVIDERS), default="offline")
    init.add_argument("--model", default="")
    init.add_argument("--profile", help="Name in the configured profile registry")
    commands.add_parser(
        "doctor", help="Check runtime, provider setup and container availability without network"
    )
    demo = commands.add_parser("demo", help="Run fictional finance checks offline")
    demo.add_argument("--output")
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
        "evaluate", help="Run a frozen synthetic discovery suite; labels stay out of context"
    )
    evaluation.add_argument("--suite", required=True)
    evaluation.add_argument("--approve-suite")
    evaluation.add_argument("--allow-network", action="store_true")
    evaluation.add_argument("--state-dir", type=Path, default=Path(".finassist"))
    evaluation.add_argument("--output", required=True)
    scoring = commands.add_parser("score", help="Score an evaluation with independent operator judgments")
    scoring.add_argument("--evaluation", required=True)
    scoring.add_argument("--labels", required=True)
    scoring.add_argument("--output", required=True)
    evidence = commands.add_parser(
        "evidence", help="Append local analyst evidence and record explicit approval"
    )
    evidence.add_argument("action", choices=["add", "approve", "reject", "latest"])
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
        _emit(doctor_report(config))
    elif args.command == "demo":
        result = run_demo()
        _emit(result, args.output)
        return 0 if result["status"] == "PASS" else 1
    elif args.command == "plan":
        packet = build_packet(args.repo, args.base, args.head, config)
        _emit(packet, args.output)
        _emit({"packet_hash": packet["packet_hash"], "output": args.output, "triage": triage(packet, config)})
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
        from .publication import public_images, verify_public_png

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
                if path.stat().st_size > 2_000_000:
                    findings.append({"path": name, "code": "publication_file_too_large"})
                    continue
                if name in images:
                    if args.forbid and any(value.casefold() in name.casefold() for value in args.forbid):
                        raise AssistantError("forbidden_publication_text")
                    verify_public_png(path, images[name])
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
        suite = _read_json(args.suite)
        _emit({"suite_hash": digest(canonical(suite)), "provider": config.provider})
        result = evaluate(
            suite,
            config,
            audit_directory(args),
            approved_suite_hash=args.approve_suite,
            network_approved=args.allow_network,
        )
        _emit(result, args.output)
        _emit({"output": args.output, "model_quality_measured": False})
    elif args.command == "score":
        _emit(score(_read_json(args.evaluation), _read_json(args.labels)), args.output)
    elif args.command == "evidence":
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
        report = verify_gate(
            _read_json(args.packet),
            _read_json(args.review),
            [_read_json(path) for path in args.receipt],
            config,
            head,
            audit_directory(args) / "audit.sqlite",
        )
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
        if args.command == "dashboard":
            from .dashboard import serve_dashboard

            return serve_dashboard(args.config or Path("finassist.json"), audit_directory(args), args.port)
        config = load_config(args.config)
        if args.command in {"doctor", "demo", "audit", "scan", "render"}:
            return execute(args, config)
        state = audit_directory(args)
        with command_audit(state / "audit.sqlite", args.command, config) as outcome:
            outcome["exit_code"] = execute(args, config)
            return outcome["exit_code"]
    except AssistantError as exc:
        print(json.dumps({"status": "error", "code": exc.code}), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, InvalidOperation, sqlite3.Error) as exc:
        # Report a stable class, never raw provider errors, source or private paths.
        print(
            json.dumps({"status": "error", "code": "invalid_input", "kind": type(exc).__name__}),
            file=sys.stderr,
        )
        return 2
