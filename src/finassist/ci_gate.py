"""Unattended checks under a pinned CI envelope; never approve model requests."""

from dataclasses import asdict
import json
from pathlib import Path

from .ci_policy import load_ci_policy, repository_name
from .errors import OperationOutcomeUnknown
from .github_context import PullRequestContext, verify_origin
from .ledger import Ledger
from .scope import build_packet, git, resolve, review_omissions
from .security import canonical, digest, regular_path
from .workflow import build_workflow_plan, preflight_workflow
from .workflow_execution import create_run, execute_run
from .workflow_state import WorkflowStore, unfinished_workflows


def _dirty(repo: Path) -> bool:
    return bool(git(repo, "status", "--porcelain", "--untracked-files=normal", "--", ".", ":(exclude).finassist"))


def ci_gate(repo: Path, context: PullRequestContext, policy_path: str, policy_sha256: str, state_dir: Path) -> dict:
    repo = regular_path(repo)
    verify_origin(repo, context.repository)
    policy = load_ci_policy(repo, context.base_sha, policy_path, policy_sha256)
    document, config = policy.document, policy.config
    blockers = set()
    if repository_name(document["repository"]) != context.repository:
        blockers.add("ci_policy_repository_mismatch")
    if context.base_branch not in document["base_branches"]:
        blockers.add("ci_base_branch_not_allowed")
    if context.head_repository != context.repository and document["forks"] != "checks-only":
        blockers.add("ci_fork_not_allowed")
    if resolve(repo, "HEAD") != context.head_sha:
        blockers.add("ci_checkout_revision_mismatch")
    if _dirty(repo):
        blockers.add("clean_worktree_required")
    steps = len(document["workflow"]["steps"])
    if steps > document["max_steps"] or steps * config.timeout_seconds > document["max_check_seconds"]:
        blockers.add("ci_check_budget_exceeded")
    if document["review"] == "required":
        blockers.add("ci_model_review_required")
    state_path = regular_path(Path(state_dir) / "audit.sqlite")
    if state_path.exists():
        with Ledger(state_path, read_only=True) as ledger, ledger.transaction():
            ledger.verify()
            events = [(seq, json.loads(raw)) for seq, raw in ledger.db.execute(
                "SELECT seq,payload FROM events ORDER BY seq")]
            if ledger.open_reservations() or ledger.incomplete_runs() or unfinished_workflows(events):
                blockers.add("ci_state_unresolved")
    packet, plan, identifier, execution = None, None, None, None
    if not blockers:
        packet = build_packet(repo, context.base_sha, context.head_sha, config)
        if any(any(path.startswith(guard) if guard.endswith("/") else path == guard
                   for guard in policy.guarded_paths) for path in packet["changed_paths"]):
            blockers.add("ci_guarded_change_requires_review")
        if review_omissions(packet):
            blockers.add("ci_coverage_incomplete")
        if not packet["changed_paths"]:
            blockers.add("ci_changes_absent")
    if packet is not None and not blockers:
        plan = build_workflow_plan(document["workflow"], packet, repo, config)
        blockers.update(preflight_workflow(plan, packet, repo, config)["blocking_reasons"])
    if plan is not None and not blockers:
        with WorkflowStore(state_dir, create=True) as store:
            store.ledger.append({
                "event": "ci_policy_authorized", "policy_hash": policy.sha256, "policy_revision": policy.revision,
                "plan_hash": plan["plan_hash"], "head": context.head_sha, "mode": "checks-only",
            })
            # Approval comes from the pinned, base-revision policy after all
            # scope/event/budget checks, not from PR text or a self-issued flag.
            identifier = create_run(store, plan, packet, repo, config, approved_plan=plan["plan_hash"],
                                    backend=document["backend"])
            try:
                execution = execute_run(store, identifier, repo, config, approved_plan=plan["plan_hash"],
                                        max_steps=document["max_steps"])
            except OperationOutcomeUnknown:
                blockers.add("ci_check_outcome_unknown")
            else:
                blockers.update(execution["blocking_reasons"])
                if execution["status"] != "completed-checks" or len(execution["check_records"]) != steps:
                    blockers.add("ci_checks_incomplete")
    if resolve(repo, "HEAD") != context.head_sha or _dirty(repo):
        blockers.add("ci_source_changed")
    report = {
        "schema_version": 1, "status": "blocked" if blockers else "passed", "mode": "checks-only",
        "context": context.document(), "policy_hash": policy.sha256, "policy_revision": policy.revision,
        "config_hash": digest(canonical(asdict(config))),
        "packet_hash": packet["packet_hash"] if packet else None, "plan_hash": plan["plan_hash"] if plan else None,
        "workflow_run_id": identifier, "blocking_reasons": sorted(blockers),
        "checks": {"required": steps, "completed": len(execution["check_records"]) if execution else 0},
        "model_review": "required-unavailable" if document["review"] == "required" else "not-requested",
        "readiness_evaluated": False, "merge_authority": False, "deployment_authority": False,
        "qualification": "Deterministic check gate only, not AI approval, full review readiness or proof of financial "
        "correctness. Trusted CI wiring and protected base policy are prerequisites. Recipes run candidate source "
        "in the configured isolated image; check semantics require independent review. GitHub merge queues and "
        "unattended model calls are not supported by this policy version.",
    }
    report["report_hash"] = digest(canonical(report))
    if identifier:
        with Ledger(Path(state_dir) / "audit.sqlite") as ledger:
            ledger.verify()
            ledger.append({"event": "ci_gate_evaluated", "policy_hash": policy.sha256, "head": context.head_sha,
                           "report_hash": report["report_hash"], "status": report["status"],
                           "reasons": report["blocking_reasons"]})
    return report
