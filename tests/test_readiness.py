from copy import deepcopy
from dataclasses import asdict, replace
from decimal import Decimal
import json
import subprocess

import httpx
import pytest

from finassist.config import Config
from finassist.errors import AssistantError
from finassist.github_audit import inspect_github
from finassist.ledger import Ledger
from finassist.readiness import verify_gate
from finassist.review import review_packet
from finassist.scope import build_packet
from finassist.security import canonical, digest
from test_providers_review import envelope, model_config, response


@pytest.fixture
def gate_bundle(repository, tmp_path, monkeypatch):
    repo, base, head = repository
    config = replace(
        model_config(),
        recipes={"unit": ["python", "-m", "pytest"], "cash": ["python", "check_cash.py"]},
        required_recipes=("unit",),
        runner_image="sha256:" + "a" * 64,
    )
    packet = build_packet(repo, base, head, config)
    value = response(packet)
    value["findings"] = []
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    state = tmp_path / "audit.db"
    review = review_packet(
        packet,
        config,
        state,
        network_approved=True,
        approved_packet_hash=packet["packet_hash"],
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=envelope(json.dumps(value)))),
    )
    snapshot = {
        "head": head,
        "files": [
            {"path": file["path"], "sha256": file["after_hash"], "mode": file["after_mode"]}
            for file in packet["files"]
        ],
    }
    receipt = {
        "head": head,
        "recipe": "unit",
        "snapshot_hash": digest(canonical(snapshot)),
        "runner_image": config.runner_image,
        "argv_hash": digest(canonical(config.recipes["unit"])),
        "passed": True,
        "cleanup_verified": True,
        "isolation": "network-disabled container",
        "config_hash": digest(canonical(asdict(config))),
    }
    with Ledger(state) as ledger:
        ledger.append(
            {
                "event": "check_completed",
                "head": head,
                "receipt_hash": digest(canonical(receipt)),
                "config_hash": receipt["config_hash"],
            }
        )
    return packet, review, [{"receipt": receipt, "snapshot": snapshot}], config, head, state


def test_gate_accepts_bound_evidence_but_grants_no_authority(gate_bundle):
    report = verify_gate(*gate_bundle)
    assert report["status"] == "eligible-for-human-review"
    assert not report["merge_authority"] and not report["deployment_authority"]


def test_workflow_blocks_green_unit_tests_without_financial_evidence(gate_bundle, repository, tmp_path, capsys):
    from finassist.cli import main
    from finassist.config import save_config
    from finassist.workflow import build_workflow_plan, verify_workflow_gate

    packet, review, checks, config, head, state = gate_bundle
    repo, _base, _head = repository
    # A synthetic source file stands in for a project's versioned rule reference.
    template = {
        "schema_version": 1, "name": "cash-validation", "goal": "Synthetic cash invariant review",
        "methodology": ["src/cash.py"],
        "requirements": [
            {"id": "unit-tests", "recipe": "unit", "methodology": ["src/cash.py"]},
            {"id": "cash-conservation", "recipe": "cash", "methodology": ["src/cash.py"]},
        ],
        "steps": [
            {"id": "unit", "requirement": "unit-tests", "depends_on": []},
            {"id": "cash", "requirement": "cash-conservation", "depends_on": ["unit"]},
        ],
    }
    plan = build_workflow_plan(template, packet, repo, config)
    assert verify_gate(*gate_bundle)["status"] == "eligible-for-human-review"
    result = verify_workflow_gate(plan, *gate_bundle, repo)
    assert result["status"] == "blocked"
    assert result["workflow_missing_requirements"] == ["cash-conservation"]
    assert "required_recipe_evidence_missing" in result["blocking_reasons"]
    # An unlogged green receipt cannot satisfy the extra obligation.
    cash = deepcopy(checks[0])
    cash["receipt"].update(recipe="cash", argv_hash=digest(canonical(config.recipes["cash"])))
    checks.append(cash)
    assert "check_receipt_missing_or_stale" in verify_workflow_gate(
        plan, *gate_bundle, repo
    )["blocking_reasons"]
    with Ledger(state) as ledger:
        ledger.append({
            "event": "check_completed", "head": head,
            "receipt_hash": digest(canonical(cash["receipt"])),
            "config_hash": cash["receipt"]["config_hash"],
        })
    result = verify_workflow_gate(plan, *gate_bundle, repo)
    assert result["status"] == "eligible-for-human-review"
    assert not result["workflow_missing_requirements"]
    assert not result["merge_authority"] and not result["deployment_authority"]
    # Required evidence is added without changing the original policy/receipt hashes.
    assert result["policy_hash"] == digest(canonical(asdict(config)))
    # Exercise the actual CLI flag, audit correlation and unchanged default gate.
    config_path = tmp_path / "config.json"
    save_config(config_path, config)
    inputs = {"packet": packet, "review": review, "unit": checks[0], "cash": cash, "plan": plan}
    for name, value in inputs.items():
        (tmp_path / (name + ".json")).write_bytes(canonical(value))
    state.rename(tmp_path / "audit.sqlite")
    args = [
        "--config", str(config_path), "--audit-dir", str(tmp_path), "verify-gate", "--repo", str(repo),
        "--expected-head", head, "--packet", str(tmp_path / "packet.json"),
        "--review", str(tmp_path / "review.json"), "--receipt", str(tmp_path / "unit.json"),
    ]
    assert main(args) == 0
    assert "workflow_plan_hash" not in json.loads(capsys.readouterr().out)
    args.extend(["--workflow-plan", str(tmp_path / "plan.json")])
    assert main(args) == 1
    assert json.loads(capsys.readouterr().out)["workflow_missing_requirements"] == ["cash-conservation"]
    args.extend(["--receipt", str(tmp_path / "cash.json")])
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["workflow_plan_hash"] == plan["plan_hash"]
    with Ledger(tmp_path / "audit.sqlite") as ledger:
        events = ledger.events()
    assert any(item["payload"].get("workflow_plan_hash") == plan["plan_hash"] for item in events)


def test_additional_recipe_api_rejects_unconfigured_checks(gate_bundle):
    with pytest.raises(AssistantError, match="readiness_additional_recipe_invalid"):
        verify_gate(*gate_bundle, additional_recipes=("unconfigured",))


def test_readiness_blocks_unfinished_workflow_until_explicit_cancellation(gate_bundle, repository, tmp_path):
    from finassist.workflow import build_workflow_plan
    from finassist.workflow_execution import cancel_run, create_run
    from finassist.workflow_state import WorkflowStore

    packet, review, checks, config, head, state = gate_bundle
    repo, _base, _head = repository
    assert verify_gate(*gate_bundle)["status"] == "eligible-for-human-review"
    target = tmp_path / "audit.sqlite"
    state.rename(target)
    template = {
        "schema_version": 1, "name": "unit-validation", "goal": "Synthetic workflow obligation",
        "methodology": ["src/cash.py"],
        "requirements": [{"id": "unit-tests", "recipe": "unit", "methodology": ["src/cash.py"]}],
        "steps": [{"id": "unit", "requirement": "unit-tests", "depends_on": []}],
    }
    plan = build_workflow_plan(template, packet, repo, config)
    with WorkflowStore(tmp_path) as store:
        identifier = create_run(store, plan, packet, repo, config, approved_plan=plan["plan_hash"],
                                backend="local", approve_local=True)
        assert "unfinished_workflow" in verify_gate(packet, review, checks, config, head, target)["blocking_reasons"]
        cancel_run(store, identifier, approved_plan=plan["plan_hash"])
        assert verify_gate(packet, review, checks, config, head, target)["status"] == "eligible-for-human-review"


@pytest.mark.parametrize(
    "mutation,code",
    [
        (lambda p, r, c: c[0]["receipt"].update(head="b" * 40), "check_revision_mismatch"),
        (lambda p, r, c: c[0]["snapshot"].update(files=[]), "snapshot_integrity_failed"),
        (lambda p, r, c: c[0]["receipt"].update(passed=False), "check_failed_or_cleanup_unknown"),
        (lambda p, r, c: c[0]["receipt"].update(cleanup_verified=False), "check_failed_or_cleanup_unknown"),
        (lambda p, r, c: c[0]["receipt"].update(runner_image="sha256:" + "b" * 64), "runner_image_changed"),
        (lambda p, r, c: c[0]["receipt"].update(argv_hash="b" * 64), "recipe_changed"),
        (lambda p, r, c: c.clear(), "required_recipe_evidence_missing"),
        (lambda p, r, c: r.update(packet_hash="b" * 64), "review_packet_mismatch"),
        (lambda p, r, c: r.update(model="another-model"), "review_policy_changed"),
    ],
)
def test_gate_fails_closed_for_changed_incomplete_or_failed_evidence(gate_bundle, mutation, code):
    packet, review, checks, config, head, state = gate_bundle
    packet, review, checks = deepcopy(packet), deepcopy(review), deepcopy(checks)
    mutation(packet, review, checks)
    assert code in verify_gate(packet, review, checks, config, head, state)["blocking_reasons"]


def test_gate_blocks_unreconciled_billing_and_unconfigured_requirements(gate_bundle):
    packet, review, checks, config, head, state = gate_bundle
    with Ledger(state) as ledger:
        ledger.reserve(Decimal("0.1"), Decimal("1"), Decimal("1"))
    result = verify_gate(packet, review, checks, replace(config, required_recipes=()), head, state)
    assert "unreconciled_spend" in result["blocking_reasons"]
    assert "required_recipes_unconfigured" in result["blocking_reasons"]


def test_gate_rejects_fabricated_receipts_even_when_hashes_are_self_consistent(gate_bundle):
    packet, review, checks, config, head, state = gate_bundle
    checks[0]["receipt"]["isolation"] = "altered container claim"
    assert (
        "check_receipt_missing_or_stale"
        in verify_gate(packet, review, checks, config, head, state)["blocking_reasons"]
    )
    review["qualification"] = "changed after review"
    assert (
        "review_receipt_missing_or_stale"
        in verify_gate(packet, review, checks, config, head, state)["blocking_reasons"]
    )


@pytest.mark.parametrize("rules", [[], [{"type": "pull_request"}]])
def test_github_inspection_uses_only_fixed_gets_and_identifies_missing_protection(monkeypatch, rules):
    calls = []
    for name in ("GH_HOST", "GH_REPO", "GH_DEBUG", "GH_CONFIG_DIR", "HTTPS_PROXY", "OPENAI_API_KEY"):
        monkeypatch.setenv(name, "synthetic-override")

    def execute(argv, **kwargs):
        calls.append(argv)
        assert argv[1] == "api" and argv[-2:] == ["--hostname", "github.com"]
        assert not any(v in argv for v in ("--method", "--input", "--field", "-X"))
        assert not any(
            name in kwargs["env"]
            for name in ("GH_HOST", "GH_REPO", "GH_DEBUG", "GH_CONFIG_DIR", "HTTPS_PROXY", "OPENAI_API_KEY")
        )
        assert kwargs["env"]["GH_PROMPT_DISABLED"] == "1"
        endpoint = argv[2]
        if endpoint.endswith("/protection"):
            return subprocess.CompletedProcess(argv, 1, json.dumps({"status": "404"}), "ignored diagnostic")
        if "/rules/" in endpoint:
            value = rules
        elif "/branches/" in endpoint:
            value = {"name": "main", "protected": False, "commit": {"sha": "a" * 40}}
        else:
            value = {"full_name": "example/repository"}
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    monkeypatch.setattr("finassist.platform_support.shutil.which", lambda _: "/trusted/gh")
    monkeypatch.setattr("finassist.github_audit.subprocess.run", execute)
    config = replace(Config(), allow_network=True)
    report = inspect_github("example/repository", "main", config, network_approved=True)
    assert ("branch_unprotected" in report["issues"]) is (not bool(rules))
    assert ("ruleset_equivalence_requires_review" in report["issues"]) is bool(rules)
    assert not report["merge_authority"] and report["status"] == "attention-required"
    assert len(calls) == 5
    with pytest.raises(AssistantError, match="network_not_approved"):
        inspect_github("example/repository", "main", config, network_approved=False)
    for repository, branch in [("other/repository?x=1", "main"), ("example/repository", "../outside")]:
        with pytest.raises(AssistantError):
            inspect_github(repository, branch, config, network_approved=True)
    assert len(calls) == 5


def test_gate_distinguishes_its_own_run_from_an_unfinished_operation(gate_bundle):
    from finassist.auditing import command_audit
    from finassist.ledger import CURRENT_RUN

    packet, review, checks, config, head, state = gate_bundle
    with command_audit(state, "verify-gate", config):
        assert (
            verify_gate(packet, review, checks, config, head, state)["status"] == "eligible-for-human-review"
        )
    token = CURRENT_RUN.set("b" * 32)
    try:
        with Ledger(state) as ledger:
            ledger.append({"event": "command_started", "command": "apply"})
    finally:
        CURRENT_RUN.reset(token)
    assert (
        "unfinished_operation" in verify_gate(packet, review, checks, config, head, state)["blocking_reasons"]
    )


def test_gate_rejects_stale_receipts(gate_bundle, monkeypatch):
    from datetime import datetime, timedelta

    class Future(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(days=2)

    monkeypatch.setattr("finassist.readiness.datetime", Future)
    reasons = verify_gate(*gate_bundle)["blocking_reasons"]
    assert "review_receipt_missing_or_stale" in reasons and "check_receipt_missing_or_stale" in reasons


@pytest.mark.parametrize("evidence_time", ["old", "future", "naive", "invalid", None])
def test_newly_adopted_check_cannot_refresh_stale_or_invalid_execution_time(gate_bundle, evidence_time):
    from datetime import datetime, timedelta, timezone

    packet, review, checks, config, head, state = gate_bundle
    now = datetime.now(timezone.utc)
    times = {
        "old": (now - timedelta(days=2)).isoformat(),
        "future": (now + timedelta(days=2)).isoformat(),
        "naive": now.replace(tzinfo=None).isoformat(), "invalid": "not-a-time", None: None,
    }
    # Give the adopted document a distinct identity, so its original event cannot match.
    checks[0]["receipt"]["output_hash"] = "b" * 64
    with Ledger(state) as ledger:
        ledger.append({
            "event": "check_completed", "head": head, "config_hash": checks[0]["receipt"]["config_hash"],
            "receipt_hash": digest(canonical(checks[0]["receipt"])),
            "evidence_recorded_at": times[evidence_time],
        })
    assert "check_receipt_missing_or_stale" in verify_gate(
        packet, review, checks, config, head, state
    )["blocking_reasons"]


def test_legacy_packets_are_inspectable_but_not_readiness_evidence(gate_bundle):
    from finassist.scope import verify_packet

    packet, review, checks, config, head, state = gate_bundle
    packet = deepcopy(packet)
    packet["schema_version"] = 1
    for file in packet["files"]:
        file.pop("before_mode")
        file.pop("after_mode")
    packet["packet_hash"] = digest(
        canonical({key: value for key, value in packet.items() if key != "packet_hash"})
    )
    verify_packet(packet)
    assert (
        "packet_mode_evidence_missing"
        in verify_gate(packet, review, checks, config, head, state)["blocking_reasons"]
    )


def test_gate_rejects_even_audited_snapshots_missing_reviewed_source(gate_bundle):
    packet, review, checks, config, head, state = gate_bundle
    checks[0]["snapshot"]["files"] = []
    checks[0]["receipt"]["snapshot_hash"] = digest(canonical(checks[0]["snapshot"]))
    with Ledger(state) as ledger:
        ledger.append(
            {
                "event": "check_completed",
                "head": head,
                "receipt_hash": digest(canonical(checks[0]["receipt"])),
                "config_hash": checks[0]["receipt"]["config_hash"],
            }
        )
    assert (
        "snapshot_scope_mismatch"
        in verify_gate(packet, review, checks, config, head, state)["blocking_reasons"]
    )


def test_gate_rejects_tests_run_under_a_different_configuration(gate_bundle):
    packet, review, checks, config, head, state = gate_bundle
    checks[0]["receipt"]["config_hash"] = digest(
        canonical(asdict(replace(config, allow_paths=("README.md",))))
    )
    with Ledger(state) as ledger:
        ledger.append(
            {
                "event": "check_completed",
                "head": head,
                "receipt_hash": digest(canonical(checks[0]["receipt"])),
                "config_hash": checks[0]["receipt"]["config_hash"],
            }
        )
    assert (
        "check_configuration_changed"
        in verify_gate(packet, review, checks, config, head, state)["blocking_reasons"]
    )
