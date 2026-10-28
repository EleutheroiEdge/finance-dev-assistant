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
        recipes={"unit": ["python", "-m", "pytest"]},
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
