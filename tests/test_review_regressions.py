"""Synthetic regressions for independent review of the security/readiness change."""

from dataclasses import replace
import os
import json
import sqlite3
import subprocess

import pytest

from conftest import command, synthetic_symlink
from finassist.cli import main
from finassist.config import Config, save_config
from finassist.errors import AssistantError
from finassist.ledger import Ledger
from finassist.github_audit import inspect_github
from finassist.patching import apply_patch_artifact, patch_paths
from finassist.readiness import verify_gate
from finassist.security import canonical, check_text, digest
from finassist.scope import build_packet
from finassist.review import review_packet
from finassist.evaluation import evaluate
from test_evaluation import suite
from test_patching_runner import artifact
from test_providers_review import model_config, envelope, response
from test_readiness import gate_bundle as _gate_bundle

gate_bundle = _gate_bundle


def hidden_section(repo, head):
    workflow = repo / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: original\n", encoding="utf-8", newline="\n")
    command(repo, "add", ".github/workflows/ci.yml")
    command(repo, "commit", "-m", "Synthetic protected file")
    proposal = artifact(repo, command(repo, "rev-parse", "HEAD"))
    proposal["patch"] += (
        "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n"
        "@@ -1 +1 @@\n-name: original\n+name: altered\n"
    )
    return proposal, workflow


def test_traditional_section_cannot_escape_approved_paths(repository):
    repo, _, head = repository
    proposal, workflow = hidden_section(repo, head)
    parsed = subprocess.check_output(
        ["git", "-C", str(repo), "apply", "--numstat", "-z", "-"], input=proposal["patch"].encode()
    )
    assert b".github/workflows/ci.yml\0" in parsed
    with pytest.raises(AssistantError):
        patch_paths(proposal["patch"], Config())
    assert workflow.read_text(encoding="utf-8") == "name: original\n"


def test_git_parser_backstop_refuses_scope_mismatch_before_backup_or_mutation(repository, monkeypatch):
    repo, _, head = repository
    proposal, workflow = hidden_section(repo, head)
    monkeypatch.setattr("finassist.patching.patch_paths", lambda *_: ["src/cash.py"])
    with pytest.raises(AssistantError, match="patch_scope_mismatch"):
        apply_patch_artifact(repo, proposal, digest(canonical(proposal)), Config())
    assert workflow.read_text(encoding="utf-8") == "name: original\n"
    assert not (repo / ".finassist/patches").exists()


@pytest.mark.parametrize(
    "key,quote,separator,value",
    [
        ("OPENAI_" + "API_KEY", "", "=", "x" * 24),
        ("db_" + "password", "", " = ", "x" * 24),
        ("client_" + "secret", '"', ": ", "x" * 24),
        ("account_" + "number", '"', ": ", "123456789"),
    ],
)
def test_prefixed_or_quoted_sensitive_assignments(key, quote, separator, value):
    payload = f'{quote}{key}{quote}{separator}"{value}"'
    if quote:
        payload = "{" + payload + "}"
    with pytest.raises(AssistantError, match="sensitive_content"):
        check_text(payload)


def test_stale_review_is_a_blocked_report_instead_of_an_exception(gate_bundle):
    packet, review, checks, config, head, state = gate_bundle
    review["head"] = review["review"]["head"] = "b" * 40
    report = verify_gate(packet, review, checks, config, head, state)
    assert report["status"] == "blocked"
    assert "revision_mismatch" in report["blocking_reasons"]
    assert "review_head_mismatch" in report["blocking_reasons"]


def test_review_base_must_match_its_packet(gate_bundle):
    packet, review, checks, config, head, state = gate_bundle
    review["base"] = "b" * 40
    assert (
        "base_revision_mismatch"
        in verify_gate(packet, review, checks, config, head, state)["blocking_reasons"]
    )


def test_readiness_holds_one_snapshot_while_inspecting_all_ledger_state(gate_bundle, monkeypatch):
    packet, review, checks, config, head, state = gate_bundle
    original = Ledger.open_reservations
    attempts = []
    with Ledger(state) as writer:
        writer.db.execute("PRAGMA busy_timeout=0")

        def inspect(ledger):
            assert ledger.db.in_transaction
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                writer.append({"event": "synthetic_concurrent_event"})
            attempts.append(True)
            return original(ledger)

        monkeypatch.setattr(Ledger, "open_reservations", inspect)
        assert (
            verify_gate(packet, review, checks, config, head, state)["status"] == "eligible-for-human-review"
        )
        # No lock leaks after the gate has taken its consistent snapshot.
        writer.append({"event": "synthetic_after_snapshot"})
    assert attempts == [True]


@pytest.mark.parametrize("approvals", [0, 2])
def test_github_reports_absence_of_formal_approvals_even_when_prs_are_required(monkeypatch, approvals):
    policy = {
        "required_status_checks": {"strict": True, "contexts": ["unit"]},
        "required_pull_request_reviews": {"required_approving_review_count": approvals},
        **{
            name: {"enabled": value}
            for name, value in (
                ("enforce_admins", True),
                ("allow_force_pushes", False),
                ("allow_deletions", False),
            )
        },
    }

    def get(argv, **_):
        if argv[2].endswith("/protection"):
            value = policy
        elif "/rules/" in argv[2]:
            value = []
        elif "/branches/" in argv[2]:
            value = {"name": "main", "protected": True, "commit": {"sha": "a" * 40}}
        else:
            value = {"full_name": "example/repository"}
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    monkeypatch.setattr("finassist.platform_support.shutil.which", lambda _: "/trusted/gh")
    monkeypatch.setattr("finassist.github_audit.subprocess.run", get)
    report = inspect_github(
        "example/repository", "main", replace(Config(), allow_network=True), network_approved=True
    )
    assert report["controls"]["pull_request_required"]
    assert report["observations"] == ([] if approvals else ["formal_approvals_not_required"])
    assert report["issues"] == []  # No invented approval requirement or server mutation.


@pytest.mark.parametrize("stale", [False, True])
def test_gate_cli_blocks_dirty_source_or_stale_review(gate_bundle, repository, tmp_path, capsys, stale):
    packet, review, checks, config, head, state = gate_bundle
    repo = repository[0]
    state.rename(tmp_path / "audit.sqlite")
    if stale:
        review["head"] = review["review"]["head"] = "b" * 40
        reason = "revision_mismatch"
    else:
        (repo / "src/cash.py").write_text("unreviewed local edit\n", encoding="utf-8", newline="\n")
        reason = "clean_worktree_required"
    config_path = tmp_path / "config.json"
    save_config(config_path, config)
    packet_path, review_path, check_path = [
        tmp_path / name for name in ("packet.json", "review.json", "check.json")
    ]
    for path, value in ((packet_path, packet), (review_path, review), (check_path, checks[0])):
        path.write_text(json.dumps(value), encoding="utf-8", newline="\n")
    assert (
        main(
            [
                "--config",
                str(config_path),
                "--audit-dir",
                str(tmp_path),
                "verify-gate",
                "--repo",
                str(repo),
                "--expected-head",
                head,
                "--packet",
                str(packet_path),
                "--review",
                str(review_path),
                "--receipt",
                str(check_path),
            ]
        )
        == 1
    )
    output = capsys.readouterr()
    assert output.err == ""
    report = json.loads(output.out)
    assert report["status"] == "blocked" and reason in report["blocking_reasons"]


@pytest.mark.parametrize(
    "suffix", ["\ninvalid hunk data\n", "\n+unexpected data\n", "\n--- a/src/other.py\n"]
)
def test_extra_content_after_hunk_counts_is_not_ignored(suffix):
    patch = "diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-a\n+b" + suffix
    with pytest.raises(AssistantError):
        patch_paths(patch, Config())


@pytest.mark.parametrize("body", ["-old\n", "invalid\n+new\n", "-old\n-context\n+new\n"])
def test_hunk_line_counts_and_prefixes_are_enforced(body):
    patch = "diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n" + body
    with pytest.raises(AssistantError, match="patch_hunk_invalid"):
        patch_paths(patch, Config())


@pytest.mark.parametrize("change", ["new", "delete", "mode", "multiple", "no-newline"])
def test_valid_git_patch_forms_still_apply_and_restore(repository, change):
    from finassist.patching import rollback_patch

    if change == "mode" and os.name == "nt":
        pytest.skip("Windows cannot apply a POSIX mode-only worktree patch; rejection is tested separately")

    repo, _, _ = repository
    file = repo / "src/example.py"
    if change != "new":
        file.write_text(
            "\n".join(str(n) for n in range(30)) + ("" if change == "no-newline" else "\n"),
            encoding="utf-8",
            newline="\n",
        )
        command(repo, "add", "src/example.py")
        command(repo, "commit", "-m", "Synthetic source")
    head = command(repo, "rev-parse", "HEAD")
    before = file.read_bytes() if file.exists() else None
    if change == "new":
        file.write_text("new source\n", encoding="utf-8", newline="\n")
        command(repo, "add", "-N", "src/example.py")
    elif change == "delete":
        file.unlink()
    elif change == "mode":
        file.chmod(0o755)
    else:
        file.write_text(
            file.read_text(encoding="utf-8").replace("0\n", "changed\n").replace("28\n", "changed again\n"),
            encoding="utf-8",
            newline="\n",
        )
    patch = command(repo, "diff", "--no-ext-diff", "--no-textconv") + "\n"
    if change == "new":
        command(repo, "reset", "--", "src/example.py")
        file.unlink()
    else:
        file.write_bytes(before)
        file.chmod(0o644)
    proposal = {"head": head, "patch": patch, "summary": "Synthetic patch form"}
    approved = digest(canonical(proposal))
    receipt = apply_patch_artifact(repo, proposal, approved, Config())
    assert receipt["paths"] == ["src/example.py"]
    rollback_patch(repo, approved)
    assert (file.read_bytes() if file.exists() else None) == before
    assert command(repo, "status", "--porcelain") == ""


def test_offline_review_and_eval_screen_custom_patterns_before_work(repository, tmp_path, monkeypatch):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    config = replace(Config(), extra_sensitive_patterns=("deposits",))
    with pytest.raises(AssistantError, match="project_content_blocked"):
        review_packet(packet, config, tmp_path / "audit.db")
    config = replace(Config(), extra_sensitive_patterns=("cash",))
    monkeypatch.setattr(
        "finassist.evaluation._fixture_git", lambda *_: pytest.fail("fixture work must not start")
    )
    with pytest.raises(AssistantError, match="project_content_blocked"):
        evaluate(suite(), config, tmp_path)
    assert not (tmp_path / "audit.db").exists()


def test_scan_records_tracked_link_and_continues(repository, capsys):
    repo, _, _ = repository
    synthetic_symlink(repo / "src/link.py", "cash.py")
    (repo / "src/synthetic.py").write_text("api" + '_key="' + "x" * 24 + '"', encoding="utf-8", newline="\n")
    command(repo, "add", "src/link.py", "src/synthetic.py")
    assert main(["scan", "--repo", str(repo)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert {row["code"] for row in report["findings"]} == {"linked_or_special_git_object", "sensitive_content"}


@pytest.mark.parametrize("kind", ["output", "input"])
def test_out_of_bounds_paid_usage_remains_reserved(repository, tmp_path, monkeypatch, kind):
    import httpx

    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    value = envelope(json.dumps(response(packet)))
    config = model_config()
    value["usage"]["output_tokens" if kind == "output" else "input_tokens"] = (
        config.max_output_tokens + 1 if kind == "output" else 1_999_999
    )
    state = tmp_path / "audit.db"
    with pytest.raises(AssistantError, match="provider_usage_exceeds_limit"):
        review_packet(
            packet,
            config,
            state,
            network_approved=True,
            approved_packet_hash=packet["packet_hash"],
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=value)),
        )
    with Ledger(state) as ledger:
        ledger.verify()
        assert len(ledger.open_reservations()) == 1
        assert not any(row["payload"]["event"] == "settled" for row in ledger.events())
