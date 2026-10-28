from dataclasses import asdict, replace
from datetime import datetime
from decimal import Decimal
import json

import httpx
import pytest

from conftest import command
from finassist.auditing import command_audit
from finassist.cli import main
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.evidence_store import EvidenceStore
from finassist.finance import observation_check
from finassist.ledger import Ledger
from finassist.patching import apply_patch_artifact, patch_paths, rollback_patch
from finassist.providers import parse_response
from finassist.review import review_packet
from finassist.scope import build_packet, git_environment, verify_packet
from finassist.security import canonical, check_text, digest
from test_evidence_store import observation
from test_providers_review import envelope, model_config, response


@pytest.mark.parametrize("style", ["json", "dict", "yaml", "assignment"])
def test_sensitive_assignments_are_screened_in_common_formats(style):
    name, value = "api" + "_key", "x" * 24
    text = {
        "json": json.dumps({name: value}),
        "dict": repr({name: value}),
        "yaml": name + ": " + value,
        "assignment": name + "=" + value,
    }[style]
    with pytest.raises(AssistantError, match="sensitive_content"):
        check_text(text)


@pytest.mark.parametrize("prefix", ["-lfoo@", "-w/tmp@", "--network=host@"])
def test_runner_image_cannot_be_a_cli_option(prefix):
    with pytest.raises(AssistantError, match="pinned_runner_image_required"):
        replace(Config(), runner_image=prefix + "sha256:" + "a" * 64).validate()


def test_untrusted_git_environment_cannot_redirect_source(repository, monkeypatch):
    repo, base, head = repository
    monkeypatch.setenv("GIT_DIR", "/nonexistent-synthetic-directory")
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    assert "OPENAI_API_KEY" not in git_environment() and "GIT_DIR" not in git_environment()
    assert build_packet(repo, base, head, Config())["head"] == head


def test_mixed_commit_retains_excluded_assets_and_lockfile_metadata(repository):
    repo, base, _ = repository
    (repo / "requirements.lock").write_text("example==1\n")
    (repo / "diagram.png").write_bytes(b"fictional-binary\x00")
    command(repo, "add", "requirements.lock", "diagram.png")
    command(repo, "commit", "-m", "Synthetic mixed source and assets")
    packet = build_packet(repo, base, "HEAD", replace(Config(), allow_paths=("src/",)))
    verify_packet(packet, replace(Config(), allow_paths=("src/",)))
    assert {item["path"] for item in packet["omitted"]} == {"requirements.lock", "diagram.png"}
    assert "fictional-binary" not in json.dumps(packet)


def test_sql_comment_hunks_apply_and_rollback_without_header_confusion(repository):
    repo, _, _ = repository
    path = repo / "src/query.sql"
    path.write_text("-- cash\nselect 1;\n")
    command(repo, "add", "src/query.sql")
    command(repo, "commit", "-m", "Synthetic SQL source")
    head = command(repo, "rev-parse", "HEAD")
    original = path.read_text()
    path.write_text("-- balance\nselect 1;\n")
    patch = command(repo, "diff") + "\n"
    path.write_text(original)
    artifact = {"head": head, "patch": patch, "summary": "Change synthetic comment"}
    approved = digest(canonical(artifact))
    apply_patch_artifact(repo, artifact, approved, Config())
    assert path.read_text().startswith("-- balance")
    rollback_patch(repo, approved)
    assert command(repo, "status", "--porcelain") == ""


def test_patch_headers_must_match_current_diff_file():
    patch = (
        "diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1 +1 @@\n-a\n+b\n"
        "diff --git a/src/b.py b/src/b.py\n--- a/src/a.py\n+++ b/src/b.py\n@@ -1 +1 @@\n-a\n+b\n"
    )
    with pytest.raises(AssistantError, match="patch_header_mismatch"):
        patch_paths(patch, Config())
    assert Config().protected("pyproject.toml") and Config().protected("scripts/check.py")


@pytest.mark.parametrize(
    "usage",
    [
        None,
        {"prompt_tokens": 0, "completion_tokens": 0},
        {"prompt_tokens": 10**20, "completion_tokens": 10**20},
    ],
)
def test_missing_or_implausible_provider_usage_remains_unknown(usage):
    result = parse_response(
        "compatible", {"choices": [{"finish_reason": "stop", "message": {"content": "{}"}}], "usage": usage}
    )
    assert result.text == "{}" and result.input_tokens is None and result.output_tokens is None


def test_zero_usage_never_clears_a_paid_reservation(repository, tmp_path, monkeypatch):
    repo, base, head = repository
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    packet = build_packet(repo, base, head, Config())
    value = envelope(json.dumps(response(packet)))
    value["usage"] = {"input_tokens": 0, "output_tokens": 0}
    report = review_packet(
        packet,
        model_config(),
        tmp_path / "audit.db",
        network_approved=True,
        approved_packet_hash=packet["packet_hash"],
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=value)),
    )
    assert report["status"] == "findings"
    with Ledger(tmp_path / "audit.db") as ledger:
        assert len(ledger.open_reservations()) == 1


def test_approved_evidence_is_directly_usable_by_the_oracle(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        entry = store.add(observation())
        store.decide(entry["id"], entry["hash"], status="approved")
        value = store.latest_approved("Fictional Example", "revenue")["observation"]
    assert observation_check(value, decision_time="2026-02-03T00:00:00Z")["passed"]


def test_command_audit_records_denial_and_exports_only_metadata(tmp_path, capsys):
    state, output, exported = tmp_path / "state", tmp_path / "private-label.json", tmp_path / "events.jsonl"
    arguments = ["--audit-dir", str(state), "init", "--output", str(output)]
    assert main(arguments) == 0
    capsys.readouterr()
    assert main(arguments) == 2
    assert "output_exists" in capsys.readouterr().err
    assert main(["audit", "--state-dir", str(state), "--export", str(exported)]) == 0
    rows = [json.loads(line) for line in exported.read_text().splitlines()]
    assert [r["payload"]["event"] for r in rows] == [
        "command_started",
        "command_completed",
        "command_started",
        "command_failed",
    ]
    assert len({r["payload"]["run_id"] for r in rows}) == 2
    assert "private-label" not in exported.read_text()
    assert all(datetime.fromisoformat(r["payload"]["recorded_at"]).tzinfo is not None for r in rows)


def test_corrupt_audit_prevents_the_action(tmp_path, capsys):
    state, output = tmp_path / "state", tmp_path / "config.json"
    with Ledger(state / "audit.sqlite") as ledger:
        ledger.append({"event": "synthetic"})
        ledger.db.execute("UPDATE events SET payload='{}'")
    assert main(["--audit-dir", str(state), "init", "--output", str(output)]) == 2
    assert not output.exists()
    assert "audit_integrity_failed" in capsys.readouterr().err


def test_spend_events_correlate_and_reservation_tampering_is_detected(tmp_path):
    path = tmp_path / "audit.db"
    with command_audit(path, "review", Config()):
        with Ledger(path) as ledger:
            identifier = ledger.reserve(Decimal("0.1"), Decimal("1"), Decimal("1"))
            ledger.settle(identifier, Decimal("0.05"))
    with Ledger(path) as ledger:
        rows = ledger.events()
        assert len({r["payload"]["run_id"] for r in rows}) == 1
        assert len(rows) == 4
        ledger.db.execute("UPDATE reservations SET actual='0'")
        with pytest.raises(AssistantError, match="audit_integrity_failed"):
            ledger.verify()


def test_invalid_reconciliation_has_a_fixed_error_and_audit_record(tmp_path, capsys):
    assert (
        main(
            [
                "reconcile-budget",
                "--state-dir",
                str(tmp_path / "state"),
                "--reservation",
                "missing",
                "--actual-usd",
                "invalid",
            ]
        )
        == 2
    )
    assert "Traceback" not in capsys.readouterr().err
    with Ledger(tmp_path / "state/audit.sqlite") as ledger:
        assert ledger.events()[-1]["payload"]["event"] == "command_failed"


def test_configured_sensitive_patterns_apply_to_publication_scan(repository, tmp_path, capsys):
    repo, _, _ = repository
    (repo / "src/cash.py").write_text("internal_marker = 1\n")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(asdict(replace(Config(), extra_sensitive_patterns=("internal_marker",)))))
    assert main(["--config", str(cfg), "scan", "--repo", str(repo)]) == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["code"] == "project_content_blocked"


def test_mode_only_changes_and_literal_git_paths_remain_visible(repository, tmp_path):
    from finassist.workspace import export_snapshot

    repo, _, baseline = repository
    (repo / "src/cash.py").chmod(0o755)
    (repo / "src/data[1].py").write_text("literal = True\n")
    (repo / "src/data1.py").write_text("other = True\n")
    command(repo, "add", "src/cash.py", "src/data[1].py", "src/data1.py")
    command(repo, "commit", "-m", "Synthetic modes and literal paths")
    packet = build_packet(repo, baseline, "HEAD", Config())
    files = {file["path"]: file for file in packet["files"]}
    assert packet["schema_version"] == 2
    assert files["src/cash.py"]["before_hash"] == files["src/cash.py"]["after_hash"]
    assert (files["src/cash.py"]["before_mode"], files["src/cash.py"]["after_mode"]) == ("100644", "100755")
    assert files["src/data[1].py"]["after"] == "literal = True\n"
    snapshot = export_snapshot(repo, "HEAD", tmp_path / "snapshot", Config())
    assert (tmp_path / "snapshot/src/cash.py").stat().st_mode & 0o111
    assert next(file for file in snapshot["files"] if file["path"] == "src/cash.py")["mode"] == "100755"


def test_local_check_receipt_binds_source_and_image_policy(repository, tmp_path):
    repo, _, head = repository
    cfg, output = tmp_path / "config.json", tmp_path / "check.json"
    config = replace(Config(), recipes={"unit": ["python", "-c", "print('fictional')"]})
    cfg.write_text(json.dumps(asdict(config)))
    assert (
        main(
            [
                "--config",
                str(cfg),
                "check",
                "--repo",
                str(repo),
                "--recipe",
                "unit",
                "--backend",
                "local",
                "--approve-local",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    document = json.loads(output.read_text())
    assert document["receipt"]["head"] == head
    assert document["receipt"]["snapshot_hash"] == digest(canonical(document["snapshot"]))
    assert document["receipt"]["runner_image"] is None
    with Ledger(repo / ".finassist/audit.sqlite") as ledger:
        assert any(row["payload"]["event"] == "check_completed" for row in ledger.events())


def test_default_auditing_does_not_make_a_clean_unignored_repo_dirty_for_apply(repository, tmp_path):
    from test_patching_runner import artifact

    repo, _, _ = repository
    (repo / ".gitignore").unlink()
    command(repo, "add", ".gitignore")
    command(repo, "commit", "-m", "Synthetic project without tool exclusions")
    head = command(repo, "rev-parse", "HEAD")
    proposal = artifact(repo, head)
    approved = digest(canonical(proposal))
    path = tmp_path / "proposal.json"
    path.write_text(json.dumps(proposal))
    assert main(["apply", "--repo", str(repo), "--proposal", str(path), "--approve-hash", approved]) == 0
    assert main(["rollback", "--repo", str(repo), "--patch-hash", approved]) == 0
    assert command(repo, "status", "--porcelain", "--", ".", ":(exclude).finassist") == ""


def test_json_array_artifacts_return_a_fixed_cli_error(tmp_path, capsys):
    path = tmp_path / "artifact.json"
    path.write_text("[]")
    assert main(["render", "--input", str(path), "--output", str(tmp_path / "report.html")]) == 2
    assert "input_object_required" in capsys.readouterr().err


def test_completion_logging_failure_preserves_unknown_operation_state(tmp_path, monkeypatch):
    path, marker = tmp_path / "audit.db", tmp_path / "performed.txt"
    append = Ledger.append

    def fail_completion(self, payload):
        if payload["event"] == "command_completed":
            raise OSError("synthetic log failure")
        return append(self, payload)

    monkeypatch.setattr(Ledger, "append", fail_completion)
    with pytest.raises(AssistantError, match="operation_finished_audit_completion_failed"):
        with command_audit(path, "apply", Config()):
            marker.write_text("performed")
    assert marker.exists()
    with Ledger(path) as ledger:
        assert len(ledger.incomplete_runs()) == 1


@pytest.mark.parametrize("field", ["run_id", "recorded_at", "event_schema"])
def test_audit_envelope_fields_cannot_be_supplied_as_event_data(tmp_path, field):
    with Ledger(tmp_path / "audit.db") as ledger:
        with pytest.raises(AssistantError, match="audit_reserved_field"):
            ledger.append({"event": "synthetic", field: "forged"})
        assert ledger.verify() == 0


def test_mismatched_lifecycle_completion_is_rejected_without_corrupting_log(tmp_path):
    path = tmp_path / "audit.db"
    with command_audit(path, "review", Config()):
        with Ledger(path) as ledger:
            with pytest.raises(AssistantError, match="audit_lifecycle_invalid"):
                ledger.append({"event": "command_completed", "command": "apply"})
    with Ledger(path) as ledger:
        assert ledger.verify() == 2 and ledger.incomplete_runs() == []
        previous = ledger.events()[-1]
        invalid = {**previous["payload"], "command": "apply"}
        payload = canonical(invalid).decode()
        ledger.db.execute(
            "INSERT INTO events(previous,payload,hash) VALUES(?,?,?)",
            (previous["hash"], payload, digest(previous["hash"].encode() + payload.encode())),
        )
        with pytest.raises(AssistantError, match="audit_integrity_failed"):
            ledger.verify()


def test_phantom_diff_sections_are_refused_but_mode_only_changes_are_supported():
    with pytest.raises(AssistantError, match="patch_header_mismatch"):
        patch_paths(
            "diff --git a/src/a.py b/src/a.py\ndiff --git a/src/b.py b/src/b.py\n--- a/src/b.py\n+++ b/src/b.py\n@@ -1 +1 @@\n-a\n+b\n",
            Config(),
        )
    assert patch_paths("diff --git a/src/a.py b/src/a.py\nold mode 100644\nnew mode 100755\n", Config()) == [
        "src/a.py"
    ]


def test_orphaned_patch_backup_stops_subsequent_application(repository):
    from test_patching_runner import artifact

    repo, _, head = repository
    proposal = artifact(repo, head)
    directory = repo / ".finassist/patches"
    directory.mkdir(parents=True)
    (directory / "interrupted.json").write_text("{}")
    with pytest.raises(AssistantError, match="incomplete_patch_reconciliation_required"):
        apply_patch_artifact(repo, proposal, digest(canonical(proposal)), Config())
    assert "- deposits" in (repo / "src/cash.py").read_text()


def test_finding_line_must_exist_on_the_primary_evidence_side(repository):
    from finassist.review import validate_review

    repo, _, _ = repository
    file = repo / "src/cash.py"
    file.write_text("line\n" * 20)
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Synthetic long source")
    base = command(repo, "rev-parse", "HEAD")
    file.write_text("short\nsource\n")
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Synthetic reduced source")
    packet = build_packet(repo, base, "HEAD", Config())
    result = response(packet)
    result["findings"][0]["line"] = 15
    with pytest.raises(AssistantError, match="finding_line_invalid"):
        validate_review(result, packet)
