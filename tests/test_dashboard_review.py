"""Regression coverage for generated scope and dashboard review findings."""

from dataclasses import replace
import json
from pathlib import Path
import sys

import pytest

from conftest import command
import test_dashboard
import test_readiness

from finassist.cli import main
from finassist.config import Config, save_config
from finassist.errors import AssistantError
from finassist.ledger import Ledger
from finassist.readiness import verify_gate
from finassist.scope import build_packet, triage, verify_packet
from finassist.security import canonical, check_path, digest
from finassist.statistics import statistics


dashboard = test_dashboard.dashboard
gate_bundle = test_readiness.gate_bundle


@pytest.mark.parametrize("operation", ["plan", "check"])
def test_plan_and_check_the_assistants_own_committed_tree(tmp_path, operation):
    root = Path(__file__).resolve().parents[1]
    base = command(root, "rev-list", "--max-parents=0", "HEAD").splitlines()[0]
    script = "from pathlib import Path; assert Path('src/finassist/config.py').is_file(); assert not Path('src/finassist/resources/dashboard/assets').exists(); print('Synthetic scope check: PASS')"
    # Retain the 48 KB file ceiling. A whole-repository change needs a larger
    # packet ceiling, independently of the generated bundle exclusion.
    config = replace(Config(), max_packet_bytes=2_000_000, recipes={"scope": [sys.executable, "-c", script]})
    path, output = tmp_path / "configuration.json", tmp_path / "result.json"
    save_config(path, config)
    args = [
        "--config",
        str(path),
        "--audit-dir",
        str(tmp_path / "audit"),
        operation,
        "--repo",
        str(root),
        "--output",
        str(output),
    ]
    args += (
        ["--base", base]
        if operation == "plan"
        else ["--recipe", "scope", "--backend", "local", "--approve-local"]
    )
    assert main(args) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    if operation == "plan":
        assert any(row["reason"] == "generated_artifact_excluded" for row in result["omitted"])
        assert not any(
            row["path"].startswith("src/finassist/resources/dashboard/") for row in result["files"]
        )
    else:
        assert result["receipt"]["passed"] and result["receipt"]["cleanup_verified"]


def test_generated_paths_are_configurable_bound_and_not_missing_coverage(repository):
    repo, base, _ = repository
    path = repo / "src/generated/large.js"
    path.parent.mkdir()
    path.write_bytes(b"synthetic;\n" * 6000)
    command(repo, "add", "src/generated/large.js")
    command(repo, "commit", "-m", "Synthetic generated artifact")
    config = replace(Config(), generated_paths=("src/generated/",))
    packet = build_packet(repo, base, "HEAD", config)
    assert packet["generated_paths"] == ["src/generated/"]
    assert triage(packet, config)["coverage_complete"]
    assert packet["omitted"] == [{"path": "src/generated/large.js", "reason": "generated_artifact_excluded"}]
    with pytest.raises(AssistantError, match="packet_generated_paths_mismatch"):
        verify_packet(packet, replace(config, generated_paths=()))
    with pytest.raises(AssistantError, match="file_limit_exceeded"):
        build_packet(repo, base, "HEAD", replace(config, generated_paths=()))


@pytest.mark.parametrize(
    "paths",
    [("../outside/",), ("/outside/",), ("",), ("src//build/",), ("secrets/",), ("src/build/", "src/build/")],
)
def test_invalid_generated_paths_are_rejected(paths):
    with pytest.raises(AssistantError):
        replace(Config(), generated_paths=paths).validate()


def test_generated_omission_cannot_be_forged_for_reviewable_source(repository):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    packet["files"] = []
    packet["omitted"] = [{"path": "src/cash.py", "reason": "generated_artifact_excluded"}]
    packet["packet_hash"] = digest(
        canonical({key: value for key, value in packet.items() if key != "packet_hash"})
    )
    with pytest.raises(AssistantError, match="generated_omission_invalid"):
        verify_packet(packet)


def test_post_save_audit_failure_remains_unknown_and_blocks_readiness(dashboard, gate_bundle, monkeypatch):
    state, _, request = dashboard
    packet, report, checks, config, head, ledger_path = gate_bundle
    assert verify_gate(*gate_bundle)["status"] == "eligible-for-human-review"
    state.ledger_path = ledger_path
    current = request("GET", "/api/config")[1]
    proposal = request(
        "POST", "/api/config/preview", {"revision": current["revision"], "changes": {"daily_budget_usd": 7}}
    )[1]
    original = Ledger.append

    def append(ledger, payload):
        if payload["event"] == "configuration_saved":
            raise OSError("synthetic post-save audit failure")
        return original(ledger, payload)

    monkeypatch.setattr(Ledger, "append", append)
    result = request("POST", "/api/config/confirm", {"proposal_id": proposal["proposal_id"], "confirm": True})
    assert result[1]["code"] == "configuration_saved_audit_unknown_reload"
    with Ledger(ledger_path) as ledger:
        assert len(ledger.incomplete_runs()) == 1
        assert not any(row["payload"]["event"] == "command_failed" for row in ledger.events())
    assert statistics(ledger_path, config)["recent_runs"][0]["status"] == "unknown"
    assert (
        "unfinished_operation"
        in verify_gate(packet, report, checks, config, head, ledger_path)["blocking_reasons"]
    )


def test_gitattributes_is_reviewable_and_protected_by_default(repository):
    repo, base, _ = repository
    (repo / ".gitattributes").write_text("* text=auto eol=lf\n", encoding="utf-8", newline="\n")
    command(repo, "add", ".gitattributes")
    command(repo, "commit", "-m", "Synthetic attribute policy")
    packet = build_packet(repo, base, "HEAD", Config())
    assert ".gitattributes" in {row["path"] for row in packet["files"]}
    assert Config().protected(".gitattributes")
    assert check_path(".gitattributes") == ".gitattributes"


def test_invalid_configuration_has_a_typed_error_on_every_data_api(dashboard):
    state, _, request = dashboard
    state.config_path.write_bytes(b"invalid JSON")
    for endpoint in ("/api/config", "/api/statistics"):
        status, value, _ = request("GET", endpoint)
        assert status == 409 and value == {"kind": "configuration", "code": "configuration_invalid"}
    assert request("GET", "/api/health")[1]["configuration"]["valid"] is False


def test_non_ascii_token_is_forbidden(dashboard):
    _, _, request = dashboard
    assert request("GET", "/api/config", headers={"X-Finassist-Token": "é"})[0] == 403


def test_evidence_age_out_of_range_has_its_own_error(dashboard):
    _, _, request = dashboard
    config = request("GET", "/api/config")[1]
    result = request(
        "POST",
        "/api/config/preview",
        {"revision": config["revision"], "changes": {"readiness_max_age_seconds": 2_000_001}},
    )
    assert result[1]["code"] == "invalid_evidence_age"


def test_confirmation_captures_one_pre_save_snapshot_for_backup(dashboard, monkeypatch):
    import finassist.dashboard as module

    state, _, request = dashboard
    config = request("GET", "/api/config")[1]
    preview = request(
        "POST", "/api/config/preview", {"revision": config["revision"], "changes": {"daily_budget_usd": 7}}
    )[1]
    before = state.config_path.read_bytes()
    reads, written = [], []
    read_bytes, write_private = Path.read_bytes, module.write_private

    def capture(path):
        if path == state.config_path and not written:
            reads.append(path)
        return read_bytes(path)

    def write(path, data, **kwargs):
        if path == state.config_path:
            written.append(True)
        return write_private(path, data, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", capture)
    monkeypatch.setattr(module, "write_private", write)
    state.confirm({"proposal_id": preview["proposal_id"], "confirm": True})
    assert len(reads) == 1
    backup = state.ledger_path.parent / "config-backups" / (digest(before) + ".json")
    assert backup.read_bytes() == before


def test_nonzero_command_exit_is_distinct_from_success_in_recent_runs(tmp_path):
    from finassist.auditing import command_audit

    path = tmp_path / "audit.sqlite"
    with command_audit(path, "verify-gate", Config()) as outcome:
        outcome["exit_code"] = 1
    run = statistics(path, Config())["recent_runs"][0]
    assert run["status"] == "blocked-or-failed" and run["exit_code"] == 1


def test_generated_exclusions_keep_model_review_and_readiness_complete(repository, tmp_path, monkeypatch):
    from dataclasses import asdict
    import httpx
    from finassist.review import review_packet
    from test_providers_review import model_config, envelope, response

    repo, base, _ = repository
    generated = repo / "src/finassist/resources/dashboard/bundle.js"
    generated.parent.mkdir(parents=True)
    generated.write_bytes(b"synthetic;\n" * 6000)
    command(repo, "add", generated.relative_to(repo).as_posix())
    command(repo, "commit", "-m", "Synthetic compiled output")
    head = command(repo, "rev-parse", "HEAD")
    config = replace(
        model_config(),
        recipes={"unit": ["python", "test.py"]},
        required_recipes=("unit",),
        runner_image="sha256:" + "a" * 64,
    )
    packet = build_packet(repo, base, head, config)
    value = response(packet)
    value["findings"] = []
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    state = tmp_path / "audit.sqlite"
    report = review_packet(
        packet,
        config,
        state,
        network_approved=True,
        approved_packet_hash=packet["packet_hash"],
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=envelope(json.dumps(value)))),
    )
    assert report["status"] == "no-findings-reported"
    snapshot = {
        "head": head,
        "files": [
            {"path": row["path"], "sha256": row["after_hash"], "mode": row["after_mode"]}
            for row in packet["files"]
        ],
    }
    # Synthetic audit evidence; the real isolation recipe remains a separate CI job.
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
    assert (
        verify_gate(packet, report, [{"receipt": receipt, "snapshot": snapshot}], config, head, state)[
            "status"
        ]
        == "eligible-for-human-review"
    )


def test_unchanged_json_lists_do_not_create_false_preview_differences(dashboard):
    _, _, request = dashboard
    current = request("GET", "/api/config")[1]
    preview = request(
        "POST", "/api/config/preview", {"revision": current["revision"], "changes": current["values"]}
    )
    assert preview[0] == 200 and preview[1]["diff"] == []
