from dataclasses import replace
import json

import httpx
import pytest

from conftest import command
from finassist.cli import main
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.proposal import propose
from finassist.scope import build_packet
from test_patching_runner import artifact
from test_providers_review import envelope, model_config


def generate(packet, config, state, candidate, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    return propose(
        packet,
        config,
        state / "audit.sqlite",
        network_approved=True,
        approved_packet_hash=packet["packet_hash"],
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=envelope(json.dumps(candidate)))),
    )


def test_model_proposal_can_be_inspected_applied_and_rolled_back(repository, tmp_path, monkeypatch, capsys):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    generated = generate(packet, model_config(), tmp_path, artifact(repo, head), monkeypatch)
    path = tmp_path / "proposal.json"
    path.write_text(json.dumps(generated), encoding="utf-8", newline="\n")
    assert not generated["applied"]
    assert "- deposits" in (repo / "src/cash.py").read_text(encoding="utf-8")
    assert (
        main(
            [
                "apply",
                "--repo",
                str(repo),
                "--proposal",
                str(path),
                "--approve-hash",
                generated["approval_hash"],
            ]
        )
        == 0
    )
    assert "+ deposits" in (repo / "src/cash.py").read_text(encoding="utf-8")
    capsys.readouterr()
    assert main(["rollback", "--repo", str(repo), "--patch-hash", generated["approval_hash"]]) == 0
    assert command(repo, "status", "--porcelain") == ""


def test_partial_review_cannot_propose_changes_to_omitted_source(repository, tmp_path, monkeypatch):
    repo, base, _ = repository
    (repo / "src/other.py").write_text("value = 1\n", encoding="utf-8", newline="\n")
    command(repo, "add", "src/other.py")
    command(repo, "commit", "-m", "Add second synthetic file")
    head = command(repo, "rev-parse", "HEAD")
    packet = build_packet(repo, base, head, replace(Config(), allow_paths=("src/cash.py",)))
    candidate = {
        "head": head,
        "summary": "Change omitted file",
        "patch": "diff --git a/src/other.py b/src/other.py\n--- a/src/other.py\n+++ b/src/other.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n",
    }
    assert packet["omitted"] == [{"path": "src/other.py", "reason": "outside_allowlist"}]
    with pytest.raises(AssistantError, match="patch_path_not_approved"):
        generate(
            packet,
            replace(model_config(), allow_partial_review=True, allow_paths=("src/cash.py",)),
            tmp_path,
            candidate,
            monkeypatch,
        )
    assert (repo / "src/other.py").read_text(encoding="utf-8") == "value = 1\n"


def test_proposal_summary_is_screened_before_returning_output(repository, tmp_path, monkeypatch):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    candidate = artifact(repo, head)
    candidate["summary"] = "sk-" + "x" * 32
    with pytest.raises(AssistantError, match="sensitive_content"):
        generate(packet, model_config(), tmp_path, candidate, monkeypatch)
