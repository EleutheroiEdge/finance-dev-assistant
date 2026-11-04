"""Synthetic regression coverage for the second PR59 review."""
from dataclasses import replace
import json

import httpx
import pytest

from conftest import command
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.patching import apply_patch_artifact, rollback_patch
from finassist.proposal import propose
from finassist.review import review_packet, validate_review
from finassist.scope import build_packet
from finassist.security import canonical, check_text, digest
from test_forbidden_token_gate import candidate
from test_model_gate import run
from test_providers_review import envelope, model_config, response

pytest_plugins = ("test_model_gate", "test_model_policy")


@pytest.mark.parametrize("annotation", [
    "Ed25519PrivateKey | None", '"Ed25519PrivateKey"', "list[Ed25519PrivateKey]",
    "((Ed25519PrivateKey | None))", "(\n    Ed25519PrivateKey | None\n)",
    "lowercase_type_name", "Zq7Lm2Xp9Rt4Vw8",
])
@pytest.mark.parametrize("parameter", [False, True])
def test_complete_python_annotations_pass_without_rewriting_requests(gate_case, annotation, parameter):
    label = "signing_" + "key"
    source = (f"def f({label}: {annotation} = None): pass\n" if parameter
              else f"{label}: {annotation} = None\n")
    candidate(gate_case, source)
    received = []
    def reply(packet):
        received.append(packet["files"][0]["after"])
        return envelope(json.dumps({"head": packet["head"], "summary": "Synthetic review",
            "reviewed_paths": [f["path"] for f in packet["files"]], "findings": []}))
    report, calls = run(gate_case, reply)
    assert received == [source]
    assert report["verdict"] == "PASS" and len(calls) == 1


@pytest.mark.parametrize("label,annotation,value", [
    ("password", "str", '\"Zq7Lm2Xp9Rt4Vw8\"'),
    ("api_" + "key", "str", '\"Zq7Lm2Xp9Rt4Vw8\"'),
    ("signing_" + "key", "str", '\"Zq7Lm2Xp9Rt4Vw8\"'),
    ("account_number", "int", "12345678"),
    ("routing_number", "int", "12345678"),
])
@pytest.mark.parametrize("parameter", [False, True])
def test_typed_sensitive_values_block_before_dispatch_and_reservation(gate_case, label, annotation, value, parameter):
    source = (f"def f({label}: ({annotation}) = {value}): pass\n" if parameter
              else f"{label}: ({annotation}) = {value}\n")
    candidate(gate_case, source)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
    assert not (gate_case["state"] / "audit.sqlite").exists()


def test_comments_inside_annotation_are_still_screened():
    source = "signing_key: tuple[\n # signing_" + 'key = "Zq7Lm2Xp9Rt4Vw8"\n int, str]\n'
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text(source, source_path="src/a.py")


def annotated_packet(repository):
    repo, base, _ = repository
    source = "# Synthetic types\nsigning_" + "key: Ed25519PrivateKey | None = None\n"
    (repo / "src/cash.py").write_text(source, encoding="utf-8", newline="")
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Synthetic annotation")
    return build_packet(repo, base, "HEAD", Config())


@pytest.mark.parametrize("quote", ["signing_" + "key: Ed25519PrivateKey", "signing_" + "key: Ed25519PrivateKey | None"])
def test_manual_review_accepts_source_bound_annotation_quotes(repository, tmp_path, monkeypatch, quote):
    packet = annotated_packet(repository)
    value = response(packet)
    value["summary"] = quote
    value["findings"][0]["claim"] = quote
    validate_review(value, packet)
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    result = review_packet(packet, model_config(), tmp_path / "audit.db", network_approved=True,
        approved_packet_hash=packet["packet_hash"],
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=envelope(json.dumps(value)))))
    assert result["review"] == value


@pytest.mark.parametrize("quote", [
    "signing_" + "key: Ed25519PrivateKeyChanged", "signing_" + "key = Ed25519PrivateKey",
    "signing_" + 'key = "Zq7Lm2Xp9Rt4Vw8"',
    "password = " + '"Ed25519PrivateKey"',
])
def test_new_output_credential_values_remain_blocked(repository, quote):
    packet = annotated_packet(repository)
    value = response(packet)
    value["summary"] = quote
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        validate_review(value, packet)


def make_patch(repository, after):
    repo, _, _ = repository
    packet = annotated_packet(repository)
    path = repo / "src/cash.py"
    before = path.read_bytes()
    path.write_bytes(after.encode())
    patch = command(repo, "diff", "--no-ext-diff", "--no-textconv") + "\n"
    path.write_bytes(before)
    return packet, {"head": packet["head"], "patch": patch, "summary": "Synthetic type correction"}, before


def test_annotation_patch_proposal_apply_and_active_policy_rollback(repository, tmp_path, monkeypatch):
    source = "# Synthetic types\nsigning_" + 'key: "Ed25519PrivateKey" = None\n'
    packet, artifact, before = make_patch(repository, source)
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    proposal = propose(packet, model_config(), tmp_path / "audit.db", network_approved=True,
        approved_packet_hash=packet["packet_hash"], transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=envelope(json.dumps(artifact)))))
    assert proposal["artifact"] == artifact
    repo = repository[0]
    original_index = command(repo, "write-tree")
    approved = digest(canonical(artifact))
    apply_patch_artifact(repo, artifact, approved, Config())
    assert (repo / "src/cash.py").read_bytes() == source.encode()
    assert command(repo, "write-tree") == original_index
    rollback_patch(repo, approved, Config())
    assert (repo / "src/cash.py").read_bytes() == before
    assert command(repo, "status", "--porcelain") == ""


@pytest.mark.parametrize("source", [
    "password: str = " + '\"Zq7Lm2Xp9Rt4Vw8\"\n',
    "signing_" + 'key: str = "Zq7Lm2Xp9Rt4Vw8"\n',
    "account_number: int = " + "12345678\n",
    '# signing_' + 'key: Ed25519PrivateKey\n',
])
def test_sensitive_patch_post_images_refuse_without_mutating_repository(repository, source):
    packet, artifact, before = make_patch(repository, source)
    repo = repository[0]
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        apply_patch_artifact(repo, artifact, digest(canonical(artifact)), Config())
    assert (repo / "src/cash.py").read_bytes() == before
    assert not (repo / ".finassist/patches").exists()
    assert command(repo, "status", "--porcelain") == ""


def test_output_and_patch_custom_patterns_are_not_exempted(repository):
    packet, artifact, before = make_patch(repository, "# Synthetic types\nsigning_" + 'key: "Ed25519PrivateKey" = None\n')
    value = response(packet)
    value["summary"] = "signing_" + "key: Ed25519PrivateKey"
    with pytest.raises(AssistantError, match="^project_content_blocked$"):
        validate_review(value, packet, extra_patterns=("Ed25519",))
    with pytest.raises(AssistantError, match="^project_content_blocked$"):
        apply_patch_artifact(repository[0], artifact, digest(canonical(artifact)),
                             replace(Config(), extra_sensitive_patterns=("Ed25519",)))
    assert (repository[0] / "src/cash.py").read_bytes() == before


@pytest.mark.parametrize("new_value", [False, True])
def test_gate_output_only_permits_a_quote_from_the_screened_source(gate_case, new_value):
    source = "# Synthetic types\nsigning_" + "key: Ed25519PrivateKey | None = None\n"
    candidate(gate_case, source)
    def reply(packet):
        value = response(packet)
        value["summary"] = "signing_" + ("key: New25519PrivateKey" if new_value else "key: Ed25519PrivateKey")
        return envelope(json.dumps(value))
    report, calls = run(gate_case, reply)
    assert len(calls) == 1
    assert report["verdict"] == ("BLOCKED" if new_value else "PASS")
    if new_value:
        assert report["reasons"] == ["sensitive_content"]
        assert "New25519" not in canonical(report).decode()


def test_value_elsewhere_in_source_does_not_exempt_a_new_output_assignment(repository):
    repo, base, _ = repository
    (repo / "src/cash.py").write_text('reference = "Ed25519PrivateKey"\n', encoding="utf-8", newline="")
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Synthetic type reference text")
    packet = build_packet(repo, base, "HEAD", Config())
    value = response(packet)
    value["summary"] = "signing_" + "key: Ed25519PrivateKey"
    value["findings"] = []
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        validate_review(value, packet)
