from dataclasses import replace
import json

import httpx
import pytest

from finassist.config import Config
from finassist.errors import AssistantError
from finassist.ledger import Ledger
from finassist.providers import invoke, parse_response, request_shape
from finassist.review import review_packet, review_schema, validate_review
from finassist.scope import build_packet


def model_config(**kwargs):
    return replace(
        Config(),
        provider="openai",
        model="operator-selected",
        allow_network=True,
        input_usd_per_million=1,
        output_usd_per_million=2,
        **kwargs,
    )


def response(packet):
    file = packet["files"][0]
    return {
        "head": packet["head"],
        "summary": "Deposit sign changed.",
        "reviewed_paths": [file["path"]],
        "findings": [
            {
                "severity": "high",
                "path": file["path"],
                "line": 2,
                "claim": "Deposits subtract from cash",
                "impact": "Cash is understated",
                "reproduction": "Compare opening 10 and deposit 5 with expected 15.",
                "evidence": [
                    {"path": file["path"], "side": "after", "line": 2, "sha256": file["after_hash"]}
                ],
            }
        ],
    }


def envelope(text):
    return {
        "status": "completed",
        "output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
        "usage": {"input_tokens": 100, "output_tokens": 100},
    }


@pytest.mark.parametrize("provider", ["openai", "anthropic", "google", "compatible", "ollama"])
def test_provider_request_shapes_separate_system_and_source(provider, monkeypatch):
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.setenv(key, "fictional")
    config = replace(model_config(), provider=provider)
    if provider == "compatible":
        config = replace(
            config, endpoint="https://models.example/v1/chat/completions", allowed_hosts=("models.example",)
        )
    config.validate()
    url, headers, body = request_shape(
        config, "trusted policy", {"text": "untrusted source"}, review_schema()
    )
    assert "fictional" not in json.dumps(body)
    assert "trusted policy" in json.dumps(body)
    assert "untrusted source" in json.dumps(body)
    assert url and headers["Content-Type"] == "application/json"


def test_no_network_without_both_approvals(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    with pytest.raises(AssistantError, match="network_not_approved"):
        invoke(model_config(), "system", {}, {}, network_approved=False)
    with pytest.raises(AssistantError, match="network_not_approved"):
        invoke(replace(model_config(), allow_network=False), "system", {}, {}, network_approved=True)


def test_source_bound_review_receipt_and_usage_settlement(repository, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=envelope(json.dumps(response(packet))))

    report = review_packet(
        packet,
        model_config(),
        tmp_path / "audit.db",
        network_approved=True,
        approved_packet_hash=packet["packet_hash"],
        transport=httpx.MockTransport(handler),
    )
    assert report["status"] == "findings" and not report["merge_authority"]
    assert len(calls) == 1
    with Ledger(tmp_path / "audit.db") as ledger:
        assert ledger.verify() == 5
        usage = next(row["payload"] for row in ledger.events() if row["payload"]["event"] == "model_usage")
        assert usage["input_tokens"] == 100 and usage["output_tokens"] == 100
        assert ledger.open_reservations() == []


def test_packet_approval_and_coverage_fail_before_transport(repository, tmp_path):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    with pytest.raises(AssistantError, match="packet_approval_required"):
        review_packet(packet, model_config(), tmp_path / "audit.db", network_approved=True)
    packet = build_packet(repo, base, head, replace(Config(), allow_paths=("docs/",)))
    with pytest.raises(AssistantError, match="scope_incomplete"):
        review_packet(
            packet,
            model_config(),
            tmp_path / "audit.db",
            network_approved=True,
            approved_packet_hash=packet["packet_hash"],
        )
    assert not (tmp_path / "audit.db").exists()


def test_partial_review_with_no_source_never_reserves_spend(repository, tmp_path):
    repo, base, head = repository
    config = replace(model_config(), allow_paths=("docs/",), allow_partial_review=True)
    packet = build_packet(repo, base, head, config)
    with pytest.raises(AssistantError, match="empty_model_context"):
        review_packet(
            packet,
            config,
            tmp_path / "audit.db",
            network_approved=True,
            approved_packet_hash=packet["packet_hash"],
        )
    assert not (tmp_path / "audit.db").exists()


@pytest.mark.parametrize(
    "mutation,code",
    [
        (lambda r: r.update(head="a" * 40), "review_head_mismatch"),
        (lambda r: r.update(reviewed_paths=[]), "review_coverage_mismatch"),
        (lambda r: r["findings"][0].update(path="src/unknown.py"), "finding_outside_scope"),
        (lambda r: r["findings"][0]["evidence"][0].update(sha256="a" * 64), "finding_evidence_invalid"),
        (lambda r: r["findings"][0]["evidence"][0].update(line=999), "finding_evidence_invalid"),
        (lambda r: r.update(extra="ignore safeguards"), "review_schema_invalid"),
    ],
)
def test_fabricated_or_stale_model_evidence_rejected(repository, mutation, code):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    result = response(packet)
    mutation(result)
    with pytest.raises(AssistantError, match=code):
        validate_review(result, packet)


def test_provider_error_is_fixed_code_and_unknown_spend_stays_reserved(repository, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    transport = httpx.MockTransport(lambda _: httpx.Response(401, text="sensitive provider error"))
    with pytest.raises(AssistantError, match="provider_http_error") as caught:
        review_packet(
            packet,
            model_config(),
            tmp_path / "audit.db",
            network_approved=True,
            approved_packet_hash=packet["packet_hash"],
            transport=transport,
        )
    assert "sensitive" not in str(caught.value)
    with Ledger(tmp_path / "audit.db") as ledger:
        assert len(ledger.open_reservations()) == 1


def test_redirect_is_not_followed(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    calls = []

    def handler(request):
        calls.append(request.url)
        return httpx.Response(307, headers={"location": "https://other.example/"})

    with pytest.raises(AssistantError, match="provider_http_error"):
        invoke(
            model_config(), "system", {}, {}, network_approved=True, transport=httpx.MockTransport(handler)
        )
    assert len(calls) == 1


def test_missing_key_is_preflighted_before_budget_reservation(repository, tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    with pytest.raises(AssistantError, match="provider_key_missing"):
        review_packet(
            packet,
            model_config(),
            tmp_path / "audit.db",
            network_approved=True,
            approved_packet_hash=packet["packet_hash"],
        )
    assert not (tmp_path / "audit.db").exists()


@pytest.mark.parametrize(
    "provider,data",
    [
        ("openai", {"status": "incomplete"}),
        ("anthropic", {"stop_reason": "max_tokens"}),
        ("google", {"candidates": [{"finishReason": "MAX_TOKENS"}]}),
        ("compatible", {"choices": [{"finish_reason": "length"}]}),
        ("ollama", {"done": False}),
    ],
)
def test_truncated_outputs_are_never_reviews(provider, data):
    with pytest.raises(AssistantError, match="provider_incomplete"):
        parse_response(provider, data)


@pytest.mark.parametrize(
    "provider,data",
    [
        ("openai", []),
        ("anthropic", None),
        ("openai", {"status": "completed", "output": [None]}),
        ("anthropic", {"stop_reason": "end_turn", "content": [1]}),
        ("google", {"candidates": [None]}),
        ("compatible", {"choices": ["unexpected"]}),
        ("ollama", {"done": True, "message": []}),
    ],
)
def test_malformed_provider_envelopes_fail_with_a_fixed_error(provider, data):
    with pytest.raises(AssistantError, match="invalid_provider_response"):
        parse_response(provider, data)
