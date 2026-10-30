"""Exact-request authorization and reservations, exercised with synthetic transports."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal
import json

import httpx
import pytest

from finassist.config import Config
from finassist.errors import AssistantError
from finassist.ledger import Ledger
from finassist.providers import invoke, request_identity, request_shape
from finassist.review import PolicyRequestApproval, call_model, review_schema
from finassist.scope import build_packet
from finassist.security import canonical
from test_providers_review import envelope, model_config, response


def test_identity_binds_destination_protocol_and_exact_body_not_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional-one")
    config = model_config()
    url, headers, payload = request_shape(config, "trusted", {"source": "fictional"}, {})
    identity, body = request_identity(url, headers, payload)
    assert body == canonical(payload)
    assert b"fictional-one" not in body
    assert request_identity(url, {**headers, "Authorization": "Bearer fictional-two"}, payload)[0] == identity
    assert request_identity(url + "/other", headers, payload)[0] != identity
    assert request_identity(url, headers, {**payload, "model": "other"})[0] != identity
    assert request_identity(url, {**headers, "anthropic-version": "another"}, payload)[0] != identity
    assert request_identity(url, {**headers, "x-api-key": "fictional"}, payload)[0] != identity


def test_invoke_rechecks_hash_before_dispatch_and_sends_identical_bytes(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    config = model_config()
    identity, body = request_identity(*request_shape(config, "trusted", {"note": "\u00e9"}, {}))
    calls = []

    def transport(request):
        calls.append(request)
        return httpx.Response(200, json=envelope("{}"))

    fake = httpx.MockTransport(transport)
    invoke(config, "trusted", {"note": "\u00e9"}, {}, network_approved=True,
           approved_request_hash=identity, transport=fake)
    assert calls[0].content == body and json.loads(body)["input"]
    with pytest.raises(AssistantError, match="request_approval_mismatch"):
        invoke(config, "changed", {"note": "\u00e9"}, {}, network_approved=True,
               approved_request_hash=identity, transport=fake)
    assert len(calls) == 1


def test_policy_approval_event_precedes_request_and_has_no_source_or_key(repository, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional-provider-value")
    repo, base, head = repository
    config = model_config()
    packet = build_packet(repo, base, head, Config())
    schema, system = review_schema(), config.instructions()
    identity, _ = request_identity(*request_shape(config, system, packet, schema))
    approval = PolicyRequestApproval("a" * 64, identity)
    path = tmp_path / "audit.sqlite"
    result, reservation = call_model(
        packet, config, path, schema, system, network_approved=True,
        approved_packet_hash=packet["packet_hash"], policy_approval=approval,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=envelope(json.dumps(response(packet))))),
    )
    assert result.input_tokens == 100 and reservation
    with Ledger(path) as ledger:
        events = [row["payload"] for row in ledger.events()]
        assert [e["event"] for e in events] == [
            "reserved", "request_approved", "review_requested", "model_usage", "settled",
        ]
        assert events[1]["approved_by"] == "policy"
        assert events[1]["request_sha256"] == identity
        assert events[1]["policy_sha256"] == "a" * 64
        serialized = canonical(events)
        assert b"fictional-provider-value" not in serialized and b"return opening" not in serialized
        assert not ledger.open_reservations()


@pytest.mark.parametrize("approval,code", [
    (PolicyRequestApproval("a" * 64, "b" * 64), "request_approval_mismatch"),
    (PolicyRequestApproval("invalid", "b" * 64), "policy_request_approval_invalid"),
])
def test_bad_approval_never_creates_a_reservation(repository, tmp_path, monkeypatch, approval, code):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    path = tmp_path / "audit.sqlite"
    with pytest.raises(AssistantError, match=code):
        call_model(packet, model_config(), path, review_schema(), "trusted",
                   network_approved=True, approved_packet_hash=packet["packet_hash"], policy_approval=approval)
    assert not path.exists()


def test_unknown_usage_holds_reservation_and_blocks_second_attempt(repository, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    config = model_config()
    packet = build_packet(repo, base, head, Config())
    schema, system = review_schema(), config.instructions()
    identity, _ = request_identity(*request_shape(config, system, packet, schema))
    calls = []

    def handler(request):
        calls.append(request)
        data = envelope(json.dumps(response(packet)))
        data.pop("usage")
        return httpx.Response(200, json=data)

    args = dict(network_approved=True, approved_packet_hash=packet["packet_hash"],
                policy_approval=PolicyRequestApproval("a" * 64, identity), transport=httpx.MockTransport(handler))
    path = tmp_path / "audit.sqlite"
    call_model(packet, config, path, schema, system, **args)
    with pytest.raises(AssistantError, match="unreconciled_model_usage"):
        call_model(packet, config, path, schema, system, **args)
    assert len(calls) == 1
    with Ledger(path) as ledger:
        assert len(ledger.open_reservations()) == 1
        ledger.verify()


def test_only_one_concurrent_unattended_reservation_can_start(tmp_path):
    path = tmp_path / "audit.sqlite"
    with Ledger(path):
        pass

    def attempt(_):
        with Ledger(path) as ledger:
            try:
                return ledger.reserve(Decimal("0.01"), Decimal(1), Decimal(1), require_reconciled=True)
            except AssistantError as exc:
                assert exc.code == "unreconciled_model_usage"
                return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        identifiers = list(pool.map(attempt, range(8)))
    assert sum(identifier is not None for identifier in identifiers) == 1


def test_budget_failure_never_records_policy_approval(repository, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    config = replace(model_config(), max_run_usd=0)
    packet = build_packet(repo, base, head, Config())
    schema, system = review_schema(), config.instructions()
    identity, _ = request_identity(*request_shape(config, system, packet, schema))
    path = tmp_path / "audit.sqlite"
    with pytest.raises(AssistantError, match="run_budget_exceeded"):
        call_model(packet, config, path, schema, system, network_approved=True,
                   approved_packet_hash=packet["packet_hash"],
                   policy_approval=PolicyRequestApproval("a" * 64, identity))
    with Ledger(path) as ledger:
        assert ledger.events() == [] and ledger.open_reservations() == []
