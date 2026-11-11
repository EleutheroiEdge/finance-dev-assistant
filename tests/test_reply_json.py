"""What a provider or a model sent is read as JSON and nothing wider, on every route.

Python's reader takes NaN and Infinity, turns a number too large to hold into infinity, and stops on
deep nesting with a RecursionError. None of those may reach a screen or a record, and none may leave
a route as anything but that route's stated refusal. Every value here is synthetic.
"""
import json

import httpx
import pytest

from finassist.config import Config
from finassist.errors import AssistantError
from finassist.ledger import Ledger
import finassist.model_gate as gate_module
from finassist.proposal import propose
from finassist.providers import invoke, reply_json
from finassist.review import review_packet, review_schema
from finassist.scope import build_packet
from finassist.security import canonical
from test_model_gate import run
from test_providers_review import envelope, model_config, response

pytest_plugins = ("test_model_gate", "test_model_policy")

DEEP = 100_000
NOT_JSON = {
    "nan": "[NaN]",
    "infinity": '{"a": Infinity}',
    "minus_infinity": "[-Infinity]",
    "too_large": "[1e999]",
    "too_large_below_zero": "[-1e999]",
    "deep_array": "[" * DEEP,
    "deep_object": '{"a":' * DEEP,
    "deep_and_closed": "[" * DEEP + "]" * DEEP,
    "key_twice": '{"a": 1, "a": 2}',
    "key_twice_inside": '[{"a": {"b": 1, "b": 1}}]',
    # Not an integer as written, and one once Python has rounded it: Codex P111-1.
    "just_over_an_integer": "[2.0000000000000001]",
    "just_under_an_integer": "[1.9999999999999999]",
    "a_half_too_large_to_keep": "[9007199254740993.5]",
    "too_small": "[1e-400]",
}
wider = pytest.mark.parametrize("text", NOT_JSON.values(), ids=NOT_JSON.keys())


@wider
def test_text_that_is_wider_than_json_is_not_read(text):
    for given in (text, text.encode()):
        with pytest.raises(ValueError):
            reply_json(given)


@pytest.mark.parametrize("text", [
    '{"line": 2, "share": 0.25, "count": 1e2, "big": 1%s, "small": 5e-324, "text": "NaN and Infinity"}' % ("0" * 400),
    "[]", '"NaN"', "null", "-0.0", "[" * 50 + "]" * 50,
])
def test_json_is_read_as_before(text):
    assert reply_json(text) == json.loads(text)
    assert reply_json(text.encode()) == json.loads(text)


@pytest.mark.parametrize("written,value", [
    ("2.0", 2), ("2e0", 2), ("20e-1", 2), ("1E+2", 100), ("-0.0", 0), ("2", 2), ("123456789.000", 123456789),
    # Exactly, however large: the digits are read, not the binary value they would round to.
    ("9007199254740993.0", 9007199254740993), ("1e23", 10**23), ("1e308", 10**308),
    ("2.5", 2.5), ("0.1", 0.1), ("0.30000000000000004", 0.30000000000000004), ("5e-324", 5e-324),
])
def test_a_number_that_is_an_integer_as_written_is_read_as_that_integer(written, value):
    read = reply_json('{"line": %s}' % written)["line"]
    assert read == value and type(read) is type(value)


def test_a_very_long_number_is_read_or_refused_at_once():
    assert reply_json("1." + "0" * 1_000_000) == 1
    for text in ("9" * 1_000_000 + ".0", "0." + "0" * 1_000_000 + "1", "1e1000000000", "1e-1000000000"):
        with pytest.raises(ValueError):
            reply_json(text)


def _replies(text):
    return httpx.MockTransport(lambda _request: httpx.Response(200, json=envelope(text)))


@wider
def test_a_review_refuses_such_a_reply_as_invalid_json(repository, tmp_path, monkeypatch, text):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    with pytest.raises(AssistantError, match="^review_json_invalid$"):
        review_packet(packet, model_config(), tmp_path / "audit.db", network_approved=True,
                      approved_packet_hash=packet["packet_hash"], transport=_replies(text))


@wider
def test_a_proposal_refuses_such_a_reply(repository, tmp_path, monkeypatch, text):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    with pytest.raises(AssistantError, match="^proposal_schema_invalid$"):
        propose(packet, model_config(), tmp_path / "audit.sqlite", network_approved=True,
                approved_packet_hash=packet["packet_hash"], transport=_replies(text))


@wider
def test_a_gate_blocks_such_a_reply_as_invalid_json(gate_case, text):
    report, calls = run(gate_case, lambda _packet: envelope(text))
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["review_json_invalid"] and len(calls) == 1
    assert not report["findings"]


def _with_lines_written(packet, written):
    text = json.dumps(response(packet))
    assert text.count('"line": 2') == 2  # the finding's line and its evidence's
    return text.replace('"line": 2', '"line": ' + written)


@pytest.mark.parametrize("written", ["2.0", "2e0"])
def test_a_gate_reads_a_line_written_with_a_point_as_that_line(gate_case, written):
    """On main this run ended with gate_report_invalid and no report."""
    report, calls = run(gate_case, lambda packet: envelope(_with_lines_written(packet, written)))
    assert report["verdict"] in ("PASS", "FAIL") and len(calls) == 1
    assert [(finding["line"], type(finding["line"])) for finding in report["findings"]] == [(2, int)]


@pytest.mark.parametrize("written", ["2.0", "2e0"])
def test_a_review_reads_a_line_written_with_a_point_as_that_line(repository, tmp_path, monkeypatch, written):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    report = review_packet(packet, model_config(), tmp_path / "audit.db", network_approved=True,
                           approved_packet_hash=packet["packet_hash"],
                           transport=_replies(_with_lines_written(packet, written)))
    assert report["status"] == "findings"
    assert b'"line":2,' in canonical(report) and b'"line":2.0' not in canonical(report)


@pytest.mark.parametrize("written", ["2.0000000000000001", "1.9999999999999999"])
def test_a_line_that_only_rounding_makes_an_integer_is_not_a_line(gate_case, repository, tmp_path, monkeypatch, written):
    """Codex P111-1: the first version of this reader took both for line 2 and a gate passed them."""
    report, calls = run(gate_case, lambda packet: envelope(_with_lines_written(packet, written)))
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["review_json_invalid"] and len(calls) == 1
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    with pytest.raises(AssistantError, match="^review_json_invalid$"):
        review_packet(packet, model_config(), tmp_path / "audit.db", network_approved=True,
                      approved_packet_hash=packet["packet_hash"],
                      transport=_replies(_with_lines_written(packet, written)))


def test_a_gate_that_cannot_identify_a_finding_blocks_and_still_reports(gate_case, monkeypatch):
    def refuse(*_arguments):
        raise AssistantError("finding_identity_invalid")

    monkeypatch.setattr(gate_module, "finding_identifier", refuse)
    report, calls = run(gate_case)  # run() checks the report against its schema and its hash
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["finding_identity_invalid"]
    assert report["findings"] == [] and len(calls) == 1


def test_a_token_count_written_with_a_point_is_a_count(repository, tmp_path, monkeypatch):
    """On main the count was not taken for one, and the reservation stayed open."""
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    body = json.dumps(envelope(json.dumps(response(packet)))).replace('"input_tokens": 100', '"input_tokens": 100.0')
    assert "100.0" in body
    transport = httpx.MockTransport(lambda _request: httpx.Response(
        200, content=body.encode(), headers={"content-type": "application/json"}))
    report = review_packet(packet, model_config(), tmp_path / "audit.db", network_approved=True,
                           approved_packet_hash=packet["packet_hash"], transport=transport)
    assert report["status"] == "findings"
    with Ledger(tmp_path / "audit.db") as ledger:
        usage = next(row["payload"] for row in ledger.events() if row["payload"]["event"] == "model_usage")
        assert (usage["input_tokens"], type(usage["input_tokens"]), usage["output_tokens"]) == (100, int, 100)
        assert ledger.open_reservations() == []


def test_a_token_count_that_only_rounding_makes_a_count_is_not_one(repository, tmp_path, monkeypatch):
    """Codex P111-1: such a count closed the reservation. It is no count, and the spend stays open."""
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    body = json.dumps(envelope(json.dumps(response(packet)))).replace(
        '"input_tokens": 100', '"input_tokens": 100.0000000000000001')
    transport = httpx.MockTransport(lambda _request: httpx.Response(
        200, content=body.encode(), headers={"content-type": "application/json"}))
    with pytest.raises(AssistantError, match="^provider_transport_failed$"):
        review_packet(packet, model_config(), tmp_path / "audit.db", network_approved=True,
                      approved_packet_hash=packet["packet_hash"], transport=transport)
    with Ledger(tmp_path / "audit.db") as ledger:
        assert len(ledger.open_reservations()) == 1


ENVELOPES = {**NOT_JSON, "usage_that_is_no_number": json.dumps(envelope("{}")).replace("100", "NaN", 1)}


@pytest.mark.parametrize("text", ENVELOPES.values(), ids=ENVELOPES.keys())
def test_a_provider_envelope_like_that_is_a_transport_failure(monkeypatch, text):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    transport = httpx.MockTransport(lambda _request: httpx.Response(
        200, content=text.encode(), headers={"content-type": "application/json"}))
    with pytest.raises(AssistantError, match="^provider_transport_failed$"):
        invoke(model_config(), "system", {}, review_schema(), network_approved=True, transport=transport)
