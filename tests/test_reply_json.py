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
}
wider = pytest.mark.parametrize("text", NOT_JSON.values(), ids=NOT_JSON.keys())


@wider
def test_text_that_is_wider_than_json_is_not_read(text):
    for given in (text, text.encode()):
        with pytest.raises(ValueError):
            reply_json(given)


@pytest.mark.parametrize("text", [
    '{"line": 2, "share": 0.25, "count": 1e2, "big": 1%s, "tiny": 1e-400, "text": "NaN and Infinity"}' % ("0" * 400),
    "[]", '"NaN"', "null", "-0.0", "[" * 50 + "]" * 50,
])
def test_json_is_read_as_before(text):
    assert reply_json(text) == json.loads(text)
    assert reply_json(text.encode()) == json.loads(text)


@pytest.mark.parametrize("written,value", [
    ("2.0", 2), ("2e0", 2), ("20e-1", 2), ("-0.0", 0), ("1e22", 10**22), ("2", 2), ("2.5", 2.5), ("1e-400", 0),
])
def test_a_number_that_equals_an_integer_is_read_as_that_integer(written, value):
    read = reply_json('{"line": %s}' % written)["line"]
    assert read == value and type(read) is type(value)


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


def test_a_gate_that_cannot_identify_a_finding_blocks_and_still_reports(gate_case, monkeypatch):
    def refuse(*_arguments):
        raise AssistantError("finding_identity_invalid")

    monkeypatch.setattr(gate_module, "finding_identifier", refuse)
    report, calls = run(gate_case)  # run() checks the report against its schema and its hash
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["finding_identity_invalid"]
    assert report["findings"] == [] and len(calls) == 1


ENVELOPES = {**NOT_JSON, "usage_that_is_no_number": json.dumps(envelope("{}")).replace("100", "NaN", 1)}


@pytest.mark.parametrize("text", ENVELOPES.values(), ids=ENVELOPES.keys())
def test_a_provider_envelope_like_that_is_a_transport_failure(monkeypatch, text):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    transport = httpx.MockTransport(lambda _request: httpx.Response(
        200, content=text.encode(), headers={"content-type": "application/json"}))
    with pytest.raises(AssistantError, match="^provider_transport_failed$"):
        invoke(model_config(), "system", {}, review_schema(), network_approved=True, transport=transport)
