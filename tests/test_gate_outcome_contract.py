"""Gate F2: a timeout, a failed connection or a provider error is never a pass.

Each ends BLOCKED after exactly one request, with its own reason and the spend held as not yet reconciled, and
the next run is BLOCKED before any request. No retry and no fallback. Only PASS exits 0.
Synthetic Git and a fake provider only.
"""

import httpx
import pytest

from test_model_gate import gate_case, run  # noqa: F401 - fixture registration
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration
from finassist.model_gate import EXIT_CODES, model_gate


def _raises(error):
    def handler(_packet):
        raise error
    return handler


def _assert_held(report, calls, code):
    assert report["verdict"] == "BLOCKED" and EXIT_CODES[report["verdict"]] != 0
    assert report["reasons"] == [code, "unreconciled_model_usage"] and len(calls) == 1
    assert report["spend"]["actual_usd"] is None and float(report["spend"]["reserved_usd"]) > 0
    assert report["findings"] == []


@pytest.mark.parametrize("error,code", [
    (httpx.ReadTimeout("synthetic"), "provider_timeout"),
    (httpx.ConnectTimeout("synthetic"), "provider_timeout"),
    (httpx.ConnectError("synthetic"), "provider_connection_failed"),
])
def test_a_timeout_or_failed_connection_blocks_and_holds_the_spend(gate_case, error, code):  # noqa: F811
    _assert_held(*run(gate_case, _raises(error)), code)
    again, calls = run(gate_case)
    assert again["verdict"] == "BLOCKED" and again["reasons"] == ["unreconciled_model_usage"] and not calls


@pytest.mark.parametrize("status,code", [
    (408, "provider_timeout"),
    (429, "provider_http_rate_limited"),
    (500, "provider_http_server_error"),
    (503, "provider_http_server_error"),
])
def test_a_provider_error_status_blocks_and_holds_the_spend(gate_case, status, code):  # noqa: F811
    calls = []

    def transport(request):
        calls.append(request)
        return httpx.Response(status, json={"error": {"message": "synthetic"}})

    report = model_gate(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                        gate_case["pin"], gate_case["state"], transport=httpx.MockTransport(transport))
    _assert_held(report, calls, code)
    again, calls = run(gate_case)
    assert again["verdict"] == "BLOCKED" and again["reasons"] == ["unreconciled_model_usage"] and not calls


def test_only_pass_or_an_opted_in_not_applicable_exits_zero():
    # NOT_APPLICABLE is produced only under the policy's explicit out_of_scope_ranges opt-in, as its own
    # document; test_not_applicable.py shows the default policy blocks such a range.
    assert {verdict for verdict, code in EXIT_CODES.items() if code == 0} == {"PASS", "NOT_APPLICABLE"}
