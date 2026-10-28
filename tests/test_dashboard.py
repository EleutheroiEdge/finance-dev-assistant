from dataclasses import asdict
from datetime import datetime, timezone
from decimal import Decimal
import http.client
import json
import threading

import pytest

from finassist.auditing import command_audit
from finassist.config import Config, load_config, save_config
from finassist.dashboard import DashboardServer, DashboardState
from finassist.errors import AssistantError
from finassist.health import doctor_report
from finassist.ledger import Ledger
from finassist.statistics import statistics


@pytest.fixture
def dashboard(tmp_path):
    path = tmp_path.resolve() / "configuration.json"
    save_config(path, Config())
    state = DashboardState(path, tmp_path.resolve() / "state")
    with DashboardServer(state) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def request(method, path, body=None, *, token=True, origin=True, headers=None):
            selected = {"Content-Type": "application/json"}
            if token:
                selected["X-Finassist-Token"] = state.token
            if origin:
                selected["Origin"] = server.origin
            selected.update(headers or {})
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            try:
                connection.request(
                    method, path, body=json.dumps(body) if body is not None else None, headers=selected
                )
                response = connection.getresponse()
                data = response.read()
                value = (
                    json.loads(data)
                    if response.getheader("Content-Type", "").startswith("application/json")
                    else data
                )
                return response.status, value, dict(response.getheaders())
            finally:
                connection.close()

        yield state, server, request
        server.shutdown()
        thread.join(timeout=5)


def test_python_serves_prebuilt_assets_and_offline_health(dashboard):
    state, server, request = dashboard
    assert server.server_address[0] == "127.0.0.1"
    status, html, headers = request("GET", "/", token=False)
    assert status == 200 and b'<div id="root"></div>' in html
    assert "connect-src 'self'" in headers["Content-Security-Policy"]
    assert headers["Cache-Control"] == "no-store"
    assert request("GET", "/api/health")[1]["doctor"] == doctor_report(Config())
    assert request("GET", "/api/health")[1]["configuration"]["valid"]
    assert not state.ledger_path.exists()  # Read-only pages don't create fake audit runs.
    assert request("GET", "/../config.py", token=False)[0] == 404
    assert request("GET", "/%2e%2e/config.py", token=False)[0] == 404


@pytest.mark.parametrize(
    "method,path,headers,token,origin",
    [
        ("GET", "/api/config", {}, False, True),
        ("POST", "/api/config/preview", {}, False, True),
        ("POST", "/api/config/preview", {}, True, False),
        ("GET", "/api/session", {"Origin": "https://example.invalid"}, False, True),
        ("GET", "/api/session", {"Host": "example.invalid"}, False, False),
        ("GET", "/api/session", {"Sec-Fetch-Site": "cross-site"}, False, False),
        ("POST", "/api/config/preview", {"Origin": "null"}, True, True),
    ],
)
def test_cross_site_and_missing_token_requests_are_rejected(dashboard, method, path, headers, token, origin):
    state, _, request = dashboard
    before = state.config_path.read_bytes()
    assert request(method, path, {}, headers=headers, token=token, origin=origin)[0] == 403
    assert state.config_path.read_bytes() == before


def test_preflight_and_oversized_bodies_are_rejected(dashboard):
    state, _, request = dashboard
    before = state.config_path.read_bytes()
    assert request("OPTIONS", "/api/config/confirm")[0] == 403
    assert (
        request("POST", "/api/config/preview", {"padding": "x" * 65536})[1]["code"] == "request_size_invalid"
    )
    assert state.config_path.read_bytes() == before


def test_preview_then_explicit_one_use_confirmation_preserves_unrelated_settings(dashboard):
    state, _, request = dashboard
    current = request("GET", "/api/config")[1]
    before = state.config_path.read_bytes()
    status, preview, _ = request(
        "POST", "/api/config/preview", {"revision": current["revision"], "changes": {"daily_budget_usd": 7}}
    )
    assert status == 200 and preview["diff"] == [{"field": "daily_budget_usd", "before": 5.0, "after": 7}]
    assert state.config_path.read_bytes() == before
    assert (
        request("POST", "/api/config/confirm", {"proposal_id": preview["proposal_id"], "confirm": False})[0]
        == 409
    )
    assert state.config_path.read_bytes() == before
    status, _, _ = request(
        "POST", "/api/config/confirm", {"proposal_id": preview["proposal_id"], "confirm": True}
    )
    assert status == 200 and load_config(state.config_path).daily_budget_usd == 7
    assert load_config(state.config_path).allow_network is False
    assert list((state.ledger_path.parent / "config-backups").glob("*.json"))
    assert (
        request("POST", "/api/config/confirm", {"proposal_id": preview["proposal_id"], "confirm": True})[0]
        == 409
    )
    with Ledger(state.ledger_path) as ledger:
        assert any(row["payload"]["event"] == "configuration_saved" for row in ledger.events())
        assert not ledger.incomplete_runs()


def test_external_edit_invalidates_confirmation(dashboard):
    state, _, request = dashboard
    config = request("GET", "/api/config")[1]
    preview = request(
        "POST", "/api/config/preview", {"revision": config["revision"], "changes": {"daily_budget_usd": 9}}
    )[1]
    state.config_path.write_bytes(json.dumps(asdict(Config(daily_budget_usd=8))).encode("utf-8"))
    response = request(
        "POST", "/api/config/confirm", {"proposal_id": preview["proposal_id"], "confirm": True}
    )
    assert response[0] == 409 and response[1]["code"] == "configuration_changed_reload"
    assert load_config(state.config_path).daily_budget_usd == 8


@pytest.mark.parametrize(
    "changes",
    [
        {"daily_budget_usd": -1},
        {"monthly_budget_usd": -1},
        {"readiness_max_age_seconds": 1.5},
        {"extra_sensitive_patterns": ["["]},
        {"required_recipes": ["undefined"]},
        {"api_key": "dummy"},
        {"api_key_env": "OTHER_NAME"},
    ],
)
def test_validation_is_shared_with_cli_and_keys_cannot_be_edited(dashboard, changes):
    state, _, request = dashboard
    before = state.config_path.read_bytes()
    current = request("GET", "/api/config")[1]
    assert (
        request("POST", "/api/config/preview", {"revision": current["revision"], "changes": changes})[0]
        == 409
    )
    assert state.config_path.read_bytes() == before


def test_environment_values_never_reach_responses_files_or_audit(dashboard, monkeypatch):
    state, _, request = dashboard
    marker = "synthetic" + "-environment-value" * 2
    monkeypatch.setenv("OPENAI_API_KEY", marker)
    config = request("GET", "/api/config")[1]
    assert config["key_presence"]["openai"] is True
    assert marker not in json.dumps(config)
    preview = request(
        "POST", "/api/config/preview", {"revision": config["revision"], "changes": {"model": "chosen"}}
    )[1]
    assert (
        request("POST", "/api/config/confirm", {"proposal_id": preview["proposal_id"], "confirm": True})[0]
        == 200
    )
    assert marker not in state.config_path.read_text(encoding="utf-8")
    with Ledger(state.ledger_path) as ledger:
        assert marker not in json.dumps(ledger.events())


def test_invalid_config_health_remains_available(dashboard):
    state, _, request = dashboard
    state.config_path.write_text("invalid JSON", encoding="utf-8", newline="\n")
    assert request("GET", "/api/config")[0] == 409
    assert request("GET", "/api/health")[1]["configuration"]["valid"] is False


def test_sensitive_patterns_can_be_configured_without_matching_their_own_definition(dashboard):
    _, _, request = dashboard
    config = request("GET", "/api/config")[1]
    preview = request(
        "POST",
        "/api/config/preview",
        {"revision": config["revision"], "changes": {"extra_sensitive_patterns": ["internal phrase"]}},
    )
    assert preview[0] == 200
    assert (
        request(
            "POST",
            "/api/config/confirm",
            {
                "proposal_id": preview[1]["proposal_id"],
                "confirm": True,
            },
        )[0]
        == 200
    )
    assert request("GET", "/api/config")[0] == 200


def test_audit_failure_after_save_reports_unknown_without_replaying(dashboard, monkeypatch):
    state, _, request = dashboard
    config = request("GET", "/api/config")[1]
    preview = request(
        "POST",
        "/api/config/preview",
        {
            "revision": config["revision"],
            "changes": {"daily_budget_usd": 7},
        },
    )[1]
    original = Ledger.append

    def fail_receipt(ledger, payload):
        if payload["event"] == "configuration_saved":
            raise OSError("synthetic audit failure")
        return original(ledger, payload)

    monkeypatch.setattr(Ledger, "append", fail_receipt)
    body = {"proposal_id": preview["proposal_id"], "confirm": True}
    assert (
        request("POST", "/api/config/confirm", body)[1]["code"] == "configuration_saved_audit_unknown_reload"
    )
    assert load_config(state.config_path).daily_budget_usd == 7
    assert request("POST", "/api/config/confirm", body)[1]["code"] == "proposal_missing_or_consumed"


def test_monthly_budget_includes_prior_month_unknown_reservations(tmp_path, monkeypatch):
    class Past(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2000, 1, 1, tzinfo=timezone.utc)

    with Ledger(tmp_path / "audit.db") as ledger:
        with monkeypatch.context() as patcher:
            patcher.setattr("finassist.ledger.datetime", Past)
            reservation = ledger.reserve(Decimal("0.4"), Decimal(10), Decimal(1), Decimal("0.5"))
        with pytest.raises(AssistantError, match="monthly_budget_exceeded"):
            ledger.reserve(Decimal("0.2"), Decimal(10), Decimal(1), Decimal("0.5"))
        ledger.settle(reservation, Decimal("0.4"))
        ledger.reserve(Decimal("0.2"), Decimal(10), Decimal(1), Decimal("0.5"))
        ledger.verify()


def test_statistics_uses_verified_metadata_and_marks_legacy_gaps(tmp_path):
    path = tmp_path / "audit.sqlite"
    with command_audit(path, "review", Config()):
        with Ledger(path) as ledger:
            first = ledger.reserve(Decimal(1), Decimal(10), Decimal(2))
            ledger.append({"event": "review_requested", "reservation": first})
            ledger.append(
                {"event": "model_usage", "reservation": first, "input_tokens": 30, "output_tokens": 10}
            )
            ledger.settle(first, Decimal("0.25"))
            ledger.append(
                {"event": "review_completed", "profile": "general", "findings_by_severity": {"high": 2}}
            )
            ledger.append({"event": "review_completed"})
            ledger.append({"event": "review_requested"})
            ledger.reserve(Decimal("0.5"), Decimal(10), Decimal(2))
            ledger.append({"event": "check_completed", "recipe": "unit", "passed": True})
            ledger.append({"event": "check_completed", "recipe": "unit", "passed": False})
            ledger.append({"event": "check_completed"})
            ledger.append({"event": "readiness_evaluated", "status": "blocked", "reasons": ["stale"]})
            ledger.append(
                {"event": "readiness_evaluated", "status": "eligible-for-human-review", "reasons": []}
            )
            ledger.append({"event": "synthetic", "raw_source": "never-return-this-marker"})
    result = statistics(path, Config())
    assert result["spend"]["today_usd"] == "0.25" and result["spend"]["open_reserved_usd"] == "0.5"
    assert result["reviews"]["findings"] == {"high": 2} and result["reviews"]["unknown_findings"] == 1
    assert result["reviews"]["findings_by_profile"] == {"general": 2}
    assert result["spend"]["available_today_usd"] == "4.25"
    assert result["usage"] == {
        "known_calls": 1,
        "unknown_calls": 1,
        "qualification": "Older or failed calls can lack usage metadata. Missing counts are not zero.",
    }
    assert result["recipes"] == [{"name": "unit", "passed": 1, "total": 2}]
    assert result["readiness"]["reasons"] == {"stale": 1}
    assert result["recent_runs"][0]["status"] == "completed"
    assert "never-return-this-marker" not in json.dumps(result)
    with Ledger(path) as ledger:
        ledger.db.execute("UPDATE events SET hash='corrupt' WHERE seq=1")
    with pytest.raises(AssistantError, match="audit_integrity_failed"):
        statistics(path, Config())
