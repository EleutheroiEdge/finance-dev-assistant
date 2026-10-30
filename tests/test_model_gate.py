"""Unattended model gate contracts with synthetic Git and fake provider IO only."""

from copy import deepcopy
from decimal import Decimal
import json

import httpx
import pytest

from conftest import command
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration
from test_providers_review import envelope, response
from finassist.ledger import Ledger
from finassist.model_gate import EXIT_CODES, model_gate, validate_model_report
from finassist.security import canonical, digest


@pytest.fixture
def gate_case(request, monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)  # Synthetic local caller, including on hosted CI.
    repo, base, pin = request.getfixturevalue("policy_case")()
    (repo / "src/cash.py").write_text("def balance(opening, deposits):\n    return opening - deposits - 1\n", encoding="utf-8")
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Synthetic gate candidate")
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "fictional-provider-value")
    return {"repo": repo, "base": base, "head": command(repo, "rev-parse", "HEAD"),
            "pin": pin, "state": tmp_path / "private-state"}


def run(case, handler=None, **kwargs):
    calls = []

    def transport(request):
        calls.append(request)
        packet = json.loads(json.loads(request.content)["input"])
        return httpx.Response(200, json=handler(packet) if handler else envelope(json.dumps(response(packet))))

    report = model_gate(case["repo"], case["base"], case["head"], "gate-policy.json", case["pin"],
                        case["state"], transport=httpx.MockTransport(transport), **kwargs)
    assert report["report_hash"] == digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
    assert not report["merge_authority"] and not report["deployment_authority"]
    return report, calls


def change_policy(case, **changes):
    document = model_policy()
    document["model_review"].update(changes)
    (case["repo"] / "gate-policy.json").write_bytes(canonical(document))
    command(case["repo"], "add", "gate-policy.json")
    command(case["repo"], "commit", "-m", "Synthetic reviewed policy")
    case["base"] = command(case["repo"], "rev-parse", "HEAD")
    case["pin"] = digest(canonical(document))
    (case["repo"] / "src/cash.py").write_text("def balance(opening, deposits):\n    return 0\n", encoding="utf-8")
    command(case["repo"], "add", "src/cash.py")
    command(case["repo"], "commit", "-m", "Synthetic new candidate")
    case["head"] = command(case["repo"], "rev-parse", "HEAD")


def test_advisory_pass_has_structured_evidence_usage_and_policy_approval(gate_case):
    report, calls = run(gate_case)
    assert report["verdict"] == "PASS" and len(calls) == 1 and not report["reasons"]
    assert report["usage"] == {"input_tokens": 100, "output_tokens": 100}
    assert report["spend"]["actual_usd"] == "0.0003"
    assert report["findings"][0]["evidence_status"] == "source-reference-validated-not-reproduced"
    assert "return opening" not in canonical(report).decode()
    with Ledger(gate_case["state"] / "audit.sqlite") as ledger:
        approval = next(e["payload"] for e in ledger.events() if e["payload"]["event"] == "request_approved")
        assert approval["request_sha256"] == report["request_sha256"]
        assert approval["policy_sha256"] == report["policy_sha256"] == gate_case["pin"]


def test_selected_severity_fails_while_default_is_advisory(gate_case):
    change_policy(gate_case, blocking_severities=["high"])
    report, calls = run(gate_case)
    assert len(calls) == 1 and report["verdict"] == "FAIL"
    assert report["reasons"] == ["gate_blocking_findings"]
    assert [EXIT_CODES[v] for v in ("PASS", "FAIL", "BLOCKED")] == [0, 1, 2]


@pytest.mark.parametrize("changes,code", [
    ({"max_request_bytes": 1}, "gate_request_bytes_exceeded"),
    ({"deny_paths": ["src/"]}, "gate_denied_path"),
    ({"allow_paths": ["tests/"]}, "gate_path_not_allowed"),
    ({"max_run_usd": 0}, "run_budget_exceeded"),
    ({"daily_budget_usd": 0}, "daily_budget_exceeded"),
    ({"max_file_bytes": 1}, "file_limit_exceeded"),
])
def test_policy_boundaries_block_before_dispatch(gate_case, changes, code):
    change_policy(gate_case, **changes)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == [code] and not calls


def test_missing_key_pin_mismatch_and_head_policy_never_dispatch(gate_case, monkeypatch):
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    report, calls = run(gate_case)
    assert report["reasons"] == ["provider_key_missing"] and not calls
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "fictional-provider-value")
    wrong = deepcopy(gate_case)
    wrong["pin"] = "0" * 64
    assert run(wrong)[0]["reasons"] == ["gate_policy_pin_mismatch"]
    (gate_case["repo"] / "gate-policy.json").write_bytes(canonical({"schema_version": 2}))
    command(gate_case["repo"], "add", "gate-policy.json")
    command(gate_case["repo"], "commit", "-m", "Unapproved policy change")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_policy_change_requires_review"] and not calls


@pytest.mark.parametrize("name", ["data/source.py", "src/client_config.json", "src/households/source.py", ".env.test"])
def test_minimum_privacy_rules_cannot_be_disabled(gate_case, name):
    target = gate_case["repo"] / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{}\n", encoding="utf-8")
    command(gate_case["repo"], "add", "--force", name)
    command(gate_case["repo"], "commit", "-m", "Synthetic denied source")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls


def test_force_added_ignored_source_is_blocked_even_with_dirty_rule_removal(gate_case):
    repo = gate_case["repo"]
    (repo / ".gitignore").write_text("src/private.py\n", encoding="utf-8")
    command(repo, "add", ".gitignore")
    command(repo, "commit", "-m", "Synthetic private baseline rule")
    gate_case["base"] = command(repo, "rev-parse", "HEAD")
    (repo / "src/private.py").write_text("synthetic = 1\n", encoding="utf-8")
    command(repo, "add", "--force", "src/private.py")
    command(repo, "commit", "-m", "Synthetic forced tracked source")
    gate_case["head"] = command(repo, "rev-parse", "HEAD")
    (repo / ".gitignore").write_text("", encoding="utf-8")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_ignored_path"] and not calls


def test_sensitive_content_is_blocked_before_dispatch(gate_case):
    (gate_case["repo"] / "src/cash.py").write_text("access_" + 'token = "' + "x" * 30 + '"\n', encoding="utf-8")
    command(gate_case["repo"], "add", "src/cash.py")
    command(gate_case["repo"], "commit", "-m", "Synthetic content screening")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert report["reasons"] == ["sensitive_content"] and not calls


def test_unknown_usage_blocks_and_is_not_automatically_retried(gate_case):
    def missing_usage(packet):
        value = envelope(json.dumps(response(packet)))
        value.pop("usage")
        return value

    report, calls = run(gate_case, missing_usage)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["unreconciled_model_usage"]
    assert len(calls) == 1 and report["spend"]["actual_usd"] is None
    assert Decimal(report["spend"]["reserved_usd"]) > 0
    again, calls = run(gate_case)
    assert again["verdict"] == "BLOCKED" and not calls


def test_provider_key_echo_is_never_in_report_or_audit(gate_case):
    def echo(packet):
        value = response(packet)
        value["summary"] = "fictional-provider-value"
        return envelope(json.dumps(value))

    report, calls = run(gate_case, echo)
    assert len(calls) == 1 and report["reasons"] == ["gate_provider_echoed_key"]
    assert "fictional-provider-value" not in canonical(report).decode()
    with Ledger(gate_case["state"] / "audit.sqlite") as ledger:
        assert "fictional-provider-value" not in canonical(ledger.events()).decode()


def test_fork_context_blocks_before_key_or_policy_access(gate_case, tmp_path, monkeypatch):
    event = {"action": "synchronize", "number": 1, "repository": {"full_name": "Example/Project"},
             "pull_request": {"number": 1, "base": {"sha": gate_case["base"], "ref": "main",
                             "repo": {"full_name": "Example/Project"}},
                              "head": {"sha": gate_case["head"], "repo": {"full_name": "Other/Project"}}}}
    path = tmp_path / "event.json"
    path.write_bytes(canonical(event))
    monkeypatch.setattr("finassist.model_gate.load_model_policy", lambda *_: pytest.fail("policy/key preflight reached"))
    report, calls = run(gate_case, environment={"GITHUB_ACTIONS": "true", "GITHUB_EVENT_PATH": str(path),
                        "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REPOSITORY": "Example/Project"})
    assert report["reasons"] == ["gate_fork_not_allowed"] and not calls


def test_file_count_limit_and_linked_source_block_without_dispatch(gate_case):
    change_policy(gate_case, max_files=1)
    (gate_case["repo"] / "src/extra.py").write_text("value = 1\n", encoding="utf-8")
    command(gate_case["repo"], "add", "src/extra.py")
    command(gate_case["repo"], "commit", "-m", "Synthetic second file")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_file_count_exceeded"] and not calls


def test_malformed_and_unbound_findings_are_blocked_without_raw_output(gate_case):
    report, calls = run(gate_case, lambda _: envelope("not a JSON document"))
    assert report["reasons"] == ["review_json_invalid"] and len(calls) == 1
    assert "not a JSON document" not in canonical(report).decode()

    def stale(packet):
        value = response(packet)
        value["findings"][0]["evidence"][0]["sha256"] = "a" * 64
        return envelope(json.dumps(value))

    report, calls = run(gate_case, stale)
    assert report["reasons"] == ["finding_evidence_invalid"] and len(calls) == 1


def test_daily_cap_honors_prior_settled_spend(gate_case):
    change_policy(gate_case, daily_budget_usd=1)
    with Ledger(gate_case["state"] / "audit.sqlite") as ledger:
        prior = ledger.reserve(Decimal("0.9999"), Decimal(1), Decimal(1))
        ledger.settle(prior, Decimal("0.9999"))
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["daily_budget_exceeded"]
    assert not calls


def test_failure_report_schema_and_injection_rejection(gate_case):
    from finassist.errors import AssistantError

    gate_case["pin"] = "0" * 64
    report, _ = run(gate_case)
    validate_model_report(report)
    report["reasons"] = ["bad\n::notice::text"]
    report["report_hash"] = digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
    with pytest.raises(AssistantError, match="gate_report_invalid"):
        validate_model_report(report)
