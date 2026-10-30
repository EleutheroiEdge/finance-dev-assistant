from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path

import httpx
import pytest

from finassist.cli import main
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.history_evaluation import evaluate_history
from finassist.history_scoring import validate_history_evaluation
from finassist.history_suite import history_approval_hash
from finassist.ledger import Ledger
from finassist.security import canonical
from test_history_suite import history_suite
from test_providers_review import envelope, response

pytest_plugins = ("test_model_gate", "test_model_policy")


def model_suite(case):
    return {"version": 1, "cases": [{"id": "held-out-case-marker", "repo_path": str(case["repo"]),
            "base_sha": case["base"], "head_sha": case["head"], "profile": "finance-saas",
            "expected": [{"label": "held-out-target-marker", "paths": ["src/cash.py"], "severity": "high"}],
            "negative_control": False, "policy": {"path": "gate-policy.json", "sha256": case["pin"]}}]}


def execute(case, suite, handler=None, *, trials=2):
    calls = []
    def transport(request):
        calls.append(request)
        text = request.content.decode()
        assert "held-out-target-marker" not in text and "held-out-case-marker" not in text
        assert str(case["repo"]) not in text and "negative_control" not in text
        packet = json.loads(json.loads(request.content)["input"])
        return httpx.Response(200, json=handler(packet) if handler else envelope(json.dumps(response(packet))))
    result = evaluate_history(suite, case["repo"].parent, Config(), case["state"], trials=trials,
                              approved_suite_hash=history_approval_hash(suite, trials), network_approved=True,
                              transport=httpx.MockTransport(transport))
    validate_history_evaluation(result)
    return result, calls


def test_repeated_trials_share_exact_policy_requests_and_one_ledger(gate_case):
    suite = model_suite(gate_case)
    result, calls = execute(gate_case, suite)
    assert len(calls) == 2
    runs = result["cases"][0]["runs"]
    assert all(run["status"] == "complete" for run in runs)
    assert all(run["elapsed_seconds"] >= 0 for run in runs)
    assert runs[0]["report"]["request_sha256"] == runs[1]["report"]["request_sha256"]
    assert all(run["report"]["policy_sha256"] == gate_case["pin"] for run in runs)
    assert json.loads(Path(result["journal"]).read_bytes()) == result
    with Ledger(gate_case["state"] / "audit.sqlite", read_only=True) as ledger:
        rows = ledger.db.execute("SELECT actual FROM reservations").fetchall()
        assert len(rows) == 2 and sum(Decimal(row[0]) for row in rows) == Decimal("0.0006")
        approval = next(item["payload"] for item in ledger.events()
                        if item["payload"]["event"] == "history_suite_approved")
        assert approval["suite_hash"] == result["suite_hash"] and approval["trials"] == 2
        assert approval["cases"][0]["request_sha256"] == runs[0]["report"]["request_sha256"]


def test_whole_suite_screening_precedes_all_network_calls(gate_case):
    suite = model_suite(gate_case)
    bad = deepcopy(suite["cases"][0])
    bad.update(id="second", policy={"path": "gate-policy.json", "sha256": "0" * 64})
    suite["cases"].append(bad)
    with pytest.raises(AssistantError, match="gate_policy_pin_mismatch"):
        execute(gate_case, suite)
    assert not gate_case["state"].exists()


def test_every_request_is_preflighted_before_the_first_dispatch(gate_case, monkeypatch):
    import finassist.history_evaluation as module
    suite = model_suite(gate_case)
    second = deepcopy(suite["cases"][0])
    second["id"] = "second-case"
    suite["cases"].append(second)
    original = module.prepare_model_request
    calls = []
    def preflight(policy, packet):
        calls.append(True)
        if len(calls) == 2:
            raise AssistantError("gate_request_bytes_exceeded")
        return original(policy, packet)
    monkeypatch.setattr(module, "prepare_model_request", preflight)
    monkeypatch.setattr(module, "model_gate", lambda *a, **k: pytest.fail("dispatch before complete preflight"))
    with pytest.raises(AssistantError, match="gate_request_bytes_exceeded"):
        execute(gate_case, suite)
    assert len(calls) == 2 and not gate_case["state"].exists()


def test_history_cannot_skip_the_gates_hosted_context_guard(gate_case, tmp_path, monkeypatch):
    event = {"action": "synchronize", "number": 1, "repository": {"full_name": "Example/Project"},
             "pull_request": {"number": 1,
                              "base": {"sha": gate_case["base"], "ref": "main",
                                       "repo": {"full_name": "Example/Project"}},
                              "head": {"sha": gate_case["head"], "repo": {"full_name": "Other/Project"}}}}
    path = tmp_path / "event.json"
    path.write_bytes(canonical(event))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_REPOSITORY", "Example/Project")
    monkeypatch.setattr("finassist.history_evaluation.prepare_model_request", lambda *a: pytest.fail("key access"))
    with pytest.raises(AssistantError, match="gate_fork_not_allowed"):
        execute(gate_case, model_suite(gate_case))
    assert not gate_case["state"].exists()


def test_approval_binds_trial_count_and_case_labels_before_state_or_network(gate_case):
    suite = model_suite(gate_case)
    approval = history_approval_hash(suite, 1)
    for trials in [2, 3]:
        with pytest.raises(AssistantError, match="eval_suite_approval_required"):
            evaluate_history(suite, gate_case["repo"].parent, Config(), gate_case["state"], trials=trials,
                             approved_suite_hash=approval, network_approved=True)
    changed = deepcopy(suite)
    changed["cases"][0]["expected"][0]["severity"] = "critical"
    with pytest.raises(AssistantError, match="eval_suite_approval_required"):
        evaluate_history(changed, gate_case["repo"].parent, Config(), gate_case["state"],
                         approved_suite_hash=approval, network_approved=True)
    assert not gate_case["state"].exists()


def test_unknown_attempt_stops_every_remaining_trial_and_case_without_retry(gate_case):
    suite = model_suite(gate_case)
    other = deepcopy(suite["cases"][0])
    other["id"] = "second-case"
    suite["cases"].append(other)
    def unknown(packet):
        value = envelope(json.dumps(response(packet)))
        value.pop("usage")
        return value
    result, calls = execute(gate_case, suite, unknown, trials=3)
    assert len(calls) == 1
    assert [run["status"] for case in result["cases"] for run in case["runs"]] == [
        "blocked", "not-run", "not-run", "not-run", "not-run", "not-run"]
    assert result["cases"][0]["runs"][0]["actual_usd"] is None
    with Ledger(gate_case["state"] / "audit.sqlite", read_only=True) as ledger:
        assert len(ledger.open_reservations()) == 1
    again, calls = execute(gate_case, suite)
    assert not calls and again["cases"][0]["runs"][0]["status"] == "blocked"


def test_journal_marks_inflight_attempt_before_dispatch(gate_case, monkeypatch):
    import finassist.history_evaluation as module
    def interrupted(*args, **kwargs):
        journal, = (gate_case["state"] / "history").glob("*.json")
        data = json.loads(journal.read_bytes())
        assert data["cases"][0]["runs"][0]["reason"] == "history_attempt_outcome_unknown"
        assert data["cases"][0]["runs"][1]["status"] == "not-run"
        raise KeyboardInterrupt
    monkeypatch.setattr(module, "model_gate", interrupted)
    with pytest.raises(KeyboardInterrupt):
        execute(gate_case, model_suite(gate_case))
    journal, = (gate_case["state"] / "history").glob("*.json")
    validate_history_evaluation(json.loads(journal.read_bytes()))


def test_offline_history_cli_is_deterministic_and_makes_no_reservations(repository, tmp_path, capsys):
    repo, _, _ = repository
    suite_file = repo.parent / "history.json"
    suite_file.write_bytes(canonical(history_suite(repository)))
    output = tmp_path / "evaluation.json"
    state = tmp_path / "no-network-state"
    assert main(["evaluate", "--history-suite", str(suite_file), "--trials", "2", "--state-dir", str(state),
                 "--output", str(output)]) == 0
    result = json.loads(output.read_bytes())
    validate_history_evaluation(result)
    assert result["mode"] == "offline"
    with Ledger(state / "audit.sqlite", read_only=True) as ledger:
        assert ledger.db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 0
    unused_state = tmp_path / "api-offline-state"
    assert result == evaluate_history(history_suite(repository), repo.parent, Config(), unused_state, trials=2)
    assert not unused_state.exists()
    assert "suite_hash" in capsys.readouterr().out
    labels = tmp_path / "labels.json"
    labels.write_bytes(canonical({"evaluation_hash": result["evaluation_hash"], "runs": []}))
    assert main(["score", "--evaluation", str(output), "--labels", str(labels),
                 "--output", str(tmp_path / "score.json")]) != 0


def test_existing_output_prevents_live_execution(gate_case, tmp_path, monkeypatch):
    suite_file = tmp_path / "suite.json"
    suite_file.write_bytes(canonical(model_suite(gate_case)))
    output = tmp_path / "existing.json"
    output.write_text("preserve\n")
    monkeypatch.setattr("finassist.history_evaluation.evaluate_history", lambda *a, **k: pytest.fail("dispatch reached"))
    assert main(["evaluate", "--history-suite", str(suite_file), "--allow-network", "--output", str(output)]) != 0
    assert output.read_text() == "preserve\n"
