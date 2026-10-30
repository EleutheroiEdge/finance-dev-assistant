from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path

import httpx
import pytest

from conftest import command
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
from test_model_policy import model_policy

pytest_plugins = ("test_model_gate", "test_model_policy")


def model_suite(case):
    return {"version": 1, "cases": [{"id": "held-out-case-marker", "repo_path": str(case["repo"]),
            "base_sha": case["base"], "head_sha": case["head"], "profile": "finance-saas",
            "expected": [{"label": "held-out-target-marker", "paths": ["src/cash.py"], "severity": "high"}],
            "negative_control": False, "policy": {"path": "gate-policy.json", "sha256": case["pin"]}}]}


def policy_repository(tmp_path, *, name="policies", document=None, ignore=None):
    from finassist.security import digest
    repo = tmp_path / name
    repo.mkdir()
    command(repo, "init", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Policy Maintainer")
    command(repo, "config", "user.email", "policy@example.invalid")
    raw = canonical(document if document is not None else model_policy()) + b"\n"
    (repo / "gate-policy.json").write_bytes(raw)
    command(repo, "add", "gate-policy.json")
    if ignore is not None:
        (repo / ".gitignore").write_text(ignore, encoding="utf-8")
        command(repo, "add", ".gitignore")
    command(repo, "commit", "-m", "Synthetic reviewed benchmark policy")
    return {"repo_path": name, "commit": command(repo, "rev-parse", "HEAD"),
            "path": "gate-policy.json", "sha256": digest(raw)}


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
    assert runs[0]["request_sha256"] == runs[1]["request_sha256"]
    assert all(run["policy_sha256"] == gate_case["pin"] for run in runs)
    for run in runs:
        assert "report" not in run
        report = json.loads((Path(result["journal"]).parent / run["report_file"]).read_bytes())
        assert report["report_hash"] == run["report_hash"]
        assert report["request_sha256"] == run["request_sha256"]
    assert result["cases"][0]["reviewer"]["model"] == "operator-selected"
    assert json.loads(Path(result["journal"]).read_bytes()) == result
    with Ledger(gate_case["state"] / "audit.sqlite", read_only=True) as ledger:
        rows = ledger.db.execute("SELECT actual FROM reservations").fetchall()
        assert len(rows) == 2 and sum(Decimal(row[0]) for row in rows) == Decimal("0.0006")
        approval = next(item["payload"] for item in ledger.events()
                        if item["payload"]["event"] == "history_suite_approved")
        assert approval["suite_hash"] == result["suite_hash"] and approval["trials"] == 2
        assert approval["cases"][0]["request_sha256"] == runs[0]["request_sha256"]


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
    monkeypatch.setattr(module, "run_history_gate", lambda *a, **k: pytest.fail("dispatch before complete preflight"))
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
    with pytest.raises(AssistantError, match="history_ci_execution_forbidden"):
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
    monkeypatch.setattr(module, "run_history_gate", interrupted)
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


def test_large_valid_history_evaluation_can_be_scored_by_the_cli(tmp_path):
    # One hundred trials with fifty findings and long safe paths exceed the old 2MB
    # input limit. This is a valid bounded external envelope, not model output.
    from finassist.security import digest
    path = "src/" + "long-path-component/" * 20 + "cash.py"
    cases, judgments = [], []
    for index in range(5):
        case_id = f"case-{index}"
        runs = []
        for trial in range(1, 21):
            findings = [{"id": f"finding-{number}", "path": path, "severity": "high"} for number in range(50)]
            runs.append({"trial": trial, "status": "complete", "findings": findings,
                         "actual_usd": None, "elapsed_seconds": None})
            judgments.append({"case_id": case_id, "trial": trial, "findings": {
                item["id"]: {"outcome": "false-alarm", "label": None} for item in findings}})
        cases.append({"id": case_id, "base_sha": "1" * 40, "head_sha": "2" * 40,
                      "source_hash": "a" * 64, "negative_control": True,
                      "expected": [], "runs": runs})
    data = {"schema_version": 2, "kind": "history-evaluation", "mode": "external", "trials": 20,
            "suite_hash": "b" * 64, "cases": cases}
    data["evaluation_hash"] = digest(canonical(data))
    evaluation_file, labels_file, output = tmp_path / "large.json", tmp_path / "labels.json", tmp_path / "score.json"
    evaluation_file.write_bytes(canonical(data))
    labels_file.write_bytes(canonical({"evaluation_hash": data["evaluation_hash"], "runs": judgments}))
    assert evaluation_file.stat().st_size > 2_000_000
    assert main(["score", "--evaluation", str(evaluation_file), "--labels", str(labels_file),
                 "--output", str(output)]) == 0
    result = json.loads(output.read_bytes())
    assert result["complete"] and result["negative_control_false_alarm_rate"] == 1


def test_extreme_planned_results_refuse_before_dispatch_instead_of_becoming_unscoreable():
    from finassist.history_evaluation import check_result_capacity
    # Unicode path encoding is much wider than character count. Fifty cases
    # times20 trials times50 returned findings would exceed the64MB score bound.
    prepared = [{"packet": {"files": [{"path": "src/" + ("\U0001f600" * 40 + "/") * 10 + "cash.py"}]}}] * 50
    with pytest.raises(AssistantError, match="history_evaluation_size_exceeded"):
        check_result_capacity({}, prepared, 20)


@pytest.mark.parametrize("mutation", ["wrong-pin", "missing-commit", "non-repository", "profile"])
def test_separate_policy_repository_refusals_happen_before_network(gate_case, tmp_path, monkeypatch, mutation):
    import finassist.scope as scope
    suite = model_suite(gate_case)
    selection = policy_repository(tmp_path)
    suite["cases"][0]["policy"] = selection
    if mutation == "wrong-pin":
        selection["sha256"] = "0" * 64
    elif mutation == "missing-commit":
        selection["commit"] = "1" * 40
    elif mutation == "non-repository":
        (tmp_path / "not-a-repo").mkdir()
        selection["repo_path"] = "not-a-repo"
    else:
        suite["cases"][0]["profile"] = "quant-review"
    original = scope.git_command
    def no_fetch(*args, **kwargs):
        assert not {"fetch", "pull", "checkout", "switch"} & set(map(str, args))
        return original(*args, **kwargs)
    monkeypatch.setattr(scope, "git_command", no_fetch)
    monkeypatch.setattr("finassist.history_evaluation.prepare_model_request", lambda *a: pytest.fail("key/network reached"))
    with pytest.raises(AssistantError):
        execute(gate_case, suite, trials=1)
    assert not gate_case["state"].exists()


def test_policy_commit_ignore_rule_survives_dirty_removal(gate_case, tmp_path):
    suite = model_suite(gate_case)
    suite["cases"][0]["policy"] = policy_repository(tmp_path, ignore="src/cash.py\n")
    (tmp_path / "policies/.gitignore").write_text("", encoding="utf-8")
    with pytest.raises(AssistantError, match="gate_ignored_path"):
        execute(gate_case, suite, trials=1)
    assert not gate_case["state"].exists()


def test_two_policy_selections_compare_same_source_without_granting_ci_override(gate_case, tmp_path):
    from finassist.history_scoring import compare_history
    from finassist.model_gate import model_gate
    first_suite = model_suite(gate_case)
    first_suite["cases"][0]["policy"] = policy_repository(tmp_path)
    first, first_calls = execute(gate_case, first_suite, trials=1)
    second_document = model_policy()
    second_document["model_review"].update(model="second-selected", profile="quant-review")
    second_suite = deepcopy(first_suite)
    second_suite["cases"][0].update(profile="quant-review", policy=policy_repository(
        tmp_path, name="second-policies", document=second_document))
    second, second_calls = execute(gate_case, second_suite, trials=1)
    assert len(first_calls) == len(second_calls) == 1
    assert first["suite_hash"] != second["suite_hash"]
    assert first["cases"][0]["source_hash"] == second["cases"][0]["source_hash"]
    assert first["cases"][0]["reviewer"]["model"] != second["cases"][0]["reviewer"]["model"]
    assert first["cases"][0]["runs"][0]["request_sha256"] != second["cases"][0]["runs"][0]["request_sha256"]
    def labels(evaluation):
        return {"evaluation_hash": evaluation["evaluation_hash"], "runs": [{
            "case_id": evaluation["cases"][0]["id"], "trial": 1, "findings": {
                finding["id"]: {"outcome": "confirmed-hit", "label": "held-out-target-marker"}
                for finding in evaluation["cases"][0]["runs"][0]["findings"]}}]}
    result = compare_history(first, labels(first), second, labels(second))
    assert result["overlap"][0]["both"] == ["held-out-target-marker"]
    # The ordinary gate still reads only the source-base policy. A benchmark's
    # separate pin cannot substitute for those source-base bytes.
    report = model_gate(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                        second_suite["cases"][0]["policy"]["sha256"], gate_case["state"],
                        transport=httpx.MockTransport(lambda _: pytest.fail("ordinary gate dispatched")))
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["gate_policy_pin_mismatch"]


def test_offline_policy_inspection_never_reads_the_provider_key(gate_case, tmp_path, monkeypatch):
    suite = model_suite(gate_case)
    suite["cases"][0]["policy"] = policy_repository(tmp_path)
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    result = evaluate_history(suite, tmp_path, Config(), gate_case["state"])
    assert result["mode"] == "offline" and not gate_case["state"].exists()
    suite["cases"][0]["policy"]["sha256"] = "0" * 64
    with pytest.raises(AssistantError, match="gate_policy_pin_mismatch"):
        evaluate_history(suite, tmp_path, Config(), gate_case["state"])


@pytest.mark.parametrize("network", [False, True])
def test_source_repository_must_name_its_root_before_key_or_network(gate_case, tmp_path, monkeypatch, network):
    suite = model_suite(gate_case)
    suite["cases"][0]["repo_path"] = str(gate_case["repo"] / "src")
    monkeypatch.setattr("finassist.history_evaluation.prepare_model_request", lambda *a: pytest.fail("key/network"))
    with pytest.raises(AssistantError, match="history_repository_root_required"):
        evaluate_history(suite, tmp_path, Config(), gate_case["state"],
                         approved_suite_hash=history_approval_hash(suite), network_approved=network)
    assert not gate_case["state"].exists()
