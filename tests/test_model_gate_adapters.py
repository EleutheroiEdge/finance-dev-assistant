"""The CLI and Action share one model gate and never print raw provider claims."""

from functools import partial
import json
from pathlib import Path

import httpx
import pytest

from conftest import command
from test_model_gate import change_policy, gate_case as _gate_case  # noqa: F401 - fixture registration
from test_model_policy import policy_case  # noqa: F401 - fixture registration
from test_providers_review import envelope, response
from finassist.cli import main
from finassist.github_actions import run_github_action
from finassist.model_gate import model_gate
from finassist.security import canonical


@pytest.fixture
def gate_case(request):
    return request.getfixturevalue("_gate_case")


def fake_model(request):
    packet = json.loads(json.loads(request.content)["input"])
    data = response(packet)
    data["findings"][0]["claim"] = "MODEL-CLAIM-PRIVATE ::notice::fictional"
    return httpx.Response(200, json=envelope(json.dumps(data)))


@pytest.mark.parametrize("block_severity,exit_code,verdict", [(False, 0, "PASS"), (True, 1, "FAIL")])
def test_cli_real_core_exit_contract(gate_case, tmp_path, monkeypatch, capsys, block_severity, exit_code, verdict):
    if block_severity:
        change_policy(gate_case, blocking_severities=["high"])
    monkeypatch.setattr("finassist.model_gate.model_gate", partial(model_gate, transport=httpx.MockTransport(fake_model)))
    output = tmp_path / "report.json"
    code = main(["gate", "run", "--repo", str(gate_case["repo"]), "--base", gate_case["base"],
                 "--head", gate_case["head"], "--policy", "gate-policy.json", "--policy-sha256", gate_case["pin"],
                 "--state-dir", str(gate_case["state"]), "--output", str(output)])
    assert code == exit_code
    result = capsys.readouterr()
    assert json.loads(result.out)["verdict"] == verdict
    assert json.loads(output.read_text(encoding="utf-8"))["verdict"] == verdict
    assert "MODEL-CLAIM-PRIVATE" not in result.out + result.err


def test_cli_blocked_and_existing_output_do_not_dispatch(gate_case, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    output = tmp_path / "report.json"
    args = ["gate", "run", "--repo", str(gate_case["repo"]), "--base", gate_case["base"], "--head", gate_case["head"],
            "--policy", "gate-policy.json", "--policy-sha256", gate_case["pin"],
            "--state-dir", str(gate_case["state"]), "--output", str(output)]
    assert main(args) == 2
    assert json.loads(capsys.readouterr().out)["verdict"] == "BLOCKED"
    first = output.read_bytes()
    assert main(args) == 2 and json.loads(capsys.readouterr().err)["code"] == "output_exists"
    assert output.read_bytes() == first


def environment(case, tmp_path, *, fork=False):
    command(case["repo"], "remote", "add", "origin", "https://github.com/example/project.git")
    event = {"action": "synchronize", "number": 1, "repository": {"full_name": "example/project"},
             "pull_request": {"number": 1, "base": {"ref": "main", "sha": case["base"], "repo": {"full_name": "example/project"}},
                              "head": {"sha": case["head"], "repo": {"full_name": "other/project" if fork else "example/project"}}}}
    path = tmp_path / "event.json"
    path.write_bytes(canonical(event))
    return {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(case["repo"]), "GITHUB_EVENT_PATH": str(path),
            "GITHUB_EVENT_NAME": "pull_request", "GITHUB_REPOSITORY": "example/project", "RUNNER_TEMP": str(tmp_path / "runner"),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"), "GITHUB_OUTPUT": str(tmp_path / "outputs"),
            "FINASSIST_CI_POLICY_PATH": "gate-policy.json", "FINASSIST_CI_POLICY_SHA256": case["pin"],
            "FINASSIST_CI_STATE_DIRECTORY": str(case["state"]), "FINASSIST_CI_MODE": "model-review"}


def test_action_reuses_core_and_projects_metadata_only(gate_case, tmp_path, monkeypatch, capsys):
    env = environment(gate_case, tmp_path)
    monkeypatch.setattr("finassist.model_gate.model_gate", partial(model_gate, transport=httpx.MockTransport(fake_model)))
    assert run_github_action(env) == 0
    summary = Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")
    outputs = Path(env["GITHUB_OUTPUT"]).read_text(encoding="utf-8")
    assert "**PASS**" in summary and "status=PASS" in outputs
    assert "MODEL-CLAIM-PRIVATE" not in summary + outputs + capsys.readouterr().out


@pytest.mark.parametrize("fork,missing_state,reason", [(True, False, "gate_fork_not_allowed"),
                                                       (False, True, "gate_state_directory_required")])
def test_action_cannot_supply_key_to_fork_or_create_fresh_implicit_state(gate_case, tmp_path, monkeypatch, capsys,
                                                                      fork, missing_state, reason):
    env = environment(gate_case, tmp_path, fork=fork)
    if missing_state:
        env.pop("FINASSIST_CI_STATE_DIRECTORY")
    monkeypatch.setattr("finassist.providers.request_shape", lambda *_: pytest.fail("key read reached"))
    assert run_github_action(env) == 2
    assert reason in Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")
    assert "BLOCKED" in capsys.readouterr().out


@pytest.mark.parametrize("changes,reason", [
    ({"GITHUB_EVENT_NAME": "pull_request_target"}, "ci_event_not_allowed"),
    ({"FINASSIST_CI_REPOSITORY_PATH": ".."}, "ci_checkout_path_invalid"),
    ({"FINASSIST_CI_MODE": "unsupported"}, "ci_action_mode_invalid"),
])
def test_action_preflight_refusals_keep_blocked_report_contract(gate_case, tmp_path, capsys, changes, reason):
    env = environment(gate_case, tmp_path)
    env.update(changes)
    assert run_github_action(env) == 2
    summary = Path(env["GITHUB_STEP_SUMMARY"])
    outputs = Path(env["GITHUB_OUTPUT"])
    assert summary.exists() and outputs.exists()
    assert reason in summary.read_text(encoding="utf-8")
    values = dict(line.split("=", 1) for line in outputs.read_text(encoding="utf-8").splitlines())
    report = json.loads(Path(values["report-path"]).read_text(encoding="utf-8"))
    assert values["status"] == report["verdict"] == "BLOCKED" and report["reasons"] == [reason]
    assert "ci_action_output_unavailable" not in capsys.readouterr().out


@pytest.mark.parametrize("location", ["relative", "runner", "repository"])
def test_action_rejects_implicit_or_candidate_managed_ledgers(gate_case, tmp_path, monkeypatch, capsys, location):
    env = environment(gate_case, tmp_path)
    paths = {"relative": "retained-state", "runner": str(tmp_path / "runner/retained-state"),
             "repository": str(gate_case["repo"] / ".finassist/retained-state")}
    env["FINASSIST_CI_STATE_DIRECTORY"] = paths[location]
    bootstrap_cwd = tmp_path / "bootstrap-cwd"
    bootstrap_cwd.mkdir()
    monkeypatch.chdir(bootstrap_cwd)
    monkeypatch.setattr("finassist.model_gate.model_gate", partial(model_gate, transport=httpx.MockTransport(fake_model)))
    assert run_github_action(env) == 2
    assert "gate_state_directory_not_retained" in Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding="utf-8")
    assert not (Path(paths[location]) / "audit.sqlite").exists()
    capsys.readouterr()
