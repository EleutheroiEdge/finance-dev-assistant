"""The Actions adapter cannot turn missing evidence, hostile text or setup failures green."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

from test_ci_gate import ci_case as _ci_case  # noqa: F401 - registered pytest fixture
from test_ci_gate import dispatch as _ci_dispatch  # noqa: F401 - registered pytest fixture
from test_ci_gate import base_policy
from finassist.errors import AssistantError
from finassist.github_actions import publish_action_report, run_github_action, summary_markdown
from finassist.security import canonical, digest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def action_case(request):
    return request.getfixturevalue("_ci_case")


@pytest.fixture
def action_dispatch(request):
    return request.getfixturevalue("_ci_dispatch")


def action_environment(case, tmp_path):
    event = deepcopy(case["event"])
    event["pull_request"]["base"]["sha"] = case["context"].base_sha
    event["pull_request"]["head"]["sha"] = case["context"].head_sha
    event_path = tmp_path / "event.json"
    event_path.write_bytes(canonical(event))
    root = tmp_path / "runner-temp"
    root.mkdir(exist_ok=True)
    return {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(case["repo"]),
            "GITHUB_EVENT_PATH": str(event_path), "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REPOSITORY": case["context"].repository, "RUNNER_TEMP": str(root),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"), "GITHUB_OUTPUT": str(tmp_path / "outputs"),
            "FINASSIST_CI_POLICY_SHA256": case["pin"]}


def test_actions_gate_publishes_only_reduced_metadata(action_case, action_dispatch, tmp_path, capsys):
    env = action_environment(action_case, tmp_path)
    assert run_github_action(env) == 0 and action_dispatch == ["unit", "cash"]
    stdout = capsys.readouterr().out
    summary = Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding='utf-8')
    outputs = Path(env["GITHUB_OUTPUT"]).read_text(encoding='utf-8')
    assert "**passed**" in summary and "status=passed" in outputs
    assert "No AI review" in summary
    assert "PRIVATE-SYNTHETIC" not in summary + outputs + stdout
    report_path = next(line.removeprefix("report-path=") for line in outputs.splitlines() if line.startswith("report-path="))
    report = json.loads(Path(report_path).read_text(encoding='utf-8'))
    assert report["status"] == "passed" and str(Path(report_path).parent).startswith(env["RUNNER_TEMP"])


def test_required_model_review_and_bad_context_never_report_success(action_case, action_dispatch, tmp_path, capsys):
    base_policy(action_case, lambda p: p.update(review="required"))
    env = action_environment(action_case, tmp_path)
    assert run_github_action(env) == 1 and not action_dispatch
    assert "ci_model_review_required" in Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding='utf-8')
    env["GITHUB_EVENT_NAME"] = "pull_request_target"
    assert run_github_action(env) == 2 and not action_dispatch
    assert "ci_event_not_allowed" in Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding='utf-8')
    assert "passed" not in capsys.readouterr().out


def test_action_paths_and_output_failures_are_closed_and_sanitized(action_case, action_dispatch, tmp_path, capsys):
    env = action_environment(action_case, tmp_path)
    env["FINASSIST_CI_REPOSITORY_PATH"] = ".."
    assert run_github_action(env) == 2 and not action_dispatch
    assert "ci_checkout_path_invalid" in Path(env["GITHUB_STEP_SUMMARY"]).read_text(encoding='utf-8')
    del env["RUNNER_TEMP"]
    assert run_github_action(env) == 2
    assert "Traceback" not in capsys.readouterr().out


def signed_report(**changes):
    value = {"schema_version": 1, "mode": "checks-only", "status": "error", "blocking_reasons": ["ci_test_refused"],
             "model_review": "not-run", **changes}
    value["report_hash"] = digest(canonical(value))
    return value


@pytest.mark.parametrize("changes", [
    {"blocking_reasons": ["ci_refused\n::notice::UNTRUSTED"]},
    {"status": "passed", "blocking_reasons": [], "model_review": "not-requested", "checks": {"required": 2, "completed": 1}},
    {"status": "passed", "blocking_reasons": [], "model_review": "not-requested"},
    {"status": "passed", "blocking_reasons": [], "model_review": "required-unavailable", "checks": {"required": 2, "completed": 2}},
    {"schema_version": True}, {"blocking_reasons": []},
])
def test_report_projection_refuses_injection_and_false_completion(changes, tmp_path):
    with pytest.raises(AssistantError, match="ci_report_invalid"):
        publish_action_report(signed_report(**changes), tmp_path / "report", tmp_path / "summary", tmp_path / "output")
    assert not (tmp_path / "summary").exists() and not (tmp_path / "output").exists()


def test_report_hash_and_output_path_are_checked_before_projection(tmp_path):
    report = signed_report()
    report["report_hash"] = "a" * 64
    with pytest.raises(AssistantError, match="ci_report_invalid"):
        summary_markdown(report)
    with pytest.raises(AssistantError, match="ci_output_path_invalid"):
        publish_action_report(signed_report(), tmp_path / "bad\nstatus=passed", tmp_path / "summary", tmp_path / "outputs")


def test_output_control_characters_are_refused_before_filesystem_access(tmp_path, monkeypatch):
    def forbidden_path_probe(_):
        pytest.fail("An invalid output path reached filesystem validation")

    monkeypatch.setattr("finassist.github_actions.regular_path", forbidden_path_probe)
    with pytest.raises(AssistantError, match="ci_output_path_invalid"):
        publish_action_report(signed_report(), tmp_path / "bad\nstatus=passed", tmp_path / "summary", tmp_path / "outputs")


def test_resolved_output_path_is_also_checked_before_projection(tmp_path, monkeypatch):
    monkeypatch.setattr("finassist.github_actions.regular_path", lambda _: tmp_path / "bad\nstatus=passed")
    with pytest.raises(AssistantError, match="ci_output_path_invalid"):
        publish_action_report(signed_report(), Path("relative-report"), tmp_path / "summary", tmp_path / "outputs")
    assert not (tmp_path / "summary").exists() and not (tmp_path / "outputs").exists()


def load_bootstrap():
    spec = importlib.util.spec_from_file_location("finassist_action_bootstrap", ROOT / "actions/gate/run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("worker_exit", [0, 1, 2])
def test_bootstrap_installs_only_trusted_action_source_and_preserves_worker_exit(tmp_path, monkeypatch, worker_exit):
    module = load_bootstrap()
    monkeypatch.setattr(module.sys, "platform", "linux")
    commands = []

    class EnvironmentBuilder:
        def __init__(self, **kwargs):
            assert kwargs == {"with_pip": True}

        def create(self, path):
            path.mkdir()

    def fake(command, **kwargs):
        commands.append((command, kwargs))
        return subprocess.CompletedProcess(command, worker_exit if len(commands) == 3 else 0)

    monkeypatch.setattr(module.venv, "EnvBuilder", EnvironmentBuilder)
    monkeypatch.setattr(module.subprocess, "run", fake)
    env = {"GITHUB_ACTIONS": "true", "RUNNER_TEMP": str(tmp_path), "PATH": "/trusted/tools",
           "PYTHONPATH": "/untrusted/pr", "OPENAI_API_KEY": "fictional"}
    assert module.bootstrap(env) == worker_exit
    first, second, third = commands
    assert "--require-hashes" in first[0] and "--isolated" in first[0]
    assert str(ROOT / "requirements-action.lock") in first[0]
    assert str(ROOT) == second[0][-1] and "--no-deps" in second[0]
    assert "PYTHONPATH" not in first[1]["env"] and "OPENAI_API_KEY" not in first[1]["env"]
    assert third[0][1:] == ["-I", "-m", "finassist.github_actions"]
    assert all(item[1]["shell"] is False and Path(item[1]["cwd"]).is_relative_to(tmp_path) for item in commands)


def test_bootstrap_setup_error_is_not_success_or_a_secret_log(tmp_path, monkeypatch, capsys):
    module = load_bootstrap()
    monkeypatch.setattr(module.sys, "platform", "linux")

    class UnavailableBuilder:
        def __init__(self, **_kwargs):
            pass

        def create(self, _path):
            raise OSError("PRIVATE-SYNTHETIC-SETUP-DETAIL")

    monkeypatch.setattr(module.venv, "EnvBuilder", UnavailableBuilder)
    assert module.bootstrap({"GITHUB_ACTIONS": "true", "RUNNER_TEMP": str(tmp_path)}) == 2
    assert "PRIVATE-SYNTHETIC" not in capsys.readouterr().err


def test_bootstrap_missing_runner_workspace_fails_without_traceback(tmp_path, monkeypatch, capsys):
    module = load_bootstrap()
    monkeypatch.setattr(module.sys, "platform", "linux")
    assert module.bootstrap({"GITHUB_ACTIONS": "true", "RUNNER_TEMP": str(tmp_path / "missing")}) == 2
    assert module.bootstrap({"GITHUB_ACTIONS": "true"}) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_action_manifest_keeps_inputs_out_of_shell_source():
    import yaml

    action = yaml.safe_load((ROOT / "actions/gate/action.yml").read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    for step in action["runs"]["steps"]:
        assert "${{" not in step["run"]
        assert step["env"]["FINASSIST_CI_POLICY_SHA256"] == "${{ inputs.policy-sha256 }}"


def test_action_lock_is_a_reviewed_runtime_build_subset():
    spec = importlib.util.spec_from_file_location("action_lock", ROOT / "scripts/action_lock.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert (ROOT / "requirements-action.lock").read_text(encoding='utf-8') == module.action_lock((ROOT / "requirements-dev.lock").read_text(encoding='utf-8'))
    assert "comrak==" not in (ROOT / "requirements-action.lock").read_text(encoding='utf-8')
