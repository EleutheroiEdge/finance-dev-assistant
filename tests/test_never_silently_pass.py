"""Work that did not complete is never a pass.

A check's own output is never read as its verdict; a killed, timed-out or contradictory check result does not pass
the checks-only gate; an empty, whitespace-only, empty-object or incomplete model reply, or an unexpected failure,
does not pass the model gate; CI credentials in the caller's environment reach neither a recipe container's command
line nor the container tool's environment; and the same gate input gives the same report bytes.
Synthetic Git, fake providers and fake container tools only.
"""

from dataclasses import replace
import json
import os
import signal
import subprocess
import sys

import pytest

from test_ci_gate import ci_case, gate  # noqa: F401 - fixture registration
from test_model_gate import gate_case, run  # noqa: F401 - fixture registration
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration
from test_providers_review import envelope, response
from finassist.config import Config
from finassist.model_gate import EXIT_CODES
from finassist.runner import run_bounded, run_recipe
from finassist.security import canonical, digest

CLAIMS = 'import json; print(json.dumps({"passed": True, "status": "success", "failures": 0}))'


def test_a_check_that_prints_success_and_exits_nonzero_does_not_pass(tmp_path):
    env = {"PATH": os.defpath, "HOME": str(tmp_path)}
    result = run_bounded([sys.executable, "-c", CLAIMS + "; raise SystemExit(1)"], cwd=tmp_path, env=env, timeout=5)
    assert result["exit_code"] == 1 and not result["passed"] and '"passed": true' in result["output"]
    # The reverse holds too: the exit code is the only signal, so printed failure text cannot fail a check.
    result = run_bounded([sys.executable, "-c", 'print("{\\"passed\\": false}")'], cwd=tmp_path, env=env, timeout=5)
    assert result["exit_code"] == 0 and result["passed"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
def test_a_check_killed_by_a_signal_does_not_pass(tmp_path):
    env = {"PATH": os.defpath, "HOME": str(tmp_path)}
    script = CLAIMS + "; import os, signal, sys; sys.stdout.flush(); os.kill(os.getpid(), signal.SIGKILL)"
    result = run_bounded([sys.executable, "-c", script], cwd=tmp_path, env=env, timeout=5)
    assert result["exit_code"] == -signal.SIGKILL and not result["passed"]


def _receipt_runner(calls, **receipt):
    def fake(config, name, _snapshot, *, backend, approve_local, repo=None, head=None):
        calls.append(name)
        output = '{"passed": true}'
        value = {"recipe": name, "argv_hash": digest(canonical(config.recipes[name])),
                 "runner_image": config.runner_image,
                 "isolation": "network-disabled read-only container; image must already be present",
                 "passed": True, "exit_code": 0, "cleanup_verified": True, "timed_out": False,
                 "output_limit_exceeded": False, "output_hash": digest(output.encode())}
        value.update(receipt)
        return {"output": output, "receipt": value}
    return fake


UNKNOWN = ["ci_check_outcome_unknown"]
FAILED = ["ci_checks_incomplete", "workflow_check_failed"]


@pytest.mark.parametrize("receipt,reasons", [
    ({"passed": True, "exit_code": 1}, UNKNOWN),                       # claims a pass the exit code denies
    ({"passed": True, "exit_code": 0, "timed_out": True}, UNKNOWN),     # timed out yet claims a pass
    ({"passed": True, "exit_code": 0, "output_limit_exceeded": True}, UNKNOWN),
    ({"passed": True, "exit_code": 0, "cleanup_verified": False}, UNKNOWN),
    ({"passed": False, "exit_code": -9}, FAILED),                      # killed by a signal
    ({"passed": False, "exit_code": 0, "timed_out": True}, FAILED),
], ids=["exit-1", "timed-out", "overflow", "cleanup-unverified", "killed", "timed-out-honest"])
def test_a_contradictory_or_incomplete_check_result_never_passes_the_ci_gate(ci_case, tmp_path, monkeypatch,  # noqa: F811
                                                                           receipt, reasons):
    # A receipt whose pass the exit code, timeout, output limit or cleanup contradicts is not believed: the
    # outcome is unknown. An honest failed receipt fails the check. Neither completes it.
    calls = []
    monkeypatch.setattr("finassist.workflow_execution.run_recipe", _receipt_runner(calls, **receipt))
    monkeypatch.setattr("socket.create_connection", lambda *_a, **_k: pytest.fail("no network in CI checks"))
    report = gate(ci_case, tmp_path)
    assert report["status"] == "blocked" and report["blocking_reasons"] == reasons and calls == ["unit"]
    assert report["checks"] == {"required": 2, "completed": 0}


@pytest.mark.parametrize("text,reasons", [
    ("", ["provider_empty_output", "unreconciled_model_usage"]),
    ("   \n\t ", ["provider_empty_output", "unreconciled_model_usage"]),
    ("{}", ["review_schema_invalid"]),
    ("[]", ["review_schema_invalid"]),
    ("null", ["review_schema_invalid"]),
], ids=["empty", "blank", "object", "list", "null"])
def test_an_empty_or_shapeless_reply_blocks_the_model_gate(gate_case, text, reasons):  # noqa: F811
    # An empty reply leaves its spend held as not reconciled, so the next run blocks before any request.
    report, calls = run(gate_case, lambda _packet: envelope(text))
    assert report["verdict"] == "BLOCKED" and EXIT_CODES[report["verdict"]] == 2 and len(calls) == 1
    assert report["reasons"] == reasons and report["findings"] == []


def test_a_reply_that_did_not_review_every_file_blocks_the_model_gate(gate_case):  # noqa: F811
    def partial(packet):
        value = response(packet)
        value["reviewed_paths"] = []
        return envelope(json.dumps(value))

    report, calls = run(gate_case, partial)
    assert report["verdict"] == "BLOCKED" and len(calls) == 1 and report["findings"] == []
    assert report["reasons"] == ["review_coverage_mismatch"]


def test_an_unexpected_failure_after_the_reply_blocks_without_its_text(gate_case, monkeypatch):  # noqa: F811
    def broken(_text):
        raise RuntimeError("PRIVATE-SYNTHETIC-FAILURE /home/someone/secret-path")

    monkeypatch.setattr("finassist.model_gate.reply_json", broken)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and EXIT_CODES["BLOCKED"] == 2 and len(calls) == 1
    assert report["reasons"] == ["gate_input_or_audit_unavailable"] and report["findings"] == []
    assert "PRIVATE-SYNTHETIC-FAILURE" not in canonical(report).decode()


# Built from the names, so no credential-shaped assignment sits in the source for the publication scan to flag.
CI_CREDENTIALS = {name: "fictional-" + name.lower().replace("_", "-") for name in (
    "GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN",
    "AWS_SECRET_ACCESS_KEY", "REVIEW_PROVIDER_KEY")}


def test_ci_credentials_reach_neither_the_container_nor_the_container_tool(tmp_path, monkeypatch):
    for name, value in CI_CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    seen = []
    monkeypatch.setattr("finassist.platform_support.locate_tool", lambda _: "/usr/bin/docker")

    def supervise(argv, **kwargs):
        seen.append((list(argv), dict(kwargs.get("env") or {})))
        return {"passed": True, "output": "fictional", "exit_code": 0}

    def tool(argv, **kwargs):
        seen.append((list(argv), dict(kwargs.get("env") or {})))
        return subprocess.CompletedProcess(argv, 1 if "inspect" in argv else 0, b"", b"")

    monkeypatch.setattr("finassist.runner.run_bounded", supervise)
    monkeypatch.setattr("finassist.runner.subprocess.run", tool)
    config = replace(Config(), runner_image="sha256:" + "a" * 64, recipes={"unit": ["python", "-V"]})
    assert run_recipe(config, "unit", tmp_path)["receipt"]["passed"]
    assert len(seen) >= 3  # the run, then removal and inspection
    for argv, env in seen:
        text = "\0".join(argv + [f"{k}={v}" for k, v in env.items()])
        for name, value in CI_CREDENTIALS.items():
            assert name not in text and value not in text


def test_the_same_gate_input_gives_the_same_report_bytes(gate_case, tmp_path):  # noqa: F811
    first, _ = run(gate_case)
    gate_case["state"] = tmp_path / "second-state"
    second, _ = run(gate_case)
    assert first["verdict"] == "PASS" and canonical(first) == canonical(second)
