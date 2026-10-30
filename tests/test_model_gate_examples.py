"""Portable examples preserve key isolation and match the installed exports."""

import importlib.util
import json
from pathlib import Path
import subprocess

from finassist.integrations import export_kit

ROOT = Path(__file__).resolve().parents[1]


def caller():
    spec = importlib.util.spec_from_file_location("synthetic_gate_caller", ROOT / "examples/model-gate/caller.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exported_policy_schema_and_caller_match_reviewed_source(tmp_path):
    export_kit(tmp_path / "kit")
    for name in ("examples/model-gate/policy.json", "examples/model-gate/caller.py", "schemas/model-gate-report.schema.json"):
        assert (tmp_path / "kit" / name).read_bytes() == (ROOT / name).read_bytes()
    assert json.loads((tmp_path / "kit/examples/model-gate/policy.json").read_text(encoding="utf-8"))["model_review"]["blocking_severities"] == []


def test_caller_passes_only_named_key_in_child_env_never_argv(monkeypatch):
    module = caller()
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "fictional-wrapper-value")
    monkeypatch.setenv("UNRELATED_PRIVATE_VARIABLE", "fictional-unrelated")
    monkeypatch.setattr(module.sys, "argv", ["caller.py", "--policy", "gate-policy.json"])
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(module.subprocess, "run", run)
    assert module.main() == 0
    argv, kwargs = calls[0]
    assert "fictional-wrapper-value" not in str(argv)
    assert kwargs["env"]["REVIEW_PROVIDER_KEY"] == "fictional-wrapper-value"
    assert "UNRELATED_PRIVATE_VARIABLE" not in kwargs["env"]
    assert kwargs["shell"] is False and "-I" in argv


def test_caller_refuses_actions_instead_of_removing_event_identity(monkeypatch, capsys):
    module = caller()
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(module.subprocess, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected child")))
    assert module.main() == 2
    assert "Action adapter" in capsys.readouterr().err
