"""Installation diagnostics use synthetic paths, environments and fake HTTP responses."""
from dataclasses import replace
import json

import pytest

from finassist.config import Config
from finassist.config_preflight import config_preflight
from finassist.onboarding import policy_preflight

from collections.abc import Mapping
import os
from types import SimpleNamespace
import httpx

from finassist import doctor_environment as diagnostic, providers, scope
from finassist.cli import main
from finassist.config import save_config
from finassist.errors import AssistantError, error_record
from finassist.error_hints import error_fields
from finassist.health import doctor_report
from finassist.security import canonical


pytest_plugins = ("test_model_gate", "test_model_policy")


def test_gate_preflight_empty_key_is_not_ready(gate_case, monkeypatch):
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "")
    report = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"],
                              "gate-policy.json", gate_case["pin"])
    assert "provider_key_missing" in [row["code"] for row in report["blockers"]]
    assert report["provider"]["key_state"] == "empty"
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "synthetic")
    cleared = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"],
                               "gate-policy.json", gate_case["pin"])
    assert "provider_key_missing" not in [row["code"] for row in cleared["blockers"]]


def test_config_preflight_empty_key_is_not_ready(repository):
    repo, base, head = repository
    config = replace(Config(), provider="openai", model="synthetic", allow_network=True,
                     api_key_env="SYNTHETIC_KEY", input_usd_per_million=1, output_usd_per_million=1)
    report = config_preflight(repo, base, head, config, environment={"SYNTHETIC_KEY": ""})
    assert "provider_key_missing" in [row["code"] for row in report["blockers"]]
    assert report["provider"]["key_state"] == "empty"
    cleared = config_preflight(repo, base, head, config, environment={"SYNTHETIC_KEY": "synthetic"})
    assert "provider_key_missing" not in [row["code"] for row in cleared["blockers"]]



@pytest.fixture
def local_environment(tmp_path, monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy",
                 "all_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(diagnostic, "user_directory", lambda kind: tmp_path / kind)
    monkeypatch.setattr(diagnostic, "git_status", lambda: {"blockers": [], "warnings": []})
    return tmp_path


def test_missing_git_clears_after_path_remedy(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    assert diagnostic.git_status()["blockers"][0]["code"] == "git_executable_missing"
    monkeypatch.setattr(diagnostic, "find_tool", lambda _: str(tmp_path / "git"))
    monkeypatch.setattr(diagnostic.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=b"git version 2.48.1.windows.1\n"))
    monkeypatch.setattr(scope, "_supports_no_lazy_fetch", lambda _: True)
    report = diagnostic.git_status()
    assert report["version"] == "2.48.1" and not report["blockers"] and not report["warnings"]


def test_old_git_names_feature_floors_and_upgrade_clears_them(monkeypatch):
    monkeypatch.setattr(diagnostic, "find_tool", lambda _: "/synthetic/git")
    output = [b"git version 2.27.0\n"]
    monkeypatch.setattr(diagnostic.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=output[0]))
    monkeypatch.setattr(scope, "_supports_no_lazy_fetch", lambda _: False)
    report = diagnostic.git_status()
    assert {row["feature"] for row in report["warnings"]} == {"init_initial_branch", "attributes_at_revision"}
    assert all(row["hint"] for row in report["warnings"])
    assert report["features"][-1]["fallback"] == "Full clones only; partial clones are refused."
    output[0] = b"git version 2.45.0\n"
    assert not diagnostic.git_status()["warnings"]


@pytest.mark.parametrize("output", [b"secret response\n", b"git version 2.45.0\nsecret\n", b"git version 2." + b"4" * 5000])
def test_git_version_failure_never_echoes_process_output(monkeypatch, output):
    monkeypatch.setattr(diagnostic, "find_tool", lambda _: "/synthetic/git")
    monkeypatch.setattr(diagnostic.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=output))
    report = diagnostic.git_status()
    assert report["blockers"][0]["code"] == "git_capability_check_failed"
    assert "secret" not in json.dumps(report) and report["version"] is None


def test_state_writability_is_nonmutating_and_remedy_clears_blocker(local_environment, monkeypatch):
    target = local_environment / "state" / "not-created"
    original = os.access
    monkeypatch.setattr(diagnostic.os, "access", lambda *a, **kw: False)
    report = diagnostic.environment_report(Config(), state_dir=target)
    assert any(row["path_role"] == "state" for row in report["blockers"])
    assert not target.exists() and report["paths"]["state"]["path"] == str(target)
    monkeypatch.setattr(diagnostic.os, "access", original)
    report = diagnostic.environment_report(Config(), state_dir=target)
    assert not report["blockers"] and not target.parent.exists()
    target.parent.mkdir()
    target.write_text("a file is not a directory")
    assert diagnostic.directory_status(target)["code"] == "doctor_directory_unusable"


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits; Windows ACL estimate tested through access")
def test_read_only_directory_and_symlink_are_refused(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir()
    directory.chmod(0o500)
    try:
        assert not diagnostic.directory_status(directory)["writable"]
    finally:
        directory.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(directory, target_is_directory=True)
    assert diagnostic.directory_status(link)["code"] == "doctor_directory_unusable"


class OnlyKey(Mapping):
    def __iter__(self):
        return iter(["SYNTHETIC_KEY", "HTTP_PROXY", "SSL_CERT_FILE", "UNRELATED"])
    def __len__(self):
        return 4
    def __getitem__(self, key):
        assert key == "SYNTHETIC_KEY"
        return "never-output-this-value"


def test_environment_reads_only_selected_key_and_not_proxy_ca_or_other_values(local_environment):
    config = replace(Config(), provider="openai", model="synthetic", api_key_env="SYNTHETIC_KEY")
    report = diagnostic.environment_report(config, environment=OnlyKey())
    encoded = json.dumps(report)
    assert "never-output" not in encoded and not report["network_used"] and not report["key_values_returned"]
    assert report["proxy_variables_seen"] == ["HTTP_PROXY"]
    assert report["custom_ca_variables_seen"] == ["SSL_CERT_FILE"]
    assert {row["code"] for row in report["warnings"]} == {"provider_proxy_not_used", "provider_custom_ca_not_used"}
    cleared = diagnostic.environment_report(config, environment={"SYNTHETIC_KEY": "synthetic"})
    assert not cleared["warnings"]


@pytest.mark.parametrize("value,state", [(None, "missing"), ("", "empty"), ("synthetic", "set")])
def test_key_states_and_nonempty_remedy(local_environment, value, state):
    config = replace(Config(), provider="openai", model="synthetic", api_key_env="SYNTHETIC_KEY")
    environment = {} if value is None else {"SYNTHETIC_KEY": value}
    report = diagnostic.environment_report(config, environment=environment)
    assert report["keys"][0]["state"] == state
    assert bool(report["blockers"]) == (state != "set")
    assert not diagnostic.environment_report(config, environment={"SYNTHETIC_KEY": "remedied"})["blockers"]


def test_shared_key_keeps_distinct_hosts_models_limits_and_permissions(local_environment):
    config = replace(Config(), provider="openai", model="review-model", api_key_env="SHARED_KEY",
                     max_run_usd=2, monthly_budget_usd=9, allow_network=False)
    gate = replace(config, provider="compatible", model="gate-model", endpoint="https://gate.example/v1",
                   allowed_hosts=("gate.example",), allow_network=True, max_run_usd=7, monthly_budget_usd=1_000_000)
    model = {"max_request_bytes": 54321, "max_run_usd": 7, "daily_budget_usd": 11}
    report = diagnostic.environment_report(config, gate_config=gate, gate_model=model,
                                           policy={"source": "working-tree"}, environment={"SHARED_KEY": "synthetic"})
    assert len(report["keys"]) == 1
    row = report["keys"][0]
    assert row["used_by"] == ["evaluate", "gate run", "propose", "review"] and len(row["uses"]) == 2
    first, second = row["uses"]
    assert (first["host"], second["host"]) == ("api.openai.com", "gate.example")
    assert first["model"] == "review-model" and second["model"] == "gate-model"
    assert first["limits"]["monthly_budget_usd"] == 9 and second["limits"]["monthly_budget_usd"] == 1_000_000
    assert first["limits"]["max_run_usd"] == 2 and second["limits"]["max_run_usd"] == 7
    assert not first["network_enabled"] and second["network_enabled"]
    assert second["policy"]["source"] == "working-tree"
    assert second["limits"]["monthly_budget_source"].startswith("Fixed gate adapter guard")
    assert not second["authorization_granted"]


def test_default_key_custom_host_warning_and_dedicated_key_remedy(local_environment):
    config = replace(Config(), provider="compatible", model="synthetic", api_key_env="OPENAI_API_KEY",
                     endpoint="https://other.example/v1", allowed_hosts=("other.example",))
    report = diagnostic.environment_report(config, environment={"OPENAI_API_KEY": "synthetic"})
    assert report["warnings"][0]["code"] == "provider_key_host_mismatch"
    assert not diagnostic.environment_report(replace(config, api_key_env="OTHER_KEY"),
                                              environment={"OTHER_KEY": "synthetic"})["warnings"]


def test_cli_combined_config_and_policy_is_diagnostic_only(gate_case, tmp_path, capsys, local_environment):
    config = replace(Config(), provider="openai", model="configuration-model", api_key_env="REVIEW_PROVIDER_KEY")
    path = tmp_path / "finassist.json"
    save_config(path, config)
    code = main(["--config", str(path), "doctor", "--repo", str(gate_case["repo"]), "--base", gate_case["base"],
                 "--head", gate_case["head"], "--policy", "gate-policy.json", "--policy-sha256", gate_case["pin"]])
    report = json.loads(capsys.readouterr().out)
    assert code == 0 and report["status"] == "ready"  # config's network=false does not override the policy
    assert len(report["environment"]["keys"]) == 1 and len(report["environment"]["keys"][0]["uses"]) == 2
    assert report["policy"]["sha256"] == gate_case["pin"]
    assert report["environment"]["paths"]["configuration"]["path"] == str(path)
    assert report["environment"]["paths"]["state"]["path"] is None
    gate_use = next(use for use in report["environment"]["keys"][0]["uses"] if use["source"] == "gate policy")
    assert gate_use["limits"]["monthly_budget_usd"] == 1_000_000
    assert not gate_use["authorization_granted"]


def test_plain_doctor_environment_is_cli_only(local_environment, capsys, monkeypatch):
    monkeypatch.chdir(local_environment)
    assert "environment" not in doctor_report(Config())
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["environment"]["paths"]["state"]["path"] == str(local_environment / ".finassist")
    assert not (local_environment / ".finassist").exists()


@pytest.mark.parametrize("status,code", [(401, "provider_http_unauthorized"), (403, "provider_http_forbidden"),
                                         (404, "provider_http_not_found"), (429, "provider_http_rate_limited"),
                                         (500, "provider_http_error"), (307, "provider_http_error")])
def test_http_status_has_hint_and_never_response_body_or_retry(monkeypatch, status, code):
    monkeypatch.setenv("SYNTHETIC_KEY", "never-output-this-key")
    config = replace(Config(), provider="openai", model="synthetic", api_key_env="SYNTHETIC_KEY", allow_network=True)
    calls = []
    def transport(request):
        calls.append(request)
        return httpx.Response(status, text="never-output-response", headers={"Location": "https://other.example"})
    with pytest.raises(AssistantError) as caught:
        providers.invoke(config, "synthetic instructions", {}, {}, network_approved=True,
                         transport=httpx.MockTransport(transport))
    assert caught.value.code == code and caught.value.public_details == {"http_status": status}
    record = error_record(caught.value, "review", error_fields(code))
    assert record["hint"] and len(calls) == 1
    assert "never-output" not in canonical(record).decode()


@pytest.mark.parametrize("character", ["\u2028", "\ufeff", "\ue000"])
def test_local_environment_paths_redact_hidden_display_characters(character):
    assert diagnostic._shown_path("/synthetic/" + character + "name") == "[redacted]"
