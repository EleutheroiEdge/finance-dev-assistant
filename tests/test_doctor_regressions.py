"""Review regressions: synthetic metadata, isolated Git and fake provider IO only."""

from dataclasses import replace
import json
from pathlib import Path
import socket
import sys

import httpx
import pytest

from finassist import __version__, doctor_environment as diagnostic, doctor_package, providers
from finassist.cli import main
from finassist.config import Config, save_config
from finassist.error_hints import error_fields
from finassist.errors import AssistantError, error_record
from finassist.model_gate import model_gate, validate_model_report
from finassist.security import canonical, digest

pytest_plugins = ("test_model_gate", "test_model_policy")


def test_missing_drive_root_terminates_without_parent_progress(monkeypatch):
    class MissingRoot:
        parent = property(lambda self: self)
        def exists(self):
            return False
        def __str__(self):
            return "Z:/"
    monkeypatch.setattr(diagnostic, "regular_path", lambda _path: MissingRoot())
    report = diagnostic.directory_status(Path("synthetic"))
    assert report["code"] == "doctor_directory_unusable"


def test_home_expansion_failure_is_diagnostic(tmp_path, monkeypatch, capsys):
    # POSIX looks up named users; Windows constructs a sibling home path. Inject the
    # expansion failure so both hosts exercise the diagnostic, not that OS difference.
    target = "~finassist-no-such-user-987654321/state"
    expanduser = Path.expanduser

    def refused_home(path):
        if path == Path(target):
            raise RuntimeError("synthetic home lookup failure")
        return expanduser(path)

    monkeypatch.setattr(Path, "expanduser", refused_home)
    monkeypatch.chdir(tmp_path)
    assert main(["doctor", "--state-dir", target]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["environment"]["paths"]["state"]["code"] == "doctor_directory_unusable"
    assert not report["environment"]["blockers"]


def test_windows_writability_is_unknown(tmp_path, monkeypatch):
    def unexpected(*_args):
        raise AssertionError("Windows writability must not claim an os.access ACL check")
    monkeypatch.setattr(diagnostic.os, "access", unexpected)
    assert diagnostic.directory_status(tmp_path, windows=True)["writable"] is None


def test_git_batch_shim_retains_its_code(monkeypatch):
    def refused(_name):
        raise AssistantError("batch_tool_not_supported")
    monkeypatch.setattr(diagnostic, "find_tool", refused)
    report = diagnostic.git_status()
    assert report["blockers"] == [{"code": "batch_tool_not_supported", **error_fields("batch_tool_not_supported")}]


def test_git_feature_shape_is_uniform():
    report = diagnostic.git_status()
    assert report["features"]
    assert all(set(row) == {"name", "minimum_version", "available", "check", "used_by", "fallback"}
               for row in report["features"])


@pytest.mark.parametrize("value,exists,state", [(None, False, "missing"), ("", True, "empty"), ("synthetic", True, "set")])
def test_key_existence_contract(value, exists, state):
    env = {} if value is None else {"SELECTED": value}
    assert diagnostic.key_diagnostic("SELECTED", env) == {
        "key_variable": "SELECTED", "key_variable_set": exists, "key_state": state}


def test_installation_warnings_do_not_block_offline_commands(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(diagnostic, "directory_status", lambda path: {
        "path": str(path), "exists": True, "writable": False, "code": "doctor_directory_unusable"})
    cfg = replace(Config(), provider="openai", model="synthetic", api_key_env="ABSENT_SYNTHETIC")
    monkeypatch.delenv("ABSENT_SYNTHETIC", raising=False)
    path = tmp_path / "config.json"
    save_config(path, cfg)
    assert main(["--config", str(path), "doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert not report["environment"]["blockers"]
    assert {"doctor_directory_unusable", "provider_key_missing"} <= {
        row["code"] for row in report["environment"]["warnings"]}


@pytest.mark.parametrize("route", ["installation", "configuration", "gate"])
@pytest.mark.parametrize("value,state", [(None, "missing"), ("", "empty"), ("synthetic-value", "set")])
def test_cli_key_values_and_lengths_never_appear(route, value, state, gate_case, tmp_path, monkeypatch, capsys):
    def no_socket(*_args, **_kwargs):
        raise AssertionError("doctor must remain offline")
    monkeypatch.setattr(socket, "socket", no_socket)
    cfg = replace(Config(), provider="openai", model="synthetic", api_key_env="REVIEW_PROVIDER_KEY",
                  input_usd_per_million=1, output_usd_per_million=1, allow_network=True)
    path = tmp_path / "config.json"
    save_config(path, cfg)
    if route == "installation":
        # Plain doctor reads the folder beside this configuration, so it runs from that directory.
        monkeypatch.chdir(tmp_path)
    args = ["--config", str(path), "doctor"]
    if route != "installation":
        args += ["--repo", str(gate_case["repo"]), "--base", gate_case["base"], "--head", gate_case["head"]]
    if route == "gate":
        args += ["--policy", "gate-policy.json", "--policy-sha256", gate_case["pin"]]
    def invoke(val):
        if val is None:
            monkeypatch.delenv("REVIEW_PROVIDER_KEY", raising=False)
        else:
            monkeypatch.setenv("REVIEW_PROVIDER_KEY", val)
        code = main(args)
        output = capsys.readouterr()
        assert not output.err
        if val:
            assert val not in output.out
        report = json.loads(output.out)
        assert report["key_value_read"] == (val is not None)
        assert not report["key_values_returned"]
        assert report["environment"]["keys"][0]["state"] == state
        if route != "installation":
            assert report["provider"]["key_variable_set"] == (val is not None)
            assert report["status"] == ("ready" if state == "set" else "blocked")
            if state != "set":
                expected = "provider_key_empty" if state == "empty" else "provider_key_missing"
                assert expected in {row["code"] for row in report["blockers"]}
        assert code == (0 if route == "installation" or state == "set" else 1)
        return report
    first = invoke(value)
    if value:
        assert first == invoke("different-synthetic-" + "x" * 200)


def test_two_keys_aggregate_reads_even_when_policy_key_missing(gate_case, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("REVIEW_PROVIDER_KEY", raising=False)
    monkeypatch.setenv("CONFIG_ONLY_KEY", "synthetic")
    cfg = replace(Config(), provider="openai", model="synthetic", api_key_env="CONFIG_ONLY_KEY")
    path = tmp_path / "config.json"
    save_config(path, cfg)
    assert main(["--config", str(path), "doctor", "--repo", str(gate_case["repo"]), "--base", gate_case["base"],
                 "--head", gate_case["head"], "--policy", "gate-policy.json", "--policy-sha256", gate_case["pin"]]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["key_value_read"] and report["environment"]["key_value_read"]
    assert report["provider"]["key_state"] == "missing"
    assert len(report["environment"]["keys"]) == 2


@pytest.mark.parametrize("route", ["configuration", "gate"])
def test_environment_blockers_reach_range_status_and_exit(route, gate_case, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(diagnostic, "git_status", lambda: {
        "blockers": [{"code": "git_capability_check_failed", **error_fields("git_capability_check_failed")}],
        "warnings": []})
    args = ["doctor", "--repo", str(gate_case["repo"]), "--base", gate_case["base"], "--head", gate_case["head"]]
    if route == "gate":
        args += ["--policy", "gate-policy.json", "--policy-sha256", gate_case["pin"]]
    assert main(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "blocked"
    assert "git_capability_check_failed" in {row["code"] for row in report["blockers"]}


def test_package_reports_running_version_and_tool_paths(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(doctor_package.metadata, "version", lambda _: "0.0.1")
    from finassist import platform_support
    monkeypatch.setattr(platform_support, "locate_tool",
                        lambda name: None if name == "podman" else str(tmp_path / name))
    # Only optional-tool lookup is replaced; preserve Git's installed resolver.
    import shutil
    monkeypatch.setattr(diagnostic, "find_tool", lambda _: shutil.which("git"))
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["version"] == __version__ and report["package"]["metadata_version"] == "0.0.1"
    assert report["python_executable"] == sys.executable
    assert report["tools"] == {"docker": str(tmp_path / "docker"), "podman": None, "gh": str(tmp_path / "gh")}
    assert report["package"]["resources"] == {"hints": "ok", "guides": "ok", "schemas": "ok"}
    assert "doctor_version_mismatch" in {row["code"] for row in report["environment"]["warnings"]}


@pytest.mark.parametrize("kind", ["guides", "schemas"])
@pytest.mark.parametrize("damage", ["missing", "malformed"])
def test_packaged_resource_damage_is_warning(kind, damage, monkeypatch):
    real = doctor_package.files("finassist").joinpath("resources")
    class Resource:
        def joinpath(self, name):
            target = "first-run-guide.md" if kind == "guides" else "review.schema.json"
            if name != target:
                return real.joinpath(name)
            class Broken:
                def read_text(self, **_kwargs):
                    if damage == "missing":
                        raise FileNotFoundError()
                    return "bad resource"
            return Broken()
    class Package:
        def joinpath(self, _name):
            return Resource()
    monkeypatch.setattr(doctor_package, "files", lambda _: Package())
    report = doctor_package.package_status()
    assert report["resources"][kind] == "unavailable"
    assert any(row.get("resource_kind") == kind for row in report["warnings"])


def test_damaged_hints_do_not_crash_package_diagnostic(monkeypatch):
    from finassist import error_hints
    class Broken:
        def joinpath(self, _name):
            return self
        def read_text(self, **_kwargs):
            return "{"
    monkeypatch.setattr(error_hints, "files", lambda _: Broken())
    assert doctor_package.package_status()["resources"]["hints"] == "unavailable"


@pytest.mark.parametrize("failure,code", [(httpx.ConnectTimeout, "provider_timeout"), (httpx.ReadTimeout, "provider_timeout"),
                                         (httpx.ConnectError, "provider_connection_failed"),
                                         (httpx.RemoteProtocolError, "provider_connection_failed")])
def test_timeout_connection_and_protocol_codes_no_echo_or_retry(failure, code, monkeypatch):
    monkeypatch.setenv("FAKE_KEY", "synthetic-secret")
    config = replace(Config(), provider="openai", model="synthetic", api_key_env="FAKE_KEY", allow_network=True)
    calls = []
    def fail(request):
        calls.append(request)
        raise failure("never-output-transport-detail", request=request)
    with pytest.raises(AssistantError) as caught:
        providers.invoke(config, "instructions", {}, {}, network_approved=True, transport=httpx.MockTransport(fail))
    assert caught.value.code == code and len(calls) == 1
    record = error_record(caught.value, "review", error_fields(code))
    assert record["hint"] and "never-output" not in canonical(record).decode()


@pytest.mark.parametrize("status,code", [(401, "provider_http_unauthorized"), (403, "provider_http_forbidden"),
    (404, "provider_http_not_found"), (408, "provider_timeout"), (429, "provider_http_rate_limited"),
    (500, "provider_http_server_error"), (503, "provider_http_server_error"), (302, "provider_http_error")])
def test_gate_http_status_survives_without_response_body_headers_or_ledger_leak(gate_case, status, code):
    calls = []
    def fail(request):
        calls.append(request)
        return httpx.Response(status, text="never-output-response", headers={"X-" + "Secret": "never-output-header"})
    report = model_gate(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                        gate_case["pin"], gate_case["state"], transport=httpx.MockTransport(fail))
    assert report["verdict"] == "BLOCKED" and code in report["reasons"] and len(calls) == 1
    assert report["reason_details"] == [{"code": code, "http_status": status}]
    assert "unreconciled_model_usage" in report["reasons"]
    validate_model_report(report)
    invalid = {**report, "reasons": ["unreconciled_model_usage"]}
    invalid["report_hash"] = digest(canonical({k: v for k, v in invalid.items() if k != "report_hash"}))
    with pytest.raises(AssistantError, match="gate_report_invalid"):
        validate_model_report(invalid)
    assert b"never-output" not in canonical(report)
    for file in gate_case["state"].iterdir():
        if file.is_file():
            assert b"never-output" not in file.read_bytes()


def test_documented_key_use_table_matches_runtime_registry():
    from finassist.doctor_key_uses import KEY_USES, key_use_markdown
    text = (Path(__file__).resolve().parents[1] / "docs/providers.md").read_text(encoding="utf-8")
    assert key_use_markdown() in text
    assert any(row["command"] == "GitHub Action model-review mode" and row["source"] == "gate policy" for row in KEY_USES)
