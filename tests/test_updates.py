"""Synthetic update checks, private cache races and explicit fake installer execution."""

from concurrent.futures import ThreadPoolExecutor
import io
import json
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import httpx
import pytest

from finassist.cli import main
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.health import doctor_report
from finassist import update_check, update_settings, updater


@pytest.fixture(autouse=True)
def isolated_updates(tmp_path, monkeypatch):
    for module in (update_settings, update_check):
        monkeypatch.setattr(module, "user_directory", lambda kind: tmp_path / kind)
    monkeypatch.delenv("FINASSIST_NO_UPDATE_CHECK", raising=False)
    for name in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(update_check, "installed_version", lambda: "0.5.0")


def notify_setting(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config/settings.json").write_text('{"update_check":"notify"}', encoding="utf-8")


def transport(calls, *, version="0.6.0", status=200):
    def handler(request):
        calls.append(request)
        return httpx.Response(status, json={"info": {"version": version}},
                              headers={"Location": "https://example.invalid/wrong"} if status == 302 else {})
    return httpx.MockTransport(handler)


def test_defaults_health_status_and_dry_run_are_offline_and_do_not_create_state(tmp_path, monkeypatch, capsys):
    def refuse(*args, **kwargs):
        pytest.fail("default health/status/preview must not request the network or execute an installer")
    monkeypatch.setattr(update_check, "fetch_latest", refuse)
    monkeypatch.setattr(updater.subprocess, "run", refuse)
    monkeypatch.chdir(tmp_path)
    assert update_settings.update_setting() == "off"
    assert doctor_report(Config())["updates"]["status"] == "not checked"
    assert main(["update", "status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["latest_version"] is None
    assert main(["update", "--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["dry_run"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("raw", ['{"update_check":"auto"}', '{"update_check":[]}',
                                '{"update_check":"off","update_check":"notify"}', '{"provider":"remote"}', '[]'])
def test_user_preferences_cannot_enable_installs_or_accept_ambiguous_values(tmp_path, raw):
    (tmp_path / "config").mkdir()
    (tmp_path / "config/settings.json").write_text(raw, encoding="utf-8")
    with pytest.raises(AssistantError, match="invalid_update_settings"):
        update_settings.update_setting()


def test_explicit_check_is_one_fixed_get_with_no_auth_cookies_or_identifiers(monkeypatch):
    calls = []
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.invalid")
    monkeypatch.setenv("SYNTHETIC_PROVIDER_DATA", "never-forward")
    report = update_check.check_once(network_allowed=True, transport=transport(calls))
    assert report["status"] == "update-available" and report["latest_version"] == "0.6.0"
    assert len(calls) == 1 and calls[0].method == "GET" and str(calls[0].url) == update_check.PYPI_URL
    assert not calls[0].content and "authorization" not in calls[0].headers and "cookie" not in calls[0].headers
    assert "0.5.0" not in str(calls[0].headers) and "never-forward" not in str(calls[0])
    assert update_check.check_report(update_check.cached_check())["status"] == "update-available"


def test_network_and_environment_denials_do_not_touch_cache_or_transport(tmp_path, monkeypatch):
    calls = []
    assert update_check.check_once(network_allowed=False, transport=transport(calls))["status"] == "not checked"
    monkeypatch.setenv("FINASSIST_NO_UPDATE_CHECK", "")
    assert update_check.check_once(network_allowed=True, transport=transport(calls))["reason"] == "disabled-by-environment"
    assert calls == [] and not (tmp_path / "cache").exists()


@pytest.mark.parametrize("status,version", [(302, "0.6.0"), (503, "0.6.0"), (200, "0.6.0rc1"), (200, "0.6.0\n")])
def test_redirects_errors_and_invalid_versions_mean_not_checked_without_retry(status, version):
    calls = []
    report = update_check.check_once(network_allowed=True, transport=transport(calls, status=status, version=version))
    assert report["status"] == "not checked" and report["latest_version"] is None
    assert len(calls) == 1 and update_check.reserve_check() is None


def test_oversized_or_malformed_response_is_not_cached_as_a_version():
    for content in (b"x" * (update_check.MAX_BYTES + 1), b'{"info":null}', b'not json'):
        response_transport = httpx.MockTransport(lambda request, body=content: httpx.Response(200, content=body))
        assert update_check.check_once(network_allowed=True, transport=response_transport)["status"] == "not checked"


def test_cache_reservations_are_atomic_and_pending_dispatch_is_not_retried():
    def reserve(_):
        try:
            return update_check.reserve_check()
        except sqlite3.OperationalError:
            # The notifier treats its short local lock timeout as unavailable,
            # never as permission to send an unreserved request.
            return None
    with ThreadPoolExecutor(max_workers=6) as pool:
        claims = list(pool.map(reserve, range(6)))
    claims = [claim for claim in claims if claim]
    assert len(claims) == 1
    calls = []
    update_check.perform_check(claims[0], transport=transport(calls))
    update_check.perform_check(claims[0], transport=transport(calls))
    assert len(calls) == 1
    assert update_check.reserve_check() is None
    assert update_check.reserve_check(now=update_check.cached_check()["started"] + update_check.INTERVAL)


class TTY(io.StringIO):
    def isatty(self):
        return True


def interactive(monkeypatch):
    monkeypatch.setattr(sys, "stdin", TTY())
    monkeypatch.setattr(sys, "stdout", TTY())


@pytest.mark.parametrize("condition", ["off", "ci", "no-network", "noninteractive", "environment", "workflow", "gate"])
def test_automatic_notice_suppression_creates_no_cache_or_worker(tmp_path, monkeypatch, condition):
    if condition != "off":
        notify_setting(tmp_path)
    interactive(monkeypatch)
    if condition == "ci":
        monkeypatch.setenv("CI", "")
    if condition == "environment":
        monkeypatch.setenv("FINASSIST_NO_UPDATE_CHECK", "1")
    if condition == "noninteractive":
        monkeypatch.setattr(sys, "stdin", io.StringIO())
    def refuse(*args, **kwargs):
        pytest.fail("suppressed notices must not start workers")
    monkeypatch.setattr(subprocess, "Popen", refuse)
    output = TTY()
    command = condition if condition in {"workflow", "gate"} else "demo"
    update_check.maybe_notify(network_allowed=condition != "no-network", command=command, stderr=output)
    assert not output.getvalue() and not (tmp_path / "cache").exists()


def test_notifier_launches_once_without_waiting_and_passes_only_scoped_environment(tmp_path, monkeypatch):
    notify_setting(tmp_path)
    interactive(monkeypatch)
    monkeypatch.setenv("SYNTHETIC_PROVIDER_DATA", "never-forward")
    monkeypatch.setenv("PYTHONPATH", "untrusted")
    calls = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: calls.append((args, kwargs)))
    for _ in range(2):
        update_check.maybe_notify(network_allowed=True, command="demo", stderr=TTY())
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0][1:4] == ["-I", "-m", "finassist.update_check"]
    assert "SYNTHETIC_PROVIDER_DATA" not in kwargs["env"] and "PYTHONPATH" not in kwargs["env"]
    assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL


def test_cached_notice_prints_to_stderr_only_once_per_utc_day(tmp_path, monkeypatch):
    notify_setting(tmp_path)
    interactive(monkeypatch)
    update_check.check_once(network_allowed=True, transport=transport([]))
    monkeypatch.setattr(updater, "installation", lambda: {"upgrade_command": "pipx upgrade finledgerpoli"})
    output = TTY()
    for _ in range(3):
        update_check.maybe_notify(network_allowed=True, command="doctor", stderr=output)
    assert output.getvalue().count("0.6.0 is available") == 1
    assert "pipx upgrade finledgerpoli" in output.getvalue()
    assert sys.stdout.getvalue() == ""


def fake_install(monkeypatch, tmp_path, *, installer="pip", editable=False, marker=None):
    prefix = tmp_path / ("venvs/finledgerpoli" if marker == "pipx_metadata.json" else "finledgerpoli")
    prefix.mkdir(parents=True)
    if marker:
        (prefix / marker).write_text("do not inspect manager settings", encoding="utf-8")
    monkeypatch.setattr(sys, "prefix", str(prefix))
    def read_text(name):
        return installer if name == "INSTALLER" else json.dumps({"dir_info": {"editable": editable}})
    monkeypatch.setattr(updater.metadata, "distribution", lambda name: SimpleNamespace(read_text=read_text, version="0.5.0"))
    monkeypatch.setattr(updater.shutil, "which", lambda name: str(tmp_path / (name + ".exe")))
    monkeypatch.setattr(updater.util, "find_spec", lambda name: object())


@pytest.mark.parametrize("marker,method,arguments", [(None, "pip", ["-I", "-m", "pip", "install", "--upgrade", "finledgerpoli"]),
    ("pipx_metadata.json", "pipx", ["upgrade", "finledgerpoli"]),
    ("uv-receipt.toml", "uv tool", ["tool", "upgrade", "finledgerpoli"])])
def test_installer_detection_binds_exact_package_and_argv(tmp_path, monkeypatch, marker, method, arguments):
    fake_install(monkeypatch, tmp_path, marker=marker)
    report = updater.installation()
    assert report["install_method"] == method and report["can_upgrade"]
    assert report["upgrade_argv"][1:] == arguments
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs)) or SimpleNamespace(returncode=0))
    monkeypatch.setenv("SYNTHETIC_PROVIDER_DATA", "never-forward")
    monkeypatch.setenv("PIPX_HOME", "unrelated-manager-home")
    monkeypatch.setenv("UV_TOOL_DIR", "unrelated-tools")
    with pytest.raises(AssistantError, match="upgrade_confirmation_required"):
        updater.run_upgrade(confirmed=False)
    assert not calls
    assert updater.run_upgrade(confirmed=True)["status"] == "installer-succeeded"
    assert len(calls) == 1 and calls[0][0][0] == report["upgrade_argv"]
    assert calls[0][1]["shell"] is False and "SYNTHETIC_PROVIDER_DATA" not in calls[0][1]["env"]
    if method == "pipx":
        assert calls[0][1]["env"]["PIPX_HOME"] == str(tmp_path)
        assert "PIPX_HOME=" in report["upgrade_command"]
    if method == "uv tool":
        assert calls[0][1]["env"]["UV_TOOL_DIR"] == str(tmp_path)
        assert "UV_TOOL_DIR=" in report["upgrade_command"]


@pytest.mark.parametrize("kind", ["editable", "unknown", "batch"])
def test_unrecognized_editable_and_batch_installers_refuse_execution(tmp_path, monkeypatch, kind):
    fake_install(monkeypatch, tmp_path, editable=kind == "editable",
                 installer="system-manager" if kind == "unknown" else "pip",
                 marker="pipx_metadata.json" if kind == "batch" else None)
    if kind == "batch":
        monkeypatch.setattr(updater.shutil, "which", lambda name: str(tmp_path / "tool.cmd"))
    assert not updater.installation()["can_upgrade"]
    with pytest.raises(AssistantError, match="upgrade_installation_not_supported"):
        updater.run_upgrade(confirmed=True)


def test_installer_timeout_has_unknown_outcome_and_is_not_retried(tmp_path, monkeypatch):
    fake_install(monkeypatch, tmp_path)
    calls = []
    def timeout(*args, **kwargs):
        calls.append(args)
        raise subprocess.TimeoutExpired(args[0], 300)
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(AssistantError, match="upgrade_outcome_unknown_inspect_installation"):
        updater.run_upgrade(confirmed=True)
    assert len(calls) == 1


def test_cli_fix_check_and_status_install_flags_cannot_silently_conflict(tmp_path, capsys):
    for args, code in [(["doctor", "--fix", "--check-updates"], "doctor_fix_must_remain_offline"),
                       (["update", "status", "--yes"], "update_status_action_conflict"),
                       (["--config", "broken.json", "update", "--dry-run"], "update_does_not_accept_project_config")]:
        assert main(args) == 2
        assert json.loads(capsys.readouterr().err)["code"] == code
    assert not (tmp_path / "cache").exists()


def test_cli_doctor_respects_network_denial_and_only_manual_check_calls_checker(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(update_check, "check_once", lambda **kwargs: calls.append(kwargs) or update_check.check_report())
    assert main(["doctor"]) == 0
    assert json.loads(capsys.readouterr().out)["updates"]["status"] == "not checked" and not calls
    assert main(["doctor", "--check-updates"]) == 0
    capsys.readouterr()
    assert calls == [{"network_allowed": False}]


def test_cli_explicit_fake_installer_is_audited_without_command_paths(tmp_path, monkeypatch, capsys):
    from finassist.ledger import Ledger

    fake_install(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append(args) or SimpleNamespace(returncode=0))
    audit = tmp_path / "audit"
    assert main(["--audit-dir", str(audit), "update", "--yes", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "installer-succeeded" and len(calls) == 1
    with Ledger(audit / "audit.sqlite") as ledger:
        ledger.verify()
        events = ledger.events()
    payloads = [row["payload"] for row in events]
    assert [row["event"] for row in payloads] == ["command_started", "package_upgrade_finished", "command_completed"]
    assert "upgrade_argv" not in str(payloads) and str(tmp_path) not in str(payloads)


def test_unknown_cli_installer_outcome_retains_an_open_audit_run(tmp_path, monkeypatch, capsys):
    from finassist.errors import OperationOutcomeUnknown
    from finassist.ledger import Ledger

    def unknown(**kwargs):
        raise OperationOutcomeUnknown("upgrade_outcome_unknown_inspect_installation")
    monkeypatch.setattr(updater, "run_upgrade", unknown)
    audit = tmp_path / "audit"
    assert main(["--audit-dir", str(audit), "update", "--yes"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "upgrade_outcome_unknown_inspect_installation"
    with Ledger(audit / "audit.sqlite") as ledger:
        ledger.verify()
        assert [row["payload"]["event"] for row in ledger.events()] == ["command_started"]


def test_windows_preview_quotes_the_bound_manager_home_without_shell_execution(tmp_path, monkeypatch):
    manager_home = tmp_path / "manager 'home"
    fake_install(monkeypatch, manager_home, marker="uv-receipt.toml")
    monkeypatch.setattr(sys, "platform", "win32")
    info = updater.installation()
    assert info["upgrade_environment"] == {"UV_TOOL_DIR": str(manager_home)}
    assert info["upgrade_command"].startswith("$env:UV_TOOL_DIR='")
    assert "manager ''home" in info["upgrade_command"] and "; & '" in info["upgrade_command"]


def test_custom_named_pipx_environment_refuses_instead_of_upgrading_default(tmp_path, monkeypatch):
    fake_install(monkeypatch, tmp_path, marker="pipx_metadata.json")
    prefix = tmp_path / "venvs/custom-name"
    prefix.mkdir()
    (prefix / "pipx_metadata.json").write_text("never read", encoding="utf-8")
    monkeypatch.setattr(sys, "prefix", str(prefix))
    assert not updater.installation()["can_upgrade"]
