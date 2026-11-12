"""Exact review regressions using synthetic keys, directories and fake transports."""

from dataclasses import replace
import json
from pathlib import Path

import httpx
import pytest

from finassist import doctor_environment as diagnostic, platform_support
from finassist.cli import main
from finassist.config import Config, save_config
from finassist.error_hints import hints, error_fields
from finassist.errors import AssistantError
from finassist.health import doctor_report
from finassist.ledger import Ledger
from finassist.model_gate import model_gate
from finassist.onboarding import policy_preflight
from finassist.review import review_packet
from finassist.scope import build_packet

pytest_plugins = ("test_model_gate", "test_model_policy")


@pytest.mark.parametrize("value", [None, "", "synthetic-local-value"])
def test_offline_custom_key_read_is_counted_only_in_cli(tmp_path, monkeypatch, capsys, value):
    monkeypatch.chdir(tmp_path)
    name = "DOCTOR_SYNTHETIC_KEY"
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)
    cfg = replace(Config(), api_key_env=name)
    config_path = tmp_path / "config.json"
    save_config(config_path, cfg)
    assert "key_value_read" not in doctor_report(cfg)
    assert main(["--config", str(config_path), "doctor"]) == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["key_value_read"] is (value is not None)
    assert report["key_present"] is bool(value)
    assert report["environment"]["keys"] == []  # Offline has no provider use.
    assert report["key_values_returned"] is False
    if value:
        assert value not in output
    assert not (tmp_path / ".finassist").exists()


@pytest.mark.parametrize("value,code", [(None, "provider_key_missing"), ("", "provider_key_empty")])
@pytest.mark.parametrize("route", ["review", "gate"])
def test_unusable_key_is_classified_before_any_reservation_or_transport(
        repository, gate_case, tmp_path, monkeypatch, route, value, code):
    name = "REVIEW_PROVIDER_KEY"
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)

    def unexpected(*_args, **_kwargs):
        raise AssertionError("No reservation or transport is allowed for an unusable key")

    monkeypatch.setattr(Ledger, "reserve", unexpected)
    transport = httpx.MockTransport(unexpected)
    if route == "review":
        repo, base, head = repository
        packet = build_packet(repo, base, head, Config())
        cfg = replace(Config(), provider="openai", model="synthetic", api_key_env=name,
                      allow_network=True, input_usd_per_million=1, output_usd_per_million=1)
        ledger = tmp_path / "review.sqlite"
        with pytest.raises(AssistantError) as caught:
            review_packet(packet, cfg, ledger, network_approved=True,
                          approved_packet_hash=packet["packet_hash"], transport=transport)
        assert caught.value.code == code
        assert not ledger.exists()
    else:
        report = model_gate(gate_case["repo"], gate_case["base"], gate_case["head"],
                            "gate-policy.json", gate_case["pin"], gate_case["state"], transport=transport)
        assert report["verdict"] == "BLOCKED" and code in report["reasons"]
        assert report["spend"]["reserved_usd"] is None


def test_missing_key_uses_same_packaged_hint_in_gate_and_environment(gate_case, monkeypatch):
    monkeypatch.delenv("REVIEW_PROVIDER_KEY", raising=False)
    report = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"],
                              "gate-policy.json", gate_case["pin"], include_environment=True)
    blocker = next(row for row in report["blockers"] if row["code"] == "provider_key_missing")
    environment = next(row for row in report["environment"]["blockers"] if row["code"] == "provider_key_missing")
    assert blocker["hint"] == environment["hint"] == error_fields("provider_key_missing")["hint"]


def test_provider_price_codes_keep_setup_area():
    for code in ("provider_prices_required", "provider_prices_missing"):
        assert hints()[code]["area"] == "setup"


def test_optional_batch_shims_are_not_reported_as_usable_tools(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    locate = platform_support.locate_tool
    monkeypatch.setattr(platform_support, "locate_tool",
                        lambda name: locate(name) if name == "git" else str(tmp_path / (name + ".cmd")))
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["tools"] == {"docker": None, "podman": None, "gh": None}
    assert not report["docker_binary_present"] and not report["podman_binary_present"]


def test_symlink_directory_metadata_reports_link_without_access_probe(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Creating a symlink requires platform permission")

    def unexpected(*_args, **_kwargs):
        raise AssertionError("A refused path must not reach the access estimate")

    monkeypatch.setattr(diagnostic.os, "access", unexpected)
    report = diagnostic.directory_status(link, windows=False)
    assert report["code"] == "doctor_directory_unusable"
    assert report["exists"] is True and report["path"] == str(link)
    assert report["writable"] is None
    assert list(target.iterdir()) == []


def test_unexpandable_directory_writability_is_unknown(monkeypatch):
    def unavailable(_path):
        raise RuntimeError("Synthetic unavailable home")
    monkeypatch.setattr(Path, "expanduser", unavailable)
    report = diagnostic.directory_status(Path("~missing/state"), windows=False)
    assert report["code"] == "doctor_directory_unusable"
    assert report["path"] is None and report["writable"] is None
