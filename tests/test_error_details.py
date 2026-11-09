"""Errors carry bounded, non-secret details, and doctor flags settings with no effect (#64 phase 1)."""

from dataclasses import replace
import json

import pytest

from test_model_policy import model_policy
from finassist.cli import main
from finassist.error_hints import error_fields
from finassist.config import Config, save_config
from finassist.errors import AssistantError
from finassist.github_audit import inspect_github
from finassist.model_policy import load_model_policy
from finassist.policy_fixtures import fixture_settings
from finassist.review import call_model, review_schema
from finassist.scope import build_packet

pytest_plugins = ("test_model_policy",)
RANGE = {"minimum": 1, "maximum": 2_000_000}
PRICES = ["input_usd_per_million", "output_usd_per_million"]


def error_output(capsys, argv) -> dict:
    """The error record without its packaged hint, which test_error_hints checks."""
    assert main(argv) == 2
    record = json.loads(capsys.readouterr().err)
    assert record.pop("hint") == error_fields(record["code"])["hint"]
    return record


@pytest.mark.parametrize("option,value,code,details", [
    ("max_file_bytes", 3_000_000, "invalid_limit", {"option": "max_file_bytes", **RANGE}),
    ("timeout_seconds", 0, "invalid_limit", {"option": "timeout_seconds", **RANGE}),
    ("readiness_max_age_seconds", 0, "invalid_evidence_age", {"option": "readiness_max_age_seconds", **RANGE}),
    ("input_usd_per_million", -1, "invalid_cost_limit", {"option": "input_usd_per_million", "minimum": 0}),
])
def test_limit_errors_state_the_option_and_allowed_range(tmp_path, capsys, option, value, code, details):
    path = tmp_path / "finassist.json"
    path.write_text(json.dumps({option: value}), encoding="utf-8")
    assert error_output(capsys, ["--config", str(path), "doctor"]) == {"status": "error", "code": code, **details}


def test_fixture_limit_states_its_range(tmp_path):
    with pytest.raises(AssistantError) as caught:
        fixture_settings(tmp_path, "0" * 40, {"fixture_max_file_bytes": 0})
    assert caught.value.code == "invalid_fixture_limit"
    assert caught.value.public_details == {"option": "fixture_max_file_bytes", **RANGE}


def test_file_limit_reports_limit_and_size_and_names_the_path_only_locally(repository, tmp_path, capsys):
    repo, base, head = repository
    path = tmp_path / "finassist.json"
    save_config(path, replace(Config(), max_file_bytes=10))
    error = error_output(capsys, ["--config", str(path), "--audit-dir", str(tmp_path / "audit"), "plan",
                                  "--repo", str(repo), "--base", base, "--head", head,
                                  "--output", str(tmp_path / "plan.json")])
    assert error.pop("local") == {"path": "src/cash.py"}  # For the person at this machine only.
    assert error["code"] == "file_limit_exceeded" and error["limit"] == 10 and error["bytes"] > 10
    assert set(error) == {"status", "code", "limit", "bytes"} and "cash" not in json.dumps(error)


@pytest.mark.parametrize("prices,missing", [((0, 0), PRICES), ((1, 0), ["output_usd_per_million"])])
def test_policy_prices_list_every_missing_field(policy_case, prices, missing):
    document = model_policy()
    document["model_review"].update(input_usd_per_million=prices[0], output_usd_per_million=prices[1])
    repo, base, pin = policy_case(document)
    with pytest.raises(AssistantError) as caught:
        load_model_policy(repo, base, "gate-policy.json", pin)
    assert caught.value.code == "provider_prices_required" and caught.value.public_details == {"missing": missing}


def test_review_refusals_name_the_missing_permission_or_prices(repository, tmp_path, monkeypatch):
    repo, base, head = repository
    config = replace(Config(), provider="openai", model="synthetic-model")
    packet = build_packet(repo, base, head, config)

    def refusal(active, *, approved):
        with pytest.raises(AssistantError) as caught:
            call_model(packet, active, tmp_path / "audit.sqlite", review_schema(), active.instructions(),
                       network_approved=approved, approved_packet_hash=packet["packet_hash"])
        return caught.value

    error = refusal(config, approved=True)
    assert error.code == "network_not_approved"
    assert error.public_details == {"allow_network": False, "allow_network_flag": True}
    error = refusal(replace(config, allow_network=True), approved=False)
    assert error.public_details == {"allow_network": True, "allow_network_flag": False}
    monkeypatch.setenv("OPENAI_API_KEY", "fictional-provider-value")
    error = refusal(replace(config, allow_network=True), approved=True)
    assert error.code == "provider_prices_required" and error.public_details == {"missing": PRICES}
    assert not (tmp_path / "audit.sqlite").exists()


def test_github_inspection_names_the_missing_network_permission():
    with pytest.raises(AssistantError) as caught:
        inspect_github("synthetic/repository", "main", Config(), network_approved=True)
    assert caught.value.public_details == {"allow_network": False, "allow_network_flag": True}


def test_doctor_reports_its_config_source_and_settings_with_no_effect(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["config_source"] == "defaults" and report["config_warnings"] == []
    path = tmp_path / "finassist.json"
    save_config(path, replace(Config(), provider="google", model="synthetic-model",
                              text_suffixes=(*Config().text_suffixes, ".csv", ".pem")))
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [warning["code"] for warning in report["config_warnings"]] == ["config_file_not_loaded"]
    assert main(["--config", str(path), "doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    codes = [warning["code"] for warning in report["config_warnings"]]
    assert report["config_source"] == "file"
    assert codes == ["text_suffix_always_denied", "text_suffix_always_denied", "provider_prices_missing"]
    suffixes = {warning["suffix"]: warning["hint"] for warning in report["config_warnings"] if "suffix" in warning}
    assert "fixture_roots" in suffixes[".csv"]
    assert "fixture_roots" not in suffixes[".pem"] and "remove it from text_suffixes" in suffixes[".pem"]
    assert "can't be admitted" in suffixes[".pem"] and "can't be admitted" not in suffixes[".csv"]
    assert report["config_warnings"][-1]["missing"] == PRICES


def test_public_details_are_bounded_and_never_replace_the_code():
    error = AssistantError("synthetic_code", {"code": "other", "status": "ok", "Bad-Key": 1, "option": "x",
                                              "limit": 10, "items": ("a", "b"), "nested": {"a": 1},
                                              "long": "x" * 300})
    assert error.public_details == {"option": "x", "limit": 10, "items": ["a", "b"]}
