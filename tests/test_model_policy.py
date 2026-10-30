"""Opt-in model authority must be present in exact pinned BASE bytes."""

from copy import deepcopy

import pytest

from conftest import command
from finassist.errors import AssistantError
from finassist.model_policy import load_model_policy
from finassist.security import canonical, digest


def model_policy():
    return {"schema_version": 2, "model_review": {
        "enabled": True, "provider": "openai", "model": "operator-selected",
        "endpoint": "https://api.openai.com/v1/responses", "allowed_host": "api.openai.com",
        "api_key_env": "REVIEW_PROVIDER_KEY", "allow_paths": ["src/"], "deny_paths": [],
        "max_request_bytes": 120_000, "max_file_bytes": 48_000, "max_files": 10,
        "profile": "finance-saas", "max_output_tokens": 4096, "timeout_seconds": 60,
        "max_run_usd": 1, "daily_budget_usd": 5,
        "input_usd_per_million": 1, "output_usd_per_million": 2,
        "blocking_severities": [],
    }}


@pytest.fixture
def policy_case(repository):
    repo, _, _ = repository

    def commit_policy(document=None, *, raw=None):
        data = raw if raw is not None else canonical(document if document is not None else model_policy()) + b"\n"
        (repo / "gate-policy.json").write_bytes(data)
        command(repo, "add", "gate-policy.json")
        command(repo, "commit", "--allow-empty", "-m", "Synthetic policy baseline")
        return repo, command(repo, "rev-parse", "HEAD"), digest(data)

    return commit_policy


def test_policy_builds_explicit_config_without_reading_key(policy_case, monkeypatch):
    monkeypatch.delenv("REVIEW_PROVIDER_KEY", raising=False)
    repo, base, pin = policy_case()
    policy = load_model_policy(repo, base, "gate-policy.json", pin)
    assert policy.config.provider == "openai" and policy.config.allow_network
    assert policy.config.key_name == "REVIEW_PROVIDER_KEY"
    assert policy.config.generated_paths == () and not policy.config.allow_partial_review
    assert policy.config.blocking_severities == ()
    assert policy.sha256 == pin and policy.base == base


def test_raw_byte_pin_and_base_revision_cannot_be_changed_by_head(policy_case):
    repo, base, pin = policy_case()
    changed = model_policy()
    changed["model_review"]["model"] = "unapproved-head-model"
    _, head, new_pin = policy_case(changed)
    assert load_model_policy(repo, base, "gate-policy.json", pin).config.model == "operator-selected"
    assert head != base
    with pytest.raises(AssistantError, match="gate_policy_pin_mismatch"):
        load_model_policy(repo, base, "gate-policy.json", new_pin)
    with pytest.raises(AssistantError, match="gate_policy_pin_mismatch"):
        load_model_policy(repo, head, "gate-policy.json", pin)


@pytest.mark.parametrize("field", list(model_policy()["model_review"]))
def test_every_authorization_field_is_required(policy_case, field):
    document = model_policy()
    document["model_review"].pop(field)
    repo, base, pin = policy_case(document)
    with pytest.raises(AssistantError, match="gate_policy_invalid"):
        load_model_policy(repo, base, "gate-policy.json", pin)


@pytest.mark.parametrize("changes,code", [
    ({"enabled": False}, "gate_policy_invalid"),
    ({"enabled": 1}, "gate_policy_invalid"),
    ({"provider": "offline"}, "gate_policy_invalid"),
    ({"allowed_host": "other.example"}, "gate_endpoint_host_mismatch"),
    ({"endpoint": "http://api.openai.com/v1/responses"}, "https_required"),
    ({"endpoint": "https://api.openai.com/v1/responses?key=fictional"}, "unsafe_endpoint"),
    ({"api_key_env": "bad-name"}, "gate_policy_invalid"),
    ({"max_files": True}, "gate_policy_invalid"),
    ({"max_request_bytes": 0}, "gate_policy_invalid"),
    ({"max_file_bytes": 2_000_001}, "gate_policy_invalid"),
    ({"max_output_tokens": 0}, "gate_policy_invalid"),
    ({"timeout_seconds": 301}, "gate_policy_invalid"),
    ({"profile": "not-registered"}, "unknown_profile"),
    ({"allow_paths": []}, "gate_policy_invalid"),
    ({"allow_paths": ["../src/"]}, "unsafe_path"),
    ({"deny_paths": ["src/**"]}, "gate_policy_path_invalid"),
    ({"daily_budget_usd": -1}, "gate_policy_invalid"),
    ({"max_run_usd": False}, "gate_policy_invalid"),
    ({"input_usd_per_million": 0}, "provider_prices_required"),
    ({"output_usd_per_million": 0}, "provider_prices_required"),
    ({"blocking_severities": ["fatal"]}, "gate_policy_invalid"),
    ({"disable_screening": True}, "gate_policy_invalid"),
    ({"denied_parts": []}, "gate_policy_invalid"),
    ({"profile_files": ["untrusted.json"]}, "gate_policy_invalid"),
])
def test_capability_or_rule_failure_is_named(policy_case, changes, code):
    document = deepcopy(model_policy())
    document["model_review"].update(changes)
    repo, base, pin = policy_case(document)
    with pytest.raises(AssistantError, match=code):
        load_model_policy(repo, base, "gate-policy.json", pin)


def test_v1_keeps_model_opt_in_blocked(policy_case):
    repo, base, pin = policy_case({"schema_version": 1, "review": "required"})
    with pytest.raises(AssistantError, match="gate_model_opt_in_required"):
        load_model_policy(repo, base, "gate-policy.json", pin)


@pytest.mark.parametrize("raw", [b'{"schema_version":2,"schema_version":2}', b'{"schema_version":NaN}', b'[]'])
def test_ambiguous_json_is_rejected(policy_case, raw):
    repo, base, pin = policy_case(raw=raw)
    with pytest.raises(AssistantError):
        load_model_policy(repo, base, "gate-policy.json", pin)
