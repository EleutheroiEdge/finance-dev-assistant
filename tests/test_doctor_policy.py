"""doctor --policy reports every gate blocker for one range in one local run (#64 phase 1b).

All repositories, policies, figures and keys are synthetic.
"""

from collections.abc import Mapping
from dataclasses import replace
import hashlib
import json

import pytest

from conftest import command
from test_model_gate import change_policy, run
from test_model_policy import model_policy
from finassist import maintenance, model_gate, onboarding, providers, review
from finassist.errors import AssistantError
from finassist.cli import main
from finassist.config import Config
from finassist.forbidden_tokens import normalize_numeric_token
from finassist.onboarding import policy_preflight
from finassist.security import canonical, digest

pytest_plugins = ("test_model_gate", "test_model_policy")
KEY_VALUE = "fictional-provider-value"


def preflight(case, **kwargs):
    report = policy_preflight(case["repo"], case["base"], case["head"], "gate-policy.json",
                              kwargs.pop("pin", case["pin"]), **kwargs)
    assert KEY_VALUE not in canonical(report).decode()
    assert not report["network_used"] and not report["key_value_read"] and not report["ledger_opened"]
    return report


def codes(report) -> list[str]:
    return [entry["code"] for entry in report["blockers"]]


def test_ready_range_matches_the_gate_without_reading_the_key(gate_case, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the preflight must not shape a keyed request")

    with monkeypatch.context() as patched:
        for module in (providers, model_gate, review):
            patched.setattr(module, "request_shape", refuse)
        patched.setattr(model_gate, "prepare_model_request", refuse)
        report = preflight(gate_case)
    assert report["status"] == "ready" and report["blockers"] == [] and report["coverage_complete"]
    assert report["paths"] == [{"path": "src/cash.py", "status": "included"}]
    assert report["policy"] == {"path": "gate-policy.json", "sha256": gate_case["pin"], "pin": "matches"}
    assert 0 < report["request"]["bytes"] <= report["request"]["limit"] == 120_000
    assert report["provider"]["key_variable"] == "REVIEW_PROVIDER_KEY" and report["provider"]["key_variable_set"]
    assert gate_case["pin"] in report["next_step"]["command"]
    gate, calls = run(gate_case)
    assert gate["verdict"] == "PASS" and len(calls) == 1


def test_missing_key_variable_is_named_but_the_request_is_still_sized(gate_case, monkeypatch):
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    report = preflight(gate_case)
    assert codes(report) == ["provider_key_missing"] and report["blockers"][0]["variable"] == "REVIEW_PROVIDER_KEY"
    assert report["request"]["bytes"] > 0 and not report["provider"]["key_variable_set"]


@pytest.fixture
def adopter_case(tmp_path, monkeypatch):
    """A synthetic repository shaped like a quant engine, with every first-run blocker."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", KEY_VALUE)
    repo = tmp_path / "engine-repo"
    repo.mkdir()
    command(repo, "init", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    document = model_policy()
    document["model_review"].update(allow_paths=["engine/", "scripts/", "tests/"], max_file_bytes=200_000,
                                    max_request_bytes=2_000_000, max_files=100,
                                    input_usd_per_million=0, output_usd_per_million=0)
    walkdown = "".join(f"def step_{n}(x):\n    return x + {n}\n" for n in range(7_000))
    files = {"engine/core.py": "def stage(x):\n    return x + 1\n", "engine/walkdown.py": walkdown,
             "scripts/run.py": "print('synthetic')\n", "app.py": "APP = 'synthetic'\n",
             "tests/test_core.py": "def test_stage():\n    assert True\n", ".gitignore": ".finassist/\n"}
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
    (repo / "gate-policy.json").write_bytes(canonical(document))
    command(repo, "add", ".")
    command(repo, "commit", "-m", "Synthetic engine baseline")
    base = command(repo, "rev-parse", "HEAD")
    command(repo, "switch", "-c", "candidate")
    changes = {"engine/core.py": "def stage(x):\n    return x + 2\n",
               "engine/walkdown.py": walkdown + "def last(x):\n    return x\n",
               "app.py": "APP = 'synthetic-two'\n",
               "tests/fixtures/prices.csv": "symbol,price\nSYNTH,1.00\n",
               "data/master.csv": "symbol,weight\nSYNTH,1.00\n",
               "keys/synthetic.pem": "synthetic placeholder\n"}
    for name, text in changes.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
    command(repo, "add", ".")
    command(repo, "commit", "-m", "Synthetic candidate with every first-run blocker")
    assert len(walkdown) > 200_000
    return {"repo": repo, "base": base, "head": command(repo, "rev-parse", "HEAD"), "pin": digest(canonical(document))}


def test_one_run_lists_every_adopter_blocker(adopter_case):
    report = preflight(adopter_case)
    assert report["status"] == "blocked" and report["coverage_complete"] is False
    rows = {row["path"]: row for row in report["paths"]}
    assert rows["engine/core.py"] == {"path": "engine/core.py", "status": "included"}
    assert rows["app.py"]["code"] == "gate_path_not_allowed"
    assert rows["engine/walkdown.py"]["code"] == "file_limit_exceeded"
    assert rows["engine/walkdown.py"]["limit"] == 200_000 and rows["engine/walkdown.py"]["bytes"] > 200_000
    assert rows["tests/fixtures/prices.csv"]["code"] == "private_or_binary_path"
    assert rows["data/master.csv"]["code"] in {"private_or_binary_path", "gate_private_path"}
    found = {(entry["code"], entry.get("path")) for entry in report["blockers"]}
    assert ("provider_prices_required", None) in found
    assert {("gate_path_not_allowed", "app.py"), ("file_limit_exceeded", "engine/walkdown.py"),
            ("private_or_binary_path", "tests/fixtures/prices.csv")} <= found
    prices = next(entry for entry in report["blockers"] if entry["code"] == "provider_prices_required")
    assert prices["missing"] == ["input_usd_per_million", "output_usd_per_million"]
    assert all(entry["hint"] for entry in report["blockers"])
    hints = {row["path"]: row.get("hint", "") for row in report["paths"] if row["status"] == "refused"}
    # fixture_roots is offered only where it can work: a qualified synthetic CSV.
    assert "fixture_roots" in hints["tests/fixtures/prices.csv"]
    assert "fixture_roots" not in hints["data/master.csv"] and "fixture_roots" not in hints["keys/synthetic.pem"]
    assert rows["keys/synthetic.pem"]["code"] == "private_or_binary_path"


def test_every_schema_error_is_reported_with_its_range_and_no_value(policy_case, monkeypatch):
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", KEY_VALUE)
    document = model_policy()
    rules = document["model_review"]
    rules.update(max_file_bytes=3_000_123, timeout_seconds=0, fixture_root=["tests/fixtures/"],
                 fixture_max_file_bytes=0)
    del rules["max_files"]
    repo, base, pin = policy_case(document)
    report = policy_preflight(repo, base, base, "gate-policy.json", pin)
    issues = [{key: value for key, value in entry.items() if key not in {"code", "hint"}}
              for entry in report["blockers"] if entry["code"] == "gate_policy_invalid"]
    assert issues == [
        {"field": "/model_review", "rule": "additionalProperties", "unknown": ["fixture_root"]},
        {"field": "/model_review", "rule": "required", "missing": ["max_files"]},
        {"field": "/model_review/fixture_max_file_bytes", "rule": "minimum",
         "allowed": {"type": "integer", "minimum": 1, "maximum": 2_000_000}},
        {"field": "/model_review/max_file_bytes", "rule": "maximum",
         "allowed": {"type": "integer", "minimum": 1, "maximum": 2_000_000}},
        {"field": "/model_review/timeout_seconds", "rule": "minimum",
         "allowed": {"type": "integer", "minimum": 1, "maximum": 300}},
    ]
    assert report["status"] == "blocked" and "3000123" not in canonical(report).decode()


def test_names_that_fail_screening_are_redacted_and_nothing_is_audited(gate_case, tmp_path, capsys):
    secret_name = "src/ghp_" + "a" * 36 + ".py"
    (gate_case["repo"] / secret_name).write_text("VALUE = 1\n", encoding="utf-8")
    command(gate_case["repo"], "add", secret_name)
    command(gate_case["repo"], "commit", "-m", "Synthetic sensitive name")
    head = command(gate_case["repo"], "rev-parse", "HEAD")
    audit = tmp_path / "audit"
    exit_code = main(["--audit-dir", str(audit), "doctor", "--policy", "gate-policy.json",
                      "--policy-sha256", gate_case["pin"], "--repo", str(gate_case["repo"]),
                      "--base", gate_case["base"], "--head", head])
    output = capsys.readouterr().out
    report = json.loads(output)
    assert exit_code == 1 and "ghp_" not in output
    assert {"path": "[redacted]", "status": "refused", "code": "sensitive_content"} in report["paths"]
    assert not audit.exists()


def test_pin_states_and_short_revisions(gate_case):
    assert preflight(gate_case, pin=None)["policy"]["pin"] == "not_supplied"
    wrong = preflight(gate_case, pin="0" * 64)
    assert wrong["policy"]["pin"] == "mismatch" and codes(wrong) == ["gate_policy_pin_mismatch"]
    short = policy_preflight(gate_case["repo"], gate_case["base"][:12], "test/candidate", "gate-policy.json",
                             gate_case["pin"])
    assert short["status"] == "ready" and short["base"] == gate_case["base"]
    assert "full_revisions_required" in [warning["code"] for warning in short["warnings"]]
    assert short["head"] == command(gate_case["repo"], "rev-parse", "test/candidate")


def test_a_policy_change_inside_the_range_is_named(gate_case):
    (gate_case["repo"] / "gate-policy.json").write_bytes(canonical({"schema_version": 2}))
    command(gate_case["repo"], "add", "gate-policy.json")
    command(gate_case["repo"], "commit", "-m", "Unreviewed policy change")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report = preflight(gate_case)
    assert {"code": "gate_policy_change_requires_review", "path": "gate-policy.json"} in [
        {key: entry[key] for key in ("code", "path")} for entry in report["blockers"] if "path" in entry]
    assert run(gate_case)[0]["reasons"] == ["gate_policy_change_requires_review"]


def test_a_listed_figure_is_located_by_path_and_never_echoed(gate_case, tmp_path):
    token = tmp_path / "tokens.txt"
    token.write_text("6729102.50\n", encoding="utf-8")
    change_policy(gate_case, forbidden_token_file=str(token))
    (gate_case["repo"] / "src/cash.py").write_text("LIMIT = 6729102.50\n", encoding="utf-8")
    command(gate_case["repo"], "add", "src/cash.py")
    command(gate_case["repo"], "commit", "-m", "Synthetic listed figure")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report = preflight(gate_case)
    assert {"path": "src/cash.py", "status": "refused", "code": "forbidden_token_present"} in report["paths"]
    assert "6729102" not in canonical(report).decode()
    assert hashlib.sha256(normalize_numeric_token("6729102.50").encode()).hexdigest() not in canonical(report).decode()


def test_request_size_and_both_budgets_are_reported_together(gate_case):
    change_policy(gate_case, max_request_bytes=100, max_run_usd=0, daily_budget_usd=0)
    report = preflight(gate_case)
    assert codes(report) == ["gate_request_bytes_exceeded", "run_budget_exceeded", "daily_budget_exceeded"]
    assert report["blockers"][0]["limit"] == 100 and report["blockers"][0]["bytes"] > 100
    assert run(gate_case)[0]["reasons"] == ["gate_request_bytes_exceeded"]


def test_settings_with_no_effect_are_warned(gate_case):
    change_policy(gate_case, deny_paths=["legacy/"], fixture_max_file_bytes=10_000,
                  max_file_bytes=200_000, daily_budget_usd=0.5)
    warnings = {warning["code"]: warning for warning in preflight(gate_case)["warnings"]}
    assert warnings["prefix_matches_nothing"]["prefix"] == "legacy/"
    assert {"fixture_limit_without_roots", "file_limit_above_request_limit", "daily_budget_below_run_budget"} <= set(warnings)


def test_cli_exit_codes_and_option_conflicts(gate_case, capsys):
    argv = ["doctor", "--policy", "gate-policy.json", "--repo", str(gate_case["repo"]),
            "--base", gate_case["base"], "--head", gate_case["head"]]
    assert main(argv) == 0 and json.loads(capsys.readouterr().out)["status"] == "ready"
    assert main([*argv, "--fix"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "doctor_policy_options_conflict"
    assert main(["doctor", "--repo", str(gate_case["repo"])]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "doctor_policy_required"
    assert main(["doctor", "--policy", "gate-policy.json"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "doctor_policy_range_required"


@pytest.mark.parametrize("provider", ["openai", "anthropic", "google", "compatible", "ollama"])
def test_request_payload_is_the_keyed_body_built_without_a_key(provider, monkeypatch):
    config = replace(Config(), provider=provider, model="synthetic-model")
    if provider == "compatible":
        config = replace(config, endpoint="https://models.example/v1/chat/completions",
                         allowed_hosts=("models.example",), api_key_env="REVIEW_PROVIDER_KEY")
    packet, schema = {"files": [{"path": "src/cash.py"}]}, review.review_schema()
    if config.key_name:
        monkeypatch.setenv(config.key_name, KEY_VALUE)
    _, _, keyed = providers.request_shape(config, "synthetic system", packet, schema)
    if config.key_name:
        monkeypatch.delenv(config.key_name)
    payload = providers.request_payload(config, "synthetic system", packet, schema)
    assert payload == keyed and KEY_VALUE not in canonical(payload).decode()


def test_offline_provider_has_no_request_payload():
    with pytest.raises(Exception, match="provider_not_remote"):
        providers.request_payload(Config(), "synthetic system", {"files": []}, {})


class NamesOnly(Mapping):
    """An environment that lists names but fails if any value is looked up."""

    def __init__(self, names):
        self.names = tuple(names)

    def __iter__(self):
        return iter(self.names)

    def __len__(self):
        return len(self.names)

    def __getitem__(self, name):
        raise AssertionError("an environment value was looked up")


def test_key_presence_is_checked_by_name_without_any_value_lookup(gate_case):
    report = preflight(gate_case, environment=NamesOnly(["PATH", "REVIEW_PROVIDER_KEY"]))
    assert report["status"] == "ready" and report["provider"]["key_variable_set"]
    assert codes(preflight(gate_case, environment=NamesOnly(["PATH"]))) == ["provider_key_missing"]


def refuse(*args, **kwargs):
    raise AssertionError("a policy-directed read happened")


def test_a_rejected_pin_reads_nothing_the_policy_selects(gate_case, tmp_path, monkeypatch):
    token = tmp_path / "tokens.txt"
    token.write_text("6729102.50\n", encoding="utf-8")
    change_policy(gate_case, forbidden_token_file=str(token))
    with monkeypatch.context() as patched:
        for name in ("prepare_token_guard", "fixture_settings", "_profile", "load_model_policy",
                     "prepare_model_source", "screen_ignores"):
            patched.setattr(onboarding, name, refuse)
        wrong = preflight(gate_case, pin="0" * 64)
        invalid = preflight(gate_case, pin="not-a-pin")
    assert codes(wrong) == ["gate_policy_pin_mismatch"] and wrong["paths"] == []
    assert codes(invalid) == ["gate_policy_pin_required"] and invalid["policy"]["pin"] == "invalid"
    with monkeypatch.context() as patched:
        for name in ("prepare_token_guard", "load_model_policy", "prepare_model_source"):
            patched.setattr(onboarding, name, refuse)
        discovery = preflight(gate_case, pin=None)
    # Without a pin the observed digest is shown, and the policy's external file is not opened.
    assert discovery["policy"]["sha256"] == gate_case["pin"]
    assert {"code": "gate_policy_pin_required", "field": "/model_review/forbidden_token_file"} in [
        {key: entry[key] for key in ("code", "field")} for entry in discovery["blockers"] if "field" in entry]
    assert {row["status"] for row in discovery["paths"]} == {"unchecked"} and discovery["coverage_complete"] is False


@pytest.mark.parametrize("failure", ["token_file", "ignore_check", "file_count"])
def test_an_unavailable_screening_step_stops_content_reads(gate_case, tmp_path, monkeypatch, failure):
    if failure == "token_file":
        change_policy(gate_case, forbidden_token_file=str(tmp_path / "absent-tokens.txt"))
        expected = "forbidden_token_file_invalid"
    elif failure == "ignore_check":
        def unavailable(*args, **kwargs):
            raise AssistantError("gate_ignore_check_unavailable")
        monkeypatch.setattr(onboarding, "screen_ignores", unavailable)
        expected = "gate_ignore_check_unavailable"
    else:
        change_policy(gate_case, max_files=1)
        (gate_case["repo"] / "src/extra.py").write_text("EXTRA = 1\n", encoding="utf-8")
        command(gate_case["repo"], "add", "src/extra.py")
        command(gate_case["repo"], "commit", "-m", "Synthetic second file")
        gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
        expected = "gate_file_count_exceeded"
    seen, original = [], onboarding.read_entry

    def recording(repo, revision, path, *args, **kwargs):
        seen.append(path)
        return original(repo, revision, path, *args, **kwargs)

    monkeypatch.setattr(onboarding, "read_entry", recording)
    report = preflight(gate_case)
    assert expected in codes(report) and report["status"] == "blocked"
    assert {row["status"] for row in report["paths"]} == {"unchecked"} and report["coverage_complete"] is False
    assert {row["reason"] for row in report["paths"]} == {expected}
    assert not [path for path in seen if path.startswith("src/")]


def test_empty_preflight_options_never_reach_plain_doctor(gate_case, capsys, monkeypatch):
    monkeypatch.setattr(maintenance, "fix_local_state", refuse)
    for argv, code in (
        (["doctor", "--policy", "", "--fix"], "doctor_policy_options_conflict"),
        (["doctor", "--base", ""], "doctor_policy_required"),
        (["doctor", "--policy", "gate-policy.json", "--repo", str(gate_case["repo"]), "--base", "",
          "--head", gate_case["head"]], "doctor_policy_range_required"),
    ):
        assert main(argv) == 2
        assert json.loads(capsys.readouterr().err)["code"] == code


def test_the_next_command_screens_the_repository_argument(gate_case):
    target = gate_case["repo"].parent / ("ghp_" + "a" * 36)
    gate_case["repo"] = gate_case["repo"].rename(target)
    report = preflight(gate_case)
    assert report["status"] == "ready" and report["next_step"]["command"][4] == "<repository>"
    assert "ghp_" not in canonical(report).decode()
