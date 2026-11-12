"""doctor --policy-file checks a past range against a policy on this machine, and authorizes nothing."""

import json
from pathlib import Path

import pytest

from conftest import command
from test_model_policy import model_policy
from finassist.cli import main
from finassist.config import Config, save_config
from finassist.onboarding import policy_preflight
from finassist.security import canonical, digest

pytest_plugins = ("test_model_gate", "test_model_policy")
KEY_VALUE = "fictional-provider-value"


@pytest.fixture
def past_range(repository, tmp_path, monkeypatch):
    """A merged range whose base holds no policy, and a policy file outside the repository."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", KEY_VALUE)
    repo, base, head = repository
    policy = tmp_path / "policies" / "gate-policy.json"
    policy.parent.mkdir()
    policy.write_bytes(canonical(model_policy()))
    return {"repo": repo, "base": base, "head": head, "file": policy, "sha": digest(canonical(model_policy()))}


def from_file(case, pin=None, file=None):
    report = policy_preflight(case["repo"], case["base"], case["head"], "", pin,
                              policy_file=str(file or case["file"]))
    assert KEY_VALUE not in canonical(report).decode()
    assert not report["network_used"] and not report["key_values_returned"] and not report["ledger_opened"]
    return report


def codes(report) -> list[str]:
    return [entry["code"] for entry in report["blockers"]]


def test_a_past_range_is_checked_against_a_policy_file(past_range):
    report = from_file(past_range)
    assert report["status"] == "ready" and report["blockers"] == []
    assert report["policy"]["source"] == "working-tree" and report["policy"]["sha256"] == past_range["sha"]
    assert "policy_from_working_tree" in [warning["code"] for warning in report["warnings"]]
    assert "policy_pin_not_supplied" not in [warning["code"] for warning in report["warnings"]]
    assert report["paths"] == [{"path": "src/cash.py", "status": "included"}]
    assert report["request"]["bytes"] > 0  # The gate's own source builder ran.


def test_a_ready_policy_file_gets_no_gate_run_command(past_range):
    report = from_file(past_range)
    assert isinstance(report["next_step"], str)
    assert "--policy" in report["next_step"] and "base" in report["next_step"]


def test_the_base_route_still_needs_the_policy_at_base(past_range):
    report = policy_preflight(past_range["repo"], past_range["base"], past_range["head"], "gate-policy.json")
    assert codes(report) == ["gate_policy_missing_at_base"]
    assert "--policy-file" in report["blockers"][0]["hint"]
    assert report["policy"]["source"] == "base"


def test_a_pin_is_checked_against_the_file(past_range):
    assert from_file(past_range, pin=past_range["sha"])["policy"]["pin"] == "matches"
    report = from_file(past_range, pin="0" * 64)
    assert report["status"] == "blocked" and "gate_policy_pin_mismatch" in codes(report)


def test_an_oversized_policy_file_is_refused_after_a_bounded_read(past_range, tmp_path, monkeypatch):
    oversized = tmp_path / "oversized-policy.json"
    oversized.write_bytes(b" " * 300_000)
    requested, real_open = [], Path.open

    class Spy:
        def __init__(self, handle):
            self.handle = handle

        def read(self, size=-1):
            requested.append(size)
            return self.handle.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.handle.close()

    def spied_open(path, *args, **kwargs):
        handle = real_open(path, *args, **kwargs)
        return Spy(handle) if path.name == oversized.name else handle

    monkeypatch.setattr(Path, "open", spied_open)
    monkeypatch.setattr(Path, "read_bytes", lambda path: pytest.fail("the whole file must never be read"))
    report = from_file(past_range, file=oversized)
    assert codes(report) == ["file_limit_exceeded"]
    assert report["blockers"][0]["limit"] == 128_000 and report["blockers"][0]["bytes"] == 300_000
    assert requested == [128_001]


def test_a_missing_policy_file_is_named(past_range, tmp_path):
    report = from_file(past_range, file=tmp_path / "absent.json")
    assert codes(report) == ["policy_file_unavailable"]


def test_a_policy_file_changed_by_the_range_still_stops_it(past_range):
    repo = past_range["repo"]
    inside = repo / "ops" / "gate-policy.json"
    inside.parent.mkdir()
    inside.write_bytes(canonical(model_policy()))
    command(repo, "add", "ops/gate-policy.json")
    command(repo, "commit", "-q", "-m", "Synthetic range that adds the policy")
    case = {**past_range, "head": command(repo, "rev-parse", "HEAD")}
    report = from_file(case, file=inside)
    assert "gate_policy_change_requires_review" in codes(report)


def test_doctor_takes_a_policy_file_but_gate_run_does_not(past_range, tmp_path, capsys):
    repo, base, head, file = past_range["repo"], past_range["base"], past_range["head"], str(past_range["file"])
    assert main(["doctor", "--policy-file", file, "--repo", str(repo), "--base", base, "--head", head]) == 0
    assert json.loads(capsys.readouterr().out)["policy"]["source"] == "working-tree"
    assert main(["doctor", "--policy", "gate-policy.json", "--policy-file", file,
                 "--repo", str(repo), "--base", base, "--head", head]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "doctor_policy_source_conflict"
    with pytest.raises(SystemExit) as exited:
        main(["gate", "run", "--repo", str(repo), "--base", base, "--head", head, "--policy", "gate-policy.json",
              "--policy-file", file, "--policy-sha256", past_range["sha"], "--state-dir", str(tmp_path / "state"),
              "--output", str(tmp_path / "report.json")])
    assert exited.value.code == 2 and "--policy-file" in capsys.readouterr().err


def test_a_configuration_given_as_a_policy_is_named(past_range, tmp_path):
    configuration = tmp_path / "finassist.json"
    save_config(configuration, Config())
    assert codes(from_file(past_range, file=configuration)) == ["gate_policy_is_configuration"]


def test_a_committed_configuration_given_as_a_policy_is_named(policy_case):
    document = json.loads(canonical({"schema_version": 1, "provider": "offline", "allow_paths": ["src/"]}))
    repo, base, pin = policy_case(document)
    report = policy_preflight(repo, base, base, "gate-policy.json", pin)
    assert codes(report) == ["gate_policy_is_configuration"]


@pytest.mark.parametrize("document,code", [
    (model_policy(), "config_is_gate_policy"),
    ({"schema_version": 1, "repository": "example/synthetic", "events": ["pull_request"], "base_branches": ["main"]},
     "config_is_ci_policy"),
])
def test_config_names_a_policy_given_in_its_place(tmp_path, capsys, document, code):
    path = tmp_path / "policy.json"
    path.write_bytes(canonical(document))
    assert main(["--config", str(path), "doctor"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == code
