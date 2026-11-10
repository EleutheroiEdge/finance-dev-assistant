"""A range larger than the earlier 2,000,000-byte ceiling, on both routes. Synthetic source only."""

from dataclasses import replace
import json

import pytest

from conftest import command
from test_model_gate import change_policy, run
from test_providers_review import envelope
from finassist.cli import main
from finassist.config import MAX_PACKET_BYTES, Config, save_config
from finassist.errors import AssistantError
from finassist.model_policy import load_model_policy
from finassist.onboarding import policy_preflight

pytest_plugins = ("test_model_policy", "test_model_gate")
LINE = "value = compute_total(opening_balance, deposits, withdrawals)  # synthetic line {index:06d}\n"
LARGE = {"max_request_bytes": 4_000_000, "max_file_bytes": 200_000, "max_files": 50, "max_run_usd": 1000,
         "daily_budget_usd": 1000}


def _module(seed: int, lines: int = 1400) -> str:
    """About 126 KB of synthetic source."""
    return "".join(LINE.format(index=seed * 10_000 + number) for number in range(lines))


def _write(repo, texts: dict, message: str) -> str:
    for name, text in texts.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", message)
    return command(repo, "rev-parse", "HEAD")


def _modules(count: int, suffix: str = "") -> dict:
    return {f"src/module_{number:02d}.py": _module(number) + suffix for number in range(count)}


@pytest.fixture
def large_range(repository):
    """Twelve modified modules: about 3 MB of earlier and later text for a diff of twelve lines."""
    repo, _base, _head = repository
    base = _write(repo, _modules(12), "Synthetic large baseline")
    return repo, base, _write(repo, _modules(12, "extra = 1\n"), "Synthetic large change")


def _config(tmp_path, **changes):
    path = tmp_path / "finassist.json"
    save_config(path, replace(Config(), max_file_bytes=200_000, **changes))
    return str(path)


def test_the_ceiling_is_stated_once_and_the_other_limits_keep_theirs():
    assert MAX_PACKET_BYTES == 8_000_000
    replace(Config(), max_packet_bytes=MAX_PACKET_BYTES).validate()
    for option, value, maximum in (("max_packet_bytes", MAX_PACKET_BYTES + 1, MAX_PACKET_BYTES),
                                   ("max_file_bytes", 2_000_001, 2_000_000),
                                   ("max_output_tokens", 2_000_001, 2_000_000)):
        with pytest.raises(AssistantError) as caught:
            replace(Config(), **{option: value}).validate()
        assert caught.value.code == "invalid_limit"
        assert caught.value.public_details == {"option": option, "minimum": 1, "maximum": maximum}
    assert Config().max_packet_bytes == 120_000  # The default did not move.


def test_plan_and_review_handle_a_packet_over_two_megabytes(large_range, tmp_path, capsys):
    repo, base, head = large_range
    config = _config(tmp_path, max_packet_bytes=4_000_000)
    packet, report = tmp_path / "packet.json", tmp_path / "review.json"
    shared = ["--config", config, "--audit-dir", str(tmp_path / "audit")]
    assert main([*shared, "plan", "--repo", str(repo), "--base", base, "--head", head, "--output", str(packet)]) == 0
    assert 2_000_000 < packet.stat().st_size < 4_000_000
    capsys.readouterr()
    assert main([*shared, "review", "--packet", str(packet), "--output", str(report)]) == 0
    result = json.loads(report.read_text(encoding="utf-8"))
    assert result["status"] == "offline-analysis" and result["head"] == head


def test_a_smaller_limit_still_refuses_the_same_range_with_both_figures(large_range, tmp_path, capsys):
    repo, base, head = large_range
    config = _config(tmp_path, max_packet_bytes=2_000_000)
    assert main(["--config", config, "--audit-dir", str(tmp_path / "audit"), "plan", "--repo", str(repo),
                 "--base", base, "--head", head, "--output", str(tmp_path / "packet.json")]) == 2
    record = json.loads(capsys.readouterr().err)
    assert record["code"] == "packet_limit_exceeded" and record["limit"] == 2_000_000
    assert 2_000_000 < record["bytes"] < 4_000_000
    assert "8,000,000" in record["hint"]


def test_the_range_preflight_reports_a_large_packet_as_ready(large_range, tmp_path, capsys):
    repo, base, head = large_range
    config = _config(tmp_path, max_packet_bytes=4_000_000)
    assert main(["--config", config, "doctor", "--repo", str(repo), "--base", base, "--head", head]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "ready" and 2_000_000 < report["packet"]["bytes"] < report["packet"]["limit"]


def _clean_review(packet):
    """A model answer that covers every file in the packet and finds nothing."""
    return envelope(json.dumps({"head": packet["head"], "summary": "No findings.",
                                "reviewed_paths": [file["path"] for file in packet["files"]], "findings": []}))


def _large_gate_change(case):
    """Twenty new modules: about 2.5 MB in one request."""
    case["head"] = _write(case["repo"], _modules(20), "Synthetic large gate candidate")


def test_a_gate_sends_a_request_over_two_megabytes_when_its_policy_states_the_limit(gate_case):
    change_policy(gate_case, **LARGE)
    _large_gate_change(gate_case)
    preflight = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                                 gate_case["pin"])
    assert preflight["status"] == "ready", preflight["blockers"]
    assert 2_000_000 < preflight["request"]["bytes"] <= preflight["request"]["limit"] == 4_000_000
    report, calls = run(gate_case, _clean_review)
    assert report["verdict"] == "PASS", report["reasons"]
    assert len(calls) == 1 and len(calls[0].content) == preflight["request"]["bytes"]


def test_a_policy_at_or_under_the_earlier_ceiling_keeps_its_packet_bound(gate_case):
    """So the configuration a gate derives from such a policy, and its hash, are what they were."""
    policy = load_model_policy(gate_case["repo"], gate_case["base"], "gate-policy.json", gate_case["pin"])
    assert policy.config.max_packet_bytes == 2_000_000
    change_policy(gate_case, **LARGE)
    policy = load_model_policy(gate_case["repo"], gate_case["base"], "gate-policy.json", gate_case["pin"])
    assert policy.config.max_packet_bytes == 4_000_000


def test_a_gate_still_refuses_a_request_over_its_own_limit(gate_case):
    change_policy(gate_case, **{**LARGE, "max_request_bytes": 2_000_000})
    _large_gate_change(gate_case)
    report, calls = run(gate_case, _clean_review)
    assert report["verdict"] == "BLOCKED" and not calls
    assert report["reasons"] in (["packet_limit_exceeded"], ["gate_request_bytes_exceeded"])
