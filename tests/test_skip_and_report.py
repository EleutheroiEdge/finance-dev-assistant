"""private_paths: skip-and-report withholds private paths unread and unnamed; refuse stays the default."""

from dataclasses import replace
import json

import pytest

from conftest import command
from test_model_gate import change_policy, run
from finassist import scope
from finassist.cli import main
from finassist.config import Config, save_config
from finassist.errors import AssistantError
from finassist.onboarding import policy_preflight
from finassist.review import review_packet
from finassist.scope import WITHHELD_REASON, build_packet, review_omissions, verify_packet
from finassist.security import canonical, digest, local_name

pytest_plugins = ("test_model_gate", "test_model_policy")
PRIVATE = {
    "data/clients.csv": "name,value\nSynthetic Client,1\n",
    "credentials/vendor.py": "TOKEN_NAME = 'synthetic'\n",
    "src/report.pdf": "synthetic placeholder\n",
}
SKIP = replace(Config(), private_paths="skip-and-report")


@pytest.fixture
def private_range(repository):
    repo, base, _head = repository
    for name, text in PRIVATE.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
    (repo / "src/cash.py").write_text("def balance(opening, deposits):\n    return opening + deposits + 0\n",
                                      encoding="utf-8", newline="\n")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic range with private files")
    return repo, base, command(repo, "rev-parse", "HEAD")


@pytest.fixture
def reads(monkeypatch):
    seen = []
    real = scope.read_entry

    def spy(repo, sha, path, *args, **kwargs):
        seen.append(path)
        return real(repo, sha, path, *args, **kwargs)

    monkeypatch.setattr(scope, "read_entry", spy)
    return seen


def test_refuse_is_the_default_and_is_unchanged(private_range):
    repo, base, head = private_range
    assert Config().private_paths == "refuse"
    with pytest.raises(AssistantError) as raised:
        build_packet(repo, base, head, Config())
    assert raised.value.code in {"private_or_binary_path", "private_path"}


def test_private_paths_are_withheld_before_any_read_and_never_named(private_range, reads):
    repo, base, head = private_range
    names = []
    packet = build_packet(repo, base, head, SKIP, withheld_names=names)
    assert sorted(names) == sorted(PRIVATE)
    assert packet["withheld"] == {"count": 3, "reason": WITHHELD_REASON}
    assert packet["changed_paths"] == ["src/cash.py"] and [f["path"] for f in packet["files"]] == ["src/cash.py"]
    assert not set(reads) & set(PRIVATE)
    encoded = canonical(packet).decode()
    for name in PRIVATE:
        assert name not in encoded
    for fragment in ("clients", "credentials", "vendor", "report.pdf", "Synthetic Client"):
        assert fragment not in encoded
    verify_packet(packet, SKIP)


def test_a_withheld_packet_needs_the_same_setting_to_verify(private_range):
    repo, base, head = private_range
    packet = build_packet(repo, base, head, SKIP)
    with pytest.raises(AssistantError, match="packet_withheld_not_allowed"):
        verify_packet(packet, Config())


@pytest.mark.parametrize("withheld", [
    {"count": 0, "reason": WITHHELD_REASON}, {"count": True, "reason": WITHHELD_REASON},
    {"count": 2001, "reason": WITHHELD_REASON}, {"count": 1, "reason": "other"}, {"count": 1}, [1],
    {"count": 1, "reason": WITHHELD_REASON, "path": "data/clients.csv"},
])
def test_a_malformed_withheld_record_is_refused(private_range, withheld):
    repo, base, head = private_range
    packet = build_packet(repo, base, head, SKIP)
    packet["withheld"] = withheld
    packet["packet_hash"] = digest(canonical({k: v for k, v in packet.items() if k != "packet_hash"}))
    with pytest.raises(AssistantError, match="packet_schema_invalid"):
        verify_packet(packet, SKIP)


def test_a_changed_withheld_count_breaks_the_packet_hash(private_range):
    repo, base, head = private_range
    packet = build_packet(repo, base, head, SKIP)
    packet["withheld"] = {"count": 1, "reason": WITHHELD_REASON}
    with pytest.raises(AssistantError, match="packet_integrity_failed"):
        verify_packet(packet, SKIP)


def test_withheld_paths_keep_every_coverage_check_incomplete(private_range):
    repo, base, head = private_range
    packet = build_packet(repo, base, head, SKIP)
    assert review_omissions(packet) == [{"path": None, "reason": WITHHELD_REASON, "count": 3}]
    assert scope.triage(packet, SKIP)["coverage_complete"] is False


def test_an_offline_review_of_the_rest_is_partial_and_counts_the_withheld(private_range, tmp_path):
    repo, base, head = private_range
    packet = build_packet(repo, base, head, SKIP)
    report = review_packet(packet, SKIP, tmp_path / "audit")
    assert report["withheld"] == {"count": 3, "reason": WITHHELD_REASON}
    assert all(name not in canonical(report).decode() for name in PRIVATE)


def test_a_name_that_is_itself_sensitive_still_refuses(repository):
    repo, base, _head = repository
    name = "data/ghp_" + "a" * 36 + ".csv"
    (repo / "data").mkdir()
    (repo / name).write_text("x\n", encoding="utf-8")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic sensitive name")
    with pytest.raises(AssistantError, match="sensitive_content"):
        build_packet(repo, base, command(repo, "rev-parse", "HEAD"), SKIP)


def test_a_range_of_only_private_paths_has_nothing_to_review(repository, tmp_path):
    repo, base, _head = repository
    (repo / "data").mkdir()
    (repo / "data/master.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic private-only range")
    candidate = command(repo, "rev-parse", "HEAD")
    parent = command(repo, "rev-parse", "HEAD~1")
    packet = build_packet(repo, parent, candidate, SKIP)
    assert packet["changed_paths"] == [] and packet["withheld"]["count"] == 1
    with pytest.raises(AssistantError, match="review_scope_entirely_withheld"):
        review_packet(packet, SKIP, tmp_path / "audit")


def test_plan_names_withheld_paths_only_in_its_local_summary(private_range, tmp_path, capsys):
    repo, base, head = private_range
    config_path, output = tmp_path / "finassist.json", tmp_path / "packet.json"
    save_config(config_path, SKIP)
    assert main(["--config", str(config_path), "--audit-dir", str(tmp_path / "audit"), "plan", "--repo", str(repo),
                 "--base", base, "--head", head, "--output", str(output)]) == 0
    summary = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert sorted(summary["withheld_paths"]) == sorted(PRIVATE)
    assert summary["triage"]["coverage_complete"] is False
    saved = output.read_text(encoding="utf-8")
    assert all(name not in saved for name in PRIVATE)


def test_local_names_are_redacted_by_the_shared_rule():
    assert local_name("data/clients.csv") == "data/clients.csv"
    for hidden in ("data/x" + chr(0x202E) + "vsc.py", "data/" + chr(0x200B) + "a.csv", "", "a" * 513,
                   "src/ghp_" + "a" * 36 + ".py", "../escape.py"):
        assert local_name(hidden) == "[redacted]", hidden


def _private_gate_candidate(case):
    repo = case["repo"]
    (repo / "src/data").mkdir(exist_ok=True)  # inside the policy's allow_paths, so withholding applies
    (repo / "src/data/clients.csv").write_text("name,value\nSynthetic Client,1\n", encoding="utf-8")
    (repo / "src/cash.py").write_text("def balance(opening, deposits):\n    return opening\n", encoding="utf-8")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic gate candidate with a private file")
    case["head"] = command(repo, "rev-parse", "HEAD")


def test_the_gate_refuses_a_private_path_by_default(gate_case):
    _private_gate_candidate(gate_case)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
    assert "coverage" not in report


def test_the_gate_withholds_a_private_path_and_reports_the_count(gate_case, reads):
    change_policy(gate_case, private_paths="skip-and-report")
    _private_gate_candidate(gate_case)
    report, calls = run(gate_case)
    assert report["verdict"] == "PASS", report["reasons"]
    assert report["coverage"] == {"complete": False, "withheld": 1}
    assert "src/data/clients.csv" not in reads
    request = calls[0].content.decode()
    for fragment in ("clients", "Synthetic Client", "data/"):
        assert fragment not in request and fragment not in canonical(report).decode()


def test_the_preflight_shows_withheld_paths_without_blocking(gate_case):
    change_policy(gate_case, private_paths="skip-and-report")
    _private_gate_candidate(gate_case)
    report = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                              gate_case["pin"])
    rows = {row["path"]: row for row in report["paths"]}
    assert rows["src/data/clients.csv"] == {"path": "src/data/clients.csv", "status": "withheld",
                                            "reason": WITHHELD_REASON}
    assert report["status"] == "ready" and report["coverage_complete"] is False
    assert {"code": "private_paths_withheld", "count": 1} in [
        {key: warning[key] for key in ("code", "count")} for warning in report["warnings"]]


def test_the_policy_schema_accepts_only_the_two_modes(gate_case):
    change_policy(gate_case, private_paths="skip-everything")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls


@pytest.mark.parametrize("config", [Config(), SKIP])
def test_an_ordinary_omission_cannot_borrow_the_withheld_reason(repository, config):
    # The reviewer's case: a rehashed packet whose omitted row claims the withheld reason.
    repo, base, head = repository
    packet = build_packet(repo, base, head, config)
    packet["omitted"] = [{"path": "src/cash.py", "reason": WITHHELD_REASON}]
    packet["files"] = []
    packet["packet_hash"] = digest(canonical({k: v for k, v in packet.items() if k != "packet_hash"}))
    with pytest.raises(AssistantError, match="packet_schema_invalid"):
        verify_packet(packet, config)


@pytest.mark.parametrize("name", ["src/data/notes.py", "src/private/notes.py", "src/client.json"])
def test_plan_withholds_the_gate_private_names_too(repository, reads, name):
    repo, base, _head = repository
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text("synthetic = 1\n", encoding="utf-8")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic private-directory file")
    names = []
    packet = build_packet(repo, base, command(repo, "rev-parse", "HEAD"), SKIP, withheld_names=names)
    assert names == [name] and name not in reads
    assert name not in canonical(packet).decode() and packet["withheld"]["count"] == 1


def test_a_configured_sensitive_name_refuses_instead_of_being_withheld(repository, tmp_path, capsys):
    repo, base, _head = repository
    name = "credentials/SYNTHETIC_PROJECT_TAG.py"
    (repo / "credentials").mkdir()
    (repo / name).write_text("X = 1\n", encoding="utf-8")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic configured-sensitive name")
    config = replace(SKIP, extra_sensitive_patterns=("SYNTHETIC_PROJECT_TAG",))
    with pytest.raises(AssistantError, match="project_content_blocked"):
        build_packet(repo, base, command(repo, "rev-parse", "HEAD"), config)
    config_path = tmp_path / "finassist.json"
    save_config(config_path, config)
    assert main(["--config", str(config_path), "--audit-dir", str(tmp_path / "audit"), "plan", "--repo", str(repo),
                 "--base", base, "--head", command(repo, "rev-parse", "HEAD"), "--output",
                 str(tmp_path / "packet.json")]) == 2
    captured = capsys.readouterr()
    assert "SYNTHETIC_PROJECT_TAG" not in captured.out + captured.err


def test_local_names_honour_configured_patterns():
    assert local_name("src/SYNTHETIC_PROJECT_TAG.py", ("SYNTHETIC_PROJECT_TAG",)) == "[redacted]"
    assert local_name("src/SYNTHETIC_PROJECT_TAG.py") == "src/SYNTHETIC_PROJECT_TAG.py"


def _gate_change(case, files):
    repo = case["repo"]
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic gate change")
    case["head"] = command(repo, "rev-parse", "HEAD")


def test_the_gate_withholds_a_private_path_outside_allow_paths(gate_case, reads):
    """allow_paths admits files for review; a withheld file is not reviewed, as in plan and review."""
    change_policy(gate_case, private_paths="skip-and-report")
    _gate_change(gate_case, {"data/prices.csv": "day,price\n1,2\n", "zq_area/private/notes.md": "Synthetic.\n"})
    report, calls = run(gate_case)
    assert report["verdict"] == "PASS", report["reasons"]
    assert report["coverage"] == {"complete": False, "withheld": 2}
    assert not {"data/prices.csv", "zq_area/private/notes.md"} & set(reads)
    request = calls[0].content.decode()
    for fragment in ("prices.csv", "zq_area", "day,price", "Synthetic."):
        assert fragment not in request and fragment not in canonical(report).decode()
    preflight = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                                 gate_case["pin"])
    rows = {row["path"]: row for row in preflight["paths"]}
    for name in ("data/prices.csv", "zq_area/private/notes.md"):
        assert rows[name] == {"path": name, "status": "withheld", "reason": WITHHELD_REASON}
    assert preflight["status"] == "ready" and preflight["coverage_complete"] is False


def test_refuse_still_refuses_a_private_path_outside_allow_paths(gate_case):
    _gate_change(gate_case, {"data/prices.csv": "day,price\n1,2\n"})
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
    assert len(report["reasons"]) == 1 and report["reasons"][0] in scope.WITHHELD_CODES


def test_a_reviewable_file_outside_allow_paths_still_refuses_beside_a_withheld_one(gate_case):
    change_policy(gate_case, private_paths="skip-and-report", allow_paths=["tests/"])
    _gate_change(gate_case, {"data/prices.csv": "day,price\n1,2\n"})
    # The fixture's own change to src/cash.py is now outside allow_paths and is not private: it refuses.
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["gate_path_not_allowed"] and not calls


@pytest.mark.parametrize("changes, files, code", [
    ({"allow_paths": ["src/", "tests/"], "deny_paths": ["src/data/"]},
     {"src/data/notes.py": "X = 1\n", "tests/test_a.py": "def test_a():\n    pass\n"}, "gate_denied_path"),
    ({"deny_paths": ["data/"]}, {"data/a.csv": "a,b\n1,2\n"}, "gate_denied_path"),
    ({}, {"notes/plan.md": "Synthetic.\n"}, "gate_path_not_allowed"),
])
def test_a_private_path_still_meets_the_policy_boundaries(gate_case, changes, files, code):
    change_policy(gate_case, private_paths="skip-and-report", **changes)
    _gate_change(gate_case, files)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == [code] and not calls
    preflight = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                                 gate_case["pin"])
    assert code in {row.get("code") for row in preflight["paths"]}
    assert not any(row["status"] == "withheld" for row in preflight["paths"])


def test_the_action_summary_and_outputs_show_incomplete_coverage(gate_case, tmp_path):
    from finassist.github_actions import publish_action_report, summary_markdown

    change_policy(gate_case, private_paths="skip-and-report")
    _private_gate_candidate(gate_case)
    report, _calls = run(gate_case)
    assert report["verdict"] == "PASS" and report["coverage"]["withheld"] == 1
    summary = summary_markdown(report)
    assert "Coverage: **incomplete**" in summary and "1 changed file(s) were withheld" in summary
    assert "clients" not in summary and "data/" not in summary
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    publish_action_report(report, report_path, tmp_path / "summary.md", tmp_path / "outputs")
    outputs = dict(line.split("=", 1) for line in (tmp_path / "outputs").read_text(encoding="utf-8").splitlines())
    assert outputs["withheld-count"] == "1" and outputs["coverage-complete"] == "false"


def test_a_complete_review_reports_complete_coverage_in_the_outputs(gate_case, tmp_path):
    from finassist.github_actions import publish_action_report, summary_markdown

    report, _calls = run(gate_case)
    assert "Coverage" not in summary_markdown(report)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    publish_action_report(report, report_path, tmp_path / "summary.md", tmp_path / "outputs")
    outputs = dict(line.split("=", 1) for line in (tmp_path / "outputs").read_text(encoding="utf-8").splitlines())
    assert outputs["withheld-count"] == "0" and outputs["coverage-complete"] == "true"


def test_the_preflight_never_shows_a_configured_sensitive_withheld_name(repository):
    # The reviewer's case: a withheld name that matches a configured pattern.
    from finassist import onboarding

    repo, base, _head = repository
    name = "src/data/SYNTHETIC_PROJECT_TAG.py"
    (repo / "src/data").mkdir()
    (repo / name).write_text("X = 1\n", encoding="utf-8")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic configured-sensitive private name")
    head = command(repo, "rev-parse", "HEAD")
    config = replace(SKIP, allow_paths=("src/",), extra_sensitive_patterns=("SYNTHETIC_PROJECT_TAG",))
    preflight = onboarding._Preflight(repo, base, head, "gate-policy.json", None, {})
    row = preflight._classify(repo, (base, head), name, {"deny_paths": []}, config, None, set(), None)
    assert row == {"path": "[redacted]", "status": "refused", "code": "project_content_blocked"}
    assert "SYNTHETIC_PROJECT_TAG" not in canonical(row).decode()
