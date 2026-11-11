"""A gate policy may deny a private path, and `init --detect` drafts a policy the gate accepts.

Every repository, name and value here is synthetic.
"""

import json

import pytest

from conftest import command
from finassist.cli import main
from finassist.onboarding import policy_preflight
from finassist.security import canonical, digest
from test_model_gate import change_policy, run

pytest_plugins = ("test_model_gate", "test_model_policy")

# Names the path policy or the gate's private names refuse for review.
PRIVATE_ENTRIES = [".env.example", "web/.env.example", "research/holdings/", "workspace/USER.md", "docs/uploads/",
                   "src/data/", "src/client.json", "exports/positions.csv"]


@pytest.mark.parametrize("entry", PRIVATE_ENTRIES)
def test_a_policy_may_deny_a_private_path(gate_case, entry):
    change_policy(gate_case, deny_paths=[entry])
    report, calls = run(gate_case)
    assert report["verdict"] == "PASS" and len(calls) == 1 and not report["reasons"]


@pytest.mark.parametrize("entry,code", [
    ("src/**", "gate_policy_path_invalid"), ("../outside/", "unsafe_path"), ("/absolute/", "unsafe_path"),
    ("src//twice/", "unsafe_path"), ("ghp_" + "a" * 36 + "/", "sensitive_content"),
])
def test_a_deny_entry_still_needs_a_safe_literal_path(gate_case, entry, code):
    change_policy(gate_case, deny_paths=[entry])
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == [code] and not calls


@pytest.mark.parametrize("entry", [".env.example", "web/.env.example", "research/holdings/", "workspace/USER.md",
                                   "docs/uploads/", "exports/positions.csv"])
def test_an_allow_entry_still_meets_the_path_policy(gate_case, entry):
    change_policy(gate_case, allow_paths=["src/", entry])
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
    assert report["reasons"][0] in {"private_path", "private_profile_path", "private_or_binary_path"}


def test_a_denied_private_file_refuses_even_under_skip_and_report(gate_case):
    change_policy(gate_case, deny_paths=["src/.env.example"], private_paths="skip-and-report")
    (gate_case["repo"] / "src/.env.example").write_text("SYNTHETIC=1\n", encoding="utf-8", newline="\n")
    command(gate_case["repo"], "add", "-f", "src/.env.example")
    command(gate_case["repo"], "commit", "-q", "-m", "Synthetic private file in a denied path")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["gate_denied_path"] and not calls


def test_the_preflight_accepts_a_denied_private_path(gate_case):
    change_policy(gate_case, deny_paths=["web/.env.example", "workspace/USER.md"])
    report = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                              gate_case["pin"], environment={"REVIEW_PROVIDER_KEY": "fictional"})
    assert report["status"] == "ready", report["blockers"]


def _repo(tmp_path, files):
    repo = tmp_path / "detected"
    repo.mkdir()
    command(repo, "init", "-q", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
    command(repo, "add", "-A", "-f")
    command(repo, "commit", "-q", "-m", "Synthetic layout")
    return repo


PRIVATE_FILES = {"web/.env.example": "SYNTHETIC=1\n", "research/holdings/notes.md": "Synthetic.\n",
                 "workspace/USER.md": "Synthetic.\n", "src/client.json": "{}\n", "src/data/rows.py": "ROWS = 1\n",
                 "web/app.ts": "export const x = 1;\n", "research/readme.md": "Synthetic.\n",
                 "workspace/notes.md": "Synthetic.\n"}


def test_the_detected_policy_is_one_the_gate_accepts(tmp_path, capsys, monkeypatch):
    """Private files inside reviewed directories once produced deny entries that refused the whole policy."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    repo = _repo(tmp_path, {"src/app.py": "X = 1\n", **PRIVATE_FILES})
    assert main(["init", "--detect", "--repo", str(repo), "--provider", "openai", "--model", "operator-selected",
                 "--api-key-env", "REVIEW_PROVIDER_KEY", "--input-usd-per-million", "1",
                 "--output-usd-per-million", "2"]) == 0
    proposal = json.loads(capsys.readouterr().out)
    draft = proposal["gate_policy_draft"]
    assert draft["model_review"]["deny_paths"] == [] and proposal["gate_policy_missing"] == []
    assert proposal["private_paths"]["count"] == 5
    warnings = {item["code"]: item for item in proposal["warnings"]}
    assert warnings["private_paths_inside_scope"]["count"] == 5 and "private_paths_outside_scope" not in warnings
    # Commit the draft, change a reviewed file, and run the gate's own preflight on that range.
    (repo / "gate-policy.json").write_bytes(canonical(draft))
    command(repo, "add", "gate-policy.json")
    command(repo, "commit", "-q", "-m", "Synthetic reviewed policy")
    base = command(repo, "rev-parse", "HEAD")
    (repo / "src/app.py").write_text("X = 2\n", encoding="utf-8", newline="\n")
    command(repo, "commit", "-q", "-am", "Synthetic change")
    report = policy_preflight(repo, base, command(repo, "rev-parse", "HEAD"), "gate-policy.json",
                              digest(canonical(draft)), environment={"REVIEW_PROVIDER_KEY": "fictional"})
    assert report["status"] == "ready", report["blockers"]
