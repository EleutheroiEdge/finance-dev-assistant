"""`init --detect` proposes hidden directories and root dotfiles of reviewable text, never private ones.

Every repository, name and value here is synthetic.
"""

import json

from conftest import command
from finassist.cli import main
from finassist.onboarding import policy_preflight
from finassist.security import canonical, digest

FILES = {
    "src/app.py": "X = 1\n",
    ".github/workflows/ci.yml": "name: ci\non: [push]\njobs: {}\n",
    ".github/CODEOWNERS": "* @synthetic\n",
    ".agent/notes/review.md": "Synthetic review notes.\n",
    ".pre-commit-config.yaml": "repos: []\n",
    ".gitignore": ".finassist/\n",
    # Private by the path policy: never proposed, read or sized.
    ".env": "SYNTHETIC=1\n",
    ".env.local/settings.md": "Synthetic.\n",
    ".aws/config.md": "Synthetic.\n",
    ".secrets/notes.md": "Synthetic.\n",
}


def _repo(tmp_path):
    repo = tmp_path / "hidden"
    repo.mkdir()
    command(repo, "init", "-q", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    for name, text in FILES.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
    command(repo, "add", "-A", "-f")
    command(repo, "commit", "-q", "-m", "Synthetic layout with hidden directories")
    return repo


def _proposal(capsys, repo):
    assert main(["init", "--detect", "--repo", str(repo), "--provider", "openai", "--model", "operator-selected",
                 "--api-key-env", "REVIEW_PROVIDER_KEY", "--input-usd-per-million", "1",
                 "--output-usd-per-million", "2"]) == 0
    return json.loads(capsys.readouterr().out)


def test_hidden_directories_and_root_dotfiles_of_text_are_proposed(tmp_path, capsys):
    proposal = _proposal(capsys, _repo(tmp_path))
    allow = set(proposal["config"]["allow_paths"])
    assert {".github/", ".agent/", ".pre-commit-config.yaml", "src/"} <= allow
    assert allow == set(proposal["gate_policy_draft"]["model_review"]["allow_paths"])
    # Nothing private, and no file the gate never reviews.
    assert not {entry for entry in allow if entry.startswith((".env", ".aws", ".secrets", ".git/", ".gitignore"))}
    evidence = {entry["value"]: entry["rule"] for entry in proposal["evidence"]["allow_paths"]}
    assert evidence[".github/"] == "text_files" and evidence[".pre-commit-config.yaml"] == "root_text_file"


def test_a_change_under_a_hidden_directory_is_ready_with_the_drafted_policy(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    repo = _repo(tmp_path)
    draft = _proposal(capsys, repo)["gate_policy_draft"]
    (repo / "gate-policy.json").write_bytes(canonical(draft))
    command(repo, "add", "gate-policy.json")
    command(repo, "commit", "-q", "-m", "Synthetic reviewed policy")
    base = command(repo, "rev-parse", "HEAD")
    (repo / ".github/workflows/ci.yml").write_text("name: ci\non: [push, pull_request]\njobs: {}\n",
                                                   encoding="utf-8", newline="\n")
    (repo / ".agent/notes/review.md").write_text("Synthetic review notes, revised.\n", encoding="utf-8", newline="\n")
    command(repo, "commit", "-q", "-am", "Synthetic change to workflow and notes")
    report = policy_preflight(repo, base, command(repo, "rev-parse", "HEAD"), "gate-policy.json",
                              digest(canonical(draft)), environment={"REVIEW_PROVIDER_KEY": "fictional"})
    assert report["status"] == "ready", report["blockers"]
    assert {row["status"] for row in report["paths"]} == {"included"}
