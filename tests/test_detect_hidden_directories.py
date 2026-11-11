"""`init --detect` proposes hidden directories and root dotfiles of reviewable text, never private ones.

Every repository, name and value here is synthetic.
"""

import base64
import json
import subprocess

import pytest

from conftest import command
from finassist import detect as detect_module
from finassist.cli import main
from finassist.onboarding import policy_preflight
from finassist.scope import WITHHELD_REASON
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


LARGE = "SYNTHETIC = 1\n" * 30_000  # About 420 KB: it would lift every limit if it were sized.
PUBLIC = {".docker/compose.yml": "services: {}\n", ".config/nextest.toml": "[profile.default]\n"}
# Private by a hidden spelling of a private name, at any depth, or as a credential store. Shapes
# only: no value here is a credential.
NESTED = {
    ".github/.secrets/config.py": LARGE,
    ".github/.data/rows.py": LARGE,
    ".github/.credentials/login.py": LARGE,
    "src/.private/notes.py": LARGE,
    ".docker/config.json": json.dumps({"auths": {"registry.invalid": {
        "auth": base64.b64encode(b"synthetic:synthetic").decode("ascii")}}}) + "\n",
    ".config/gh/hosts.yml": "github.invalid:\n    user: synthetic\n",
    ".config/gcloud/application_default_credentials.json": "{}\n",
    ".kube/config.yaml": "apiVersion: v1\nkind: Config\n",
    ".claude/.credentials.json": "{}\n",
}
INSIDE = 7  # Of NESTED, the files under a directory the proposal allows: .github/, src/, .docker/ and .config/.


def _repo(tmp_path, files=None):
    repo = tmp_path / "hidden"
    repo.mkdir(parents=True)
    command(repo, "init", "-q", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    for name, text in (FILES if files is None else files).items():
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


def _change(repo, files):
    for name, content in files.items():
        (repo / name).write_text(content, encoding="utf-8", newline="\n")
    command(repo, "add", "-A", "-f")
    command(repo, "commit", "-q", "-m", "Synthetic change")
    return command(repo, "rev-parse", "HEAD")


def test_private_files_under_hidden_directories_are_never_read_sized_or_counted_toward_a_limit(
        tmp_path, capsys, monkeypatch):
    plain = _repo(tmp_path / "plain", {**FILES, **PUBLIC})
    _change(plain, {"src/app.py": "X = 2\n"})
    expected = _proposal(capsys, plain)
    repo = _repo(tmp_path / "stores", {**FILES, **PUBLIC, **NESTED})
    _change(repo, {"src/app.py": "X = 2\n", **{name: "SYNTHETIC = 2\n" * 31_000 for name in NESTED}})
    private_blobs = {command(repo, "rev-parse", f"{revision}:{name}") for revision in ("HEAD", "HEAD~1")
                     for name in NESTED}
    reads, sized = [], []
    real_git, real_run = detect_module.git, subprocess.run

    def spy(repository, *args, **kwargs):
        if args[:2] == ("cat-file", "blob"):
            reads.append(args[2].split(":", 1)[1])
        return real_git(repository, *args, **kwargs)

    def recording(argv, *args, **kwargs):
        if "--batch-check" in argv:
            sized.extend(kwargs["input"].decode("ascii").split())
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(detect_module, "git", spy)
    monkeypatch.setattr(detect_module.subprocess, "run", recording)
    proposal = _proposal(capsys, repo)
    monkeypatch.undo()
    # No private blob is asked for, by content or by size.
    assert "src/app.py" in reads and not set(reads) & set(NESTED)
    assert sized and not set(sized) & private_blobs
    # The proposal is the one the same repository gets without them: the same scope and the same limits.
    assert proposal["config"] == expected["config"]
    assert proposal["gate_policy_draft"] == expected["gate_policy_draft"]
    allow = set(proposal["config"]["allow_paths"])
    assert {".github/", ".docker/", ".config/"} <= allow and not {".kube/", ".claude/"} & allow
    assert all(entry["path"] not in NESTED for entries in proposal["evidence"].values() for entry in entries
               if isinstance(entry, dict) and "path" in entry)
    # They are counted, and the person is told some sit inside the proposed scope.
    assert proposal["private_paths"]["count"] == expected["private_paths"]["count"] + len(NESTED)
    warnings = {entry["code"]: entry for entry in proposal["warnings"]}
    assert warnings["private_paths_inside_scope"]["count"] == INSIDE
    assert (warnings["private_paths_outside_scope"]["count"]
            == expected["private_paths"]["count"] + len(NESTED) - INSIDE)


@pytest.mark.parametrize("mode", ["refuse", "skip-and-report"])
def test_a_private_file_under_an_allowed_hidden_directory_is_refused_or_withheld_never_reviewed(
        tmp_path, capsys, monkeypatch, mode):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    repo = _repo(tmp_path, {**FILES, **PUBLIC, **NESTED})
    draft = _proposal(capsys, repo)["gate_policy_draft"]
    assert {".github/", ".docker/", ".config/"} <= set(draft["model_review"]["allow_paths"])
    draft["model_review"]["private_paths"] = mode
    (repo / "gate-policy.json").write_bytes(canonical(draft))
    command(repo, "add", "gate-policy.json")
    command(repo, "commit", "-q", "-m", "Synthetic reviewed policy")
    base = command(repo, "rev-parse", "HEAD")
    private = [".config/gh/hosts.yml", ".docker/config.json", ".github/.secrets/config.py"]
    head = _change(repo, {".docker/compose.yml": "services:\n  app: {}\n", ".docker/config.json": "{}\n",
                          ".github/.secrets/config.py": "SYNTHETIC = 3\n",
                          ".config/gh/hosts.yml": "github.invalid:\n    user: other\n"})
    report = policy_preflight(repo, base, head, "gate-policy.json", digest(canonical(draft)),
                              environment={"REVIEW_PROVIDER_KEY": "fictional"})
    rows = {row["path"]: row for row in report["paths"]}
    assert all(rows[name]["status"] != "included" for name in private)
    if mode == "refuse":
        assert report["status"] == "blocked" and {entry["code"] for entry in report["blockers"]} == {"private_path"}
        assert all(rows[name] == {"path": name, "status": "refused", "code": "private_path"} for name in private)
    else:
        assert report["status"] == "ready" and report["coverage_complete"] is False
        assert all(rows[name] == {"path": name, "status": "withheld", "reason": WITHHELD_REASON} for name in private)
        assert rows[".docker/compose.yml"]["status"] == "included"


def test_a_fixture_root_the_gate_would_refuse_is_never_drafted(tmp_path, capsys):
    rows = "day,price\n1,2\n"
    repo = _repo(tmp_path, {"src/app.py": "X = 1\n", "tests/fixtures/prices.csv": rows,
                            "tests/.data/prices.csv": rows, "tests/.secrets/prices.csv": rows,
                            "tests/fixtures/.private/prices.csv": rows})
    proposal = _proposal(capsys, repo)
    assert proposal["gate_policy_draft"]["model_review"]["fixture_roots"] == ["tests/fixtures/"]
    assert proposal["private_paths"]["count"] == 4
