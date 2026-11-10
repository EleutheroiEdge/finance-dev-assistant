"""Guard repository automation permissions and safe contributor entry points."""

import importlib.util
from pathlib import Path
import re
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


def document(name):
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def events(workflow):
    return workflow.get("on", workflow.get(True))


def test_weekly_dependency_updates_cover_all_manifests():
    config = document(".github/dependabot.yml")
    assert config["version"] == 2
    assert {(row["package-ecosystem"], row["directory"]) for row in config["updates"]} == {
        ("pip", "/"), ("npm", "/dashboard"), ("github-actions", "/")
    }
    for row in config["updates"]:
        assert row["schedule"]["interval"] == "weekly"
        assert list(row["groups"].values()) == [{"patterns": ["*"]}]


HASHED = "anyio==4.15.1 \\\n    --hash=sha256:" + "0" * 64 + "\n"


def dependabot_requirements_script():
    path = ROOT / "scripts/dependabot_requirements.py"
    spec = importlib.util.spec_from_file_location("dependabot_requirements", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dependabot_entry_point_is_the_reviewed_lock_with_no_include():
    module = dependabot_requirements_script()
    lock = (ROOT / "requirements-dev.lock").read_text(encoding="utf-8")
    entry = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert entry == module.dependabot_requirements(lock)
    assert entry.endswith(lock) and entry[: -len(lock)] == module.HEADER
    # Dependabot fetches an included file only when its name ends in .txt or .in. With any other
    # include, pip fails to open the missing file and every Dependabot pip job fails.
    assert not module.INCLUDE.search(entry)
    assert all(line.startswith("#") for line in module.HEADER.splitlines())


@pytest.mark.parametrize("include", [
    "-r requirements-dev.lock", "-rother.txt", "  -c constraints.txt", "--requirement=other.txt",
    "--constraint other.txt",
])
def test_dependabot_entry_point_refuses_a_lock_that_needs_another_file(include):
    module = dependabot_requirements_script()
    assert module.dependabot_requirements(HASHED) == module.HEADER + HASHED
    with pytest.raises(ValueError, match="includes another requirements file"):
        module.dependabot_requirements(include + "\n" + HASHED)
    with pytest.raises(ValueError, match="not hashed"):
        module.dependabot_requirements("anyio==4.15.1\n")


def test_dependabot_entry_point_script_writes_and_checks(tmp_path, monkeypatch):
    module = dependabot_requirements_script()
    (tmp_path / "requirements-dev.lock").write_text(HASHED, encoding="utf-8", newline="\n")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["dependabot_requirements.py"])
    module.main()
    assert (tmp_path / "requirements.txt").read_bytes() == (module.HEADER + HASHED).encode()
    monkeypatch.setattr(sys, "argv", ["dependabot_requirements.py", "--check"])
    module.main()
    (tmp_path / "requirements.txt").write_text("-r requirements-dev.lock\n", encoding="utf-8", newline="\n")
    with pytest.raises(SystemExit, match="drifted"):
        module.main()


def test_scanners_are_pinned_with_bounded_permissions():
    codeql = document(".github/workflows/codeql.yml")
    scorecard = document(".github/workflows/scorecard.yml")
    assert codeql["jobs"]["analyze"]["strategy"]["matrix"]["language"] == ["python", "javascript-typescript"]
    assert "pull_request" in events(codeql)
    assert "pull_request_target" not in events(codeql)
    assert set(events(scorecard)) == {"push", "schedule"}
    assert events(scorecard)["push"] == {"branches": ["main"]}
    for workflow in [codeql, scorecard]:
        assert workflow["permissions"] == {"contents": "read"}
        for name, job in workflow["jobs"].items():
            permissions = job["permissions"]
            assert permissions["contents"] == "read"
            assert permissions["security-events"] == "write"
            assert "id-token" not in permissions or name == "publish"
            for step in job["steps"]:
                assert re.fullmatch(r"[^@]+@[a-f0-9]{40}", step["uses"])
                assert "run" not in step
                if step["uses"].startswith("actions/checkout@"):
                    assert step["with"]["persist-credentials"] is False
    publish = scorecard["jobs"]["publish"]
    assert publish["if"] == "github.event.repository.fork == false"
    assert publish["permissions"]["id-token"] == "write"
    assert "src/finassist/resources/dashboard" in document(".github/codeql-config.yml")["paths-ignore"]


def test_issue_security_redirect_and_contributor_documents():
    config = document(".github/ISSUE_TEMPLATE/config.yml")
    assert config["blank_issues_enabled"] is False
    assert config["contact_links"][0]["url"].endswith("/SECURITY.md")
    for form in ["bug", "feature"]:
        fields = document(f".github/ISSUE_TEMPLATE/{form}.yml")["body"]
        assert any(field.get("validations", {}).get("required") for field in fields)
    conduct = (ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
    assert "Contributor Covenant" in conduct and "version 2.1" in conduct
    assert "INSERT CONTACT" not in conduct
    assert "Do not post incident details publicly" in conduct
    owners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
    assert "* @EleutheroiEdge" in owners and "forks must replace" in owners
    template = (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8")
    assert "synthetic" in template and "CHANGELOG" in template and "Ready for review at" in template
