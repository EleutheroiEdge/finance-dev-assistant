"""Guard repository automation permissions and safe contributor entry points."""

from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parent.parent


def document(name):
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def events(workflow):
    return workflow.get("on", workflow.get(True))


def test_weekly_dependency_updates_cover_all_manifests():
    config = document(".github/dependabot.yml")
    assert "-r requirements-dev.lock" in (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert config["version"] == 2
    assert {(row["package-ecosystem"], row["directory"]) for row in config["updates"]} == {
        ("pip", "/"), ("npm", "/dashboard"), ("github-actions", "/")
    }
    for row in config["updates"]:
        assert row["schedule"]["interval"] == "weekly"
        assert list(row["groups"].values()) == [{"patterns": ["*"]}]


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
