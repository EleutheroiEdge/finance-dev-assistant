"""Offline checks for release gates; never publish or request an OIDC token."""

from pathlib import Path
import re
import tomllib

import pytest
import yaml

from scripts.release_checks import release_notes, validate_environment, validate_tag

ROOT = Path(__file__).resolve().parent.parent


def test_release_versions_and_tag_gate():
    assert validate_tag(ROOT, "v0.3.1") == "0.3.1"
    for tag in ["main", "v0.2.0", "v0.3.0", "v0.3.1rc1", "v0.3.1; echo unsafe"]:
        with pytest.raises(ValueError):
            validate_tag(ROOT, tag)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["name"] == "finledgerpoli"
    assert project["scripts"] == {"finassist": "finassist.cli:main", "finledgerpoli": "finassist.cli:main"}


def test_environment_requires_actual_human_reviewers():
    for document in [{}, {"name": "pypi"}, {"name": "pypi", "protection_rules": [{"type": "required_reviewers", "reviewers": []}]}]:
        with pytest.raises(ValueError):
            validate_environment(document)
    validate_environment({"name": "pypi", "protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User"}]}]})


def test_release_workflow_is_tag_only_and_least_privilege():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    assert workflow.get("on", workflow.get(True)) == {"push": {"tags": ["v*"]}}
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"build", "publish"}
    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == "build" and publish["environment"]["name"] == "pypi"
    assert publish["environment"]["url"] == "https://pypi.org/project/finledgerpoli/"
    assert publish["permissions"] == {"contents": "write", "id-token": "write", "attestations": "write"}
    assert "permissions" not in workflow["jobs"]["build"]
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[^@]+@[a-f0-9]{40}", step["uses"])
    steps = workflow["jobs"]["build"]["steps"]
    assert any("--check-environment" in step.get("run", "") for step in steps)
    assert any("git diff --exit-code -- src/finassist/resources/dashboard" == step.get("run") for step in steps)
    assert not any("secrets." in str(job) for job in workflow["jobs"].values())
    assert "gh release create" in publish["steps"][-1]["run"]
    publisher = publish["steps"][-2]
    assert publisher["uses"].startswith("pypa/gh-action-pypi-publish@")
    assert publisher["with"] == {"packages-dir": "release/dist/", "attestations": True}


def test_release_notes_only_include_requested_version():
    notes = release_notes(ROOT, "0.3.1")
    assert notes.startswith("# finledgerpoli 0.3.1\n")
    assert "PyPI page: absolute links and images, project URLs, badge" in notes
    assert "#1 and #3–#5" not in notes
    assert "## Next" not in notes and "Unreleased" not in notes
