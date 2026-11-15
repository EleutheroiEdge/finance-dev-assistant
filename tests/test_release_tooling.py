"""Offline checks for release gates; never publish or request an OIDC token."""

from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile

import pytest
import yaml

from scripts.release_checks import (release_notes, validate_environment, validate_tag, validate_tag_rules,
                                    wheel_matches_tree)
from finassist.platform_support import clean_environment

ROOT = Path(__file__).resolve().parent.parent


def test_release_versions_and_tag_gate():
    assert validate_tag(ROOT, "v0.11.0") == "0.11.0"
    for tag in ["main", "v0.2.0", "v0.3.1", "v0.4.0", "v0.5.0", "v0.6.0", "v0.7.0", "v0.7.1", "v0.8.0", "v0.9.0", "v0.10.0", "v0.11.0rc1", "v0.11.0; echo unsafe"]:
        with pytest.raises(ValueError):
            validate_tag(ROOT, tag)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["name"] == "finledgerpoli"
    assert project["scripts"] == {"finassist": "finassist.cli:main", "finledgerpoli": "finassist.cli:main"}


TAG_ONLY = {"protected_branches": False, "custom_branch_policies": True}
RELEASE_TAGS = [{"type": "tag", "name": "v*"}]


@pytest.mark.parametrize("document,policies", [
    ({}, RELEASE_TAGS),
    ({"name": "pypi"}, RELEASE_TAGS),
    ({"name": "pypi", "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False}},
     RELEASE_TAGS),
    ({"name": "pypi", "deployment_branch_policy": TAG_ONLY}, []),
    ({"name": "pypi", "deployment_branch_policy": TAG_ONLY}, [*RELEASE_TAGS, {"type": "branch", "name": "main"}]),
    ({"name": "pypi", "deployment_branch_policy": TAG_ONLY}, [{"type": "tag", "name": "*"}]),
], ids=["missing", "no-rule", "protected-branches", "no-tag-rule", "and-a-branch", "every-tag"])
def test_the_pypi_environment_must_deploy_only_release_tags(document, policies):
    with pytest.raises(ValueError):
        validate_environment(document, policies)


def test_a_release_needs_no_reviewer_and_may_keep_one():
    validate_environment({"name": "pypi", "deployment_branch_policy": TAG_ONLY}, RELEASE_TAGS)
    validate_environment({"name": "pypi", "deployment_branch_policy": TAG_ONLY, "protection_rules": [
        {"type": "required_reviewers", "reviewers": [{"type": "User"}]}]}, RELEASE_TAGS)


def _ruleset(**changes):
    return {"target": "tag", "enforcement": "active", "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [{"type": "deletion"}, {"type": "update"}], **changes}


def test_release_tags_must_be_kept_from_moving_and_deletion():
    validate_tag_rules([_ruleset()])
    validate_tag_rules([_ruleset(target="branch"), _ruleset(conditions={"ref_name": {"include": ["~ALL"]}})])
    for rulesets in ([], [_ruleset(enforcement="evaluate")], [_ruleset(target="branch")],
                     [_ruleset(rules=[{"type": "deletion"}])], [_ruleset(bypass_actors=[{"actor_type": "RepositoryRole"}])],
                     [_ruleset(conditions={"ref_name": {"include": ["refs/tags/v*"], "exclude": ["refs/tags/v0*"]}})],
                     [_ruleset(conditions={"ref_name": {"include": ["refs/tags/release-*"]}})], [_ruleset(conditions=None)]):
        with pytest.raises(ValueError, match="ruleset"):
            validate_tag_rules(rulesets)


def test_the_published_wheel_must_hold_exactly_the_tagged_package_files(tmp_path):
    files = {"finassist/__init__.py": b"__version__ = '0.0.0'\n", "finassist/resources/guide.md": b"# Guide\n"}
    for name, data in files.items():
        (tmp_path / "src" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "src" / name).write_bytes(data)
    (tmp_path / "src/finassist/__pycache__").mkdir()
    (tmp_path / "src/finassist/__pycache__/x.cpython-313.pyc").write_bytes(b"compiled")  # never packaged
    dist = tmp_path / "dist"
    dist.mkdir()

    def build(entries):
        with zipfile.ZipFile(dist / "finledgerpoli-0.0.0-py3-none-any.whl", "w") as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
            archive.writestr("finledgerpoli-0.0.0.dist-info/METADATA", "Name: finledgerpoli\n")

    build(files)
    assert wheel_matches_tree(tmp_path, dist) == 2
    for entries in ({**files, "finassist/resources/guide.md": b"# Changed\n"},
                    {"finassist/__init__.py": files["finassist/__init__.py"]}, {**files, "finassist/extra.py": b""}):
        build(entries)
        with pytest.raises(ValueError, match="differ"):
            wheel_matches_tree(tmp_path, dist)
    (dist / "finledgerpoli-9.9.9-py3-none-any.whl").write_bytes(b"")
    with pytest.raises(ValueError, match="exactly one"):
        wheel_matches_tree(tmp_path, dist)


def test_release_workflow_is_tag_only_and_least_privilege():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    assert workflow.get("on", workflow.get(True)) == {"push": {"tags": ["v*"]}}
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"build", "gates", "publish"}
    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == ["build", "gates"] and publish["environment"]["name"] == "pypi"
    # The gates job holds no permission of its own, and tests the built wheel, never the tree: the wheel's files are
    # checked against the tagged tree before it is installed by its hash, and the whole suite runs after.
    gates = workflow["jobs"]["gates"]
    assert gates["needs"] == "build" and "permissions" not in gates and "environment" not in gates
    runs = [step.get("run", "") for step in gates["steps"]]
    order = [next(index for index, run in enumerate(runs) if text in run) for text in (
        "--wheel-matches-tree release/dist", "python scripts/ci_install.py wheel release/dist", "python scripts/ci_test.py")]
    assert order == sorted(order) and not any("ci_install.py project" in run for run in runs)
    downloads = [step["with"]["name"] for step in gates["steps"] if "download-artifact" in step.get("uses", "")]
    assert downloads == ["release-${{ github.sha }}"]
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


def test_dated_first_public_release_notes_extract_cleanly():
    notes = release_notes(ROOT, "0.3.0")
    assert notes.startswith("# finledgerpoli 0.3.0\n")
    assert "First public release" in notes
    assert "PyPI page:" not in notes
    assert "Earlier development" not in notes
    assert "#1" not in notes and "development milestones" not in notes


def test_workflow_release_notes_exclude_already_published_changes():
    notes = release_notes(ROOT, "0.4.0")
    assert notes.startswith("# finledgerpoli 0.4.0\n")
    assert "hash-pinned base policy" in notes and "audit-backed checkpoints" in notes
    assert "full trusted-source Action bootstrap" in notes
    assert "PyPI page:" not in notes and "brand artwork" not in notes
    previous = release_notes(ROOT, "0.3.1")
    assert "hash-pinned base policy" not in previous and "audit-backed checkpoints" not in previous


@pytest.mark.parametrize("section", ["Changes only", "### Upgrading\n", "### Upgrading\nFirst\n\n### Upgrading\nSecond"])
def test_new_release_notes_require_one_nonempty_upgrading_section(tmp_path, section):
    (tmp_path / "CHANGELOG.md").write_text("## 0.5.0 - Unreleased\n\n" + section, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\nname="synthetic"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Upgrading"):
        release_notes(tmp_path, "0.5.0")


def test_current_unreleased_notes_explain_upgrade_and_downgrade_boundary():
    notes = release_notes(ROOT, "0.5.0")
    assert "### Upgrading" in notes and "pre-migration evidence" in notes
    assert "Historical releases" in notes


def test_built_source_distribution_contains_complete_action_bootstrap(tmp_path):
    subprocess.run([sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", str(tmp_path)],
                   cwd=ROOT, env=clean_environment(), capture_output=True, check=True, timeout=90, shell=False)
    archives = list(tmp_path.glob("finledgerpoli-*.tar.gz"))
    assert len(archives) == 1
    with tarfile.open(archives[0], "r:gz") as archive:
        prefix = archive.getmembers()[0].name.split("/")[0] + "/"
        for relative in ("actions/gate/action.yml", "actions/gate/run.py", "requirements-action.lock"):
            member = archive.extractfile(prefix + relative)
            assert member is not None and member.read() == (ROOT / relative).read_bytes()
        assert not any(".finassist" in Path(member.name).parts for member in archive.getmembers())


@pytest.mark.parametrize("headers", ["", "## 0.3.01 - Unreleased\n\nWrong version", "## 0.3.0 - Unreleased\n\n", "## 0.3.0 - Unreleased\n\nOne\n\n## 0.3.0 - 2026-10-28\n\nTwo"])
def test_release_notes_refuse_missing_empty_or_duplicate_sections(tmp_path, headers):
    (tmp_path / "CHANGELOG.md").write_text(headers, encoding="utf-8", newline="\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "synthetic"\n', encoding="utf-8", newline="\n")
    with pytest.raises(ValueError, match="release notes"):
        release_notes(tmp_path, "0.3.0")
