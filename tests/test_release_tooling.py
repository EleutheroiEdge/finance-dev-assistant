"""Offline checks for release gates; never publish or request an OIDC token."""

from pathlib import Path
import re
import subprocess
import sys
import io
import sysconfig
import tarfile
import tomllib
import urllib.error
import zipfile

import pytest
import yaml

from scripts import release_checks
from scripts.release_checks import (distributions_match_tree, installed_package, release_notes, validate_environment,
                                    validate_tag, validate_tag_rules)
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


def _ruleset(*kinds, **changes):
    return {"target": "tag", "enforcement": "active", "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [{"type": kind} for kind in kinds], **changes}


FIXED, CREATION = _ruleset("deletion", "update"), _ruleset("creation", bypass_actors=[{"actor_type": "RepositoryRole"}])


def test_release_tags_are_kept_from_moving_and_deletion_and_their_creation_is_restricted():
    validate_tag_rules([FIXED, CREATION])
    validate_tag_rules([_ruleset("deletion", "update", "creation")])  # one ruleset may hold all three
    without_list = {key: value for key, value in FIXED.items() if key != "bypass_actors"}
    validate_tag_rules([without_list, CREATION])  # the workflow token sees no bypass list: the maintainer checks it
    validate_tag_rules([_ruleset("deletion", "update", conditions={"ref_name": {"include": ["~ALL"]}}), CREATION])


@pytest.mark.parametrize("rulesets", [
    [],
    [FIXED],
    [CREATION],
    [_ruleset("deletion", "update", enforcement="evaluate"), CREATION],
    [_ruleset("deletion", "update", target="branch"), CREATION],
    [_ruleset("deletion"), CREATION],
    [_ruleset("deletion", "update", bypass_actors=[{"actor_type": "RepositoryRole"}]), CREATION],
    [{**FIXED, "rules": [{"type": "deletion"}, {"type": "update", "parameters": {"update_allows_fetch_and_merge": True}}]},
     CREATION],
    [_ruleset("deletion", "update", conditions={"ref_name": {"include": ["refs/tags/v*"], "exclude": ["refs/tags/v0*"]}}),
     CREATION],
    [_ruleset("deletion", "update", conditions={"ref_name": {"include": ["refs/tags/release-*"]}}), CREATION],
    [_ruleset("deletion", "update", conditions=None), CREATION],
    [FIXED, _ruleset("creation", enforcement="disabled")],
], ids=["none", "no-creation-rule", "no-fixed-rule", "evaluate-only", "branches", "no-update-rule", "bypass-shown",
        "fast-forward-moves", "excluded", "other-tags", "no-conditions", "creation-disabled"])
def test_release_tag_rules_that_leave_a_gap_refuse(rulesets):
    with pytest.raises(ValueError, match="ruleset"):
        validate_tag_rules(rulesets)


def _release_tree(root):
    files = {"src/finassist/__init__.py": b"__version__ = '0.0.0'\n", "src/finassist/resources/guide.md": b"# Guide\n",
             "README.md": b"# Synthetic\n", "LICENSE": b"Synthetic licence\n",
             "pyproject.toml": b'[project]\nname = "finledgerpoli"\nversion = "0.0.0"\n'
                               b'[project.scripts]\nfinassist = "finassist.cli:main"\n'}
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    (root / "src/finassist/__pycache__").mkdir()
    (root / "src/finassist/__pycache__/x.cpython-313.pyc").write_bytes(b"compiled")  # never packaged
    return files


def _build(root, files, wheel_changes=None, sdist_changes=None, extra=None):
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    for old in dist.iterdir():
        old.unlink()
    info = "finledgerpoli-0.0.0.dist-info/"
    wheel = {name.removeprefix("src/"): data for name, data in files.items() if name.startswith("src/finassist/")}
    wheel.update({info + "licenses/LICENSE": files["LICENSE"], info + "METADATA": b"Name: finledgerpoli\n",
                  info + "WHEEL": b"Wheel-Version: 1.0\n", info + "top_level.txt": b"finassist\n",
                  info + "entry_points.txt": b"[console_scripts]\nfinassist = finassist.cli:main\n", info + "RECORD": b""})
    wheel.update(wheel_changes or {})
    with zipfile.ZipFile(dist / "finledgerpoli-0.0.0-py3-none-any.whl", "w") as archive:
        for name, data in wheel.items():
            if data is not None:
                archive.writestr(name, data)
    sdist = {name: data for name, data in files.items()}
    sdist.update({"PKG-INFO": b"Name: finledgerpoli\n", "src/finledgerpoli.egg-info/SOURCES.txt": b"README.md\n"})
    sdist.update(sdist_changes or {})
    with tarfile.open(dist / "finledgerpoli-0.0.0.tar.gz", "w:gz") as archive:
        for name, data in sdist.items():
            if data is not None:
                member = tarfile.TarInfo("finledgerpoli-0.0.0/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    for name, data in (extra or {}).items():
        (dist / name).write_bytes(data)
    return dist


def test_published_distributions_must_hold_exactly_the_tagged_files(tmp_path):
    files = _release_tree(tmp_path)
    assert distributions_match_tree(tmp_path, _build(tmp_path, files), "0.0.0") == 2


@pytest.mark.parametrize("changes,match", [
    ({"wheel_changes": {"finassist/resources/guide.md": b"# Changed\n"}}, "wheel"),
    ({"wheel_changes": {"finassist/resources/guide.md": None}}, "wheel"),
    ({"wheel_changes": {"finassist/extra.py": b""}}, "wheel"),
    ({"wheel_changes": {"autoload.pth": b"import os\n"}}, "wheel"),
    ({"wheel_changes": {"finledgerpoli-0.0.0.data/scripts/run": b"#!/bin/sh\n"}}, "wheel"),
    ({"wheel_changes": {"finledgerpoli-0.0.0.dist-info/entry_points.txt":
                        b"[console_scripts]\nfinassist = other.module:main\n"}}, "wheel"),
    ({"wheel_changes": {"finledgerpoli-0.0.0.dist-info/licenses/LICENSE": b"Other\n"}}, "wheel"),
    ({"sdist_changes": {"README.md": b"# Changed\n"}}, "sdist"),
    ({"sdist_changes": {"setup.py": b"import os\n"}}, "sdist"),
    ({"sdist_changes": {"../outside.txt": b""}}, "sdist"),
    ({"extra": {"other-1.0-py3-none-any.whl": b""}}, "dist"),
], ids=["wheel-file-changed", "wheel-file-missing", "wheel-file-extra", "wheel-path-file", "wheel-data-script",
        "wheel-entry-point", "wheel-licence", "sdist-file-changed", "sdist-file-extra", "sdist-outside", "dist-extra"])
def test_a_distribution_with_anything_but_the_tagged_files_refuses(tmp_path, changes, match):
    files = _release_tree(tmp_path)
    with pytest.raises(ValueError, match=match):
        distributions_match_tree(tmp_path, _build(tmp_path, files, **changes), "0.0.0")


def test_a_wheel_naming_one_file_twice_refuses(tmp_path):
    files = _release_tree(tmp_path)
    dist = _build(tmp_path, files)
    with zipfile.ZipFile(dist / "finledgerpoli-0.0.0-py3-none-any.whl", "a") as archive, pytest.warns(UserWarning):
        archive.writestr("finassist/__init__.py", b"__version__ = 'other'\n")
    with pytest.raises(ValueError, match="repeats"):
        distributions_match_tree(tmp_path, dist, "0.0.0")


def test_the_tests_must_import_the_installed_wheel_and_not_the_tree(tmp_path):
    installed = Path(sysconfig.get_path("purelib")) / "finassist" / "__init__.py"
    installed_package(tmp_path, installed)
    for location in (tmp_path / "src/finassist/__init__.py", tmp_path / "elsewhere/finassist/__init__.py"):
        with pytest.raises(ValueError, match="installed wheel"):
            installed_package(tmp_path, location)


def test_the_settings_are_read_with_the_token_and_any_failed_read_stops_the_release(monkeypatch):
    documents = {
        "environments/pypi": {"name": "pypi", "deployment_branch_policy": TAG_ONLY},
        "environments/pypi/deployment-branch-policies?per_page=100": {"branch_policies": RELEASE_TAGS},
        "rulesets?per_page=100": [{"id": 7, "target": "tag"}, {"id": 8, "target": "tag"}, {"id": 9, "target": "branch"}],
        "rulesets/7": FIXED, "rulesets/8": CREATION,
    }
    seen = []

    def read(repository, path, token):
        seen.append((repository, path, token))
        if path not in documents:
            raise urllib.error.HTTPError(path, 404, "missing", {}, None)
        return documents[path]

    monkeypatch.setattr(release_checks, "read_github", read)
    given = object()  # stands for the workflow's token, which every read must carry
    release_checks.check_settings("owner/repository", given)
    assert {path for _repository, path, _token in seen} == set(documents)
    assert all(token is given for _repository, _path, token in seen)
    del documents["rulesets/8"]
    with pytest.raises(urllib.error.HTTPError):
        release_checks.check_settings("owner/repository", given)
    with pytest.raises(ValueError, match="repository"):
        release_checks.check_settings("owner/repository/../other", given)


def test_release_workflow_is_tag_only_and_least_privilege():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    assert workflow.get("on", workflow.get(True)) == {"push": {"tags": ["v*"]}}
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"build", "gates", "publish"}
    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == ["build", "gates"] and publish["environment"]["name"] == "pypi"
    # The gates job holds no permission of its own, and tests the built distributions, never the tree: they are checked
    # against the tagged tree, outside the checkout, before the wheel is installed by its hash; the tests' import of
    # the installed wheel is checked; and the whole suite and the demo run after.
    gates = workflow["jobs"]["gates"]
    assert gates["needs"] == "build" and "permissions" not in gates and "environment" not in gates
    runs = [step.get("run", "") for step in gates["steps"]]
    order = [next(index for index, run in enumerate(runs) if text in run) for text in (
        '--distributions-match-tree "$RUNNER_TEMP/release/dist"', 'python scripts/ci_install.py wheel "$RUNNER_TEMP/release/dist"',
        "--imports-installed", "python scripts/ci_test.py", "finassist demo")]
    assert order == sorted(order)
    assert not any("ci_install.py project" in run or "finassist scan" in run for run in runs)
    downloads = [step["with"] for step in gates["steps"] if "download-artifact" in step.get("uses", "")]
    assert downloads == [{"name": "release-${{ github.sha }}", "path": "${{ runner.temp }}/release"}]
    assert next(step for step in gates["steps"] if step.get("run") == "finassist demo")["working-directory"] == (
        "${{ runner.temp }}")
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
