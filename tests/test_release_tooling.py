"""Offline checks for release gates; never publish or request an OIDC token."""

from pathlib import Path
import re
import subprocess
import sys
import gzip
import io
import stat
import sysconfig
import tarfile
import tomllib
import urllib.error
import zipfile

import pytest
import yaml

from scripts import release_checks
from scripts.release_checks import (distributions_match_rebuild, installed_package, release_notes,
                                    validate_environment, validate_tag, validate_tag_rules)
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
    without_list = {key: value for key, value in FIXED.items() if key != "bypass_actors"}
    validate_tag_rules([without_list, CREATION])  # the workflow token sees no bypass list: the maintainer checks it
    validate_tag_rules([{**FIXED, "current_user_can_bypass": "never"}, CREATION])
    validate_tag_rules([{**FIXED, "current_user_can_bypass": None}, CREATION])  # null, as an API may send it
    validate_tag_rules([_ruleset("deletion", "update", conditions={"ref_name": {"include": ["~ALL"]}}), CREATION])


@pytest.mark.parametrize("rulesets", [
    [],
    [FIXED],
    [CREATION],
    [_ruleset("deletion", "update", "creation")],
    [_ruleset("deletion", "update", enforcement="evaluate"), CREATION],
    [_ruleset("deletion", "update", target="branch"), CREATION],
    [_ruleset("deletion"), CREATION],
    [_ruleset("deletion", "update", bypass_actors=[{"actor_type": "RepositoryRole"}]), CREATION],
    [{**FIXED, "current_user_can_bypass": "always"}, CREATION],
    [{**FIXED, "rules": [{"type": "deletion"}, {"type": "update", "parameters": {"update_allows_fetch_and_merge": True}}]},
     CREATION],
    [_ruleset("deletion", "update", conditions={"ref_name": {"include": ["refs/tags/v*"], "exclude": ["refs/tags/v0*"]}}),
     CREATION],
    [_ruleset("deletion", "update", conditions={"ref_name": {"include": ["refs/tags/release-*"]}}), CREATION],
    [_ruleset("deletion", "update", conditions=None), CREATION],
    [FIXED, _ruleset("creation", enforcement="disabled")],
], ids=["none", "no-creation-rule", "no-fixed-rule", "one-ruleset-for-all", "evaluate-only", "branches",
        "no-update-rule", "bypass-shown", "token-may-bypass", "fast-forward-moves", "excluded", "other-tags",
        "no-conditions", "creation-disabled"])
def test_release_tag_rules_that_leave_a_gap_refuse(rulesets):
    with pytest.raises(ValueError, match="ruleset"):
        validate_tag_rules(rulesets)


WHEEL, SDIST = "finledgerpoli-0.0.0-py3-none-any.whl", "finledgerpoli-0.0.0.tar.gz"
_WHEEL = [("finassist/__init__.py", b"__version__ = '0.0.0'\n"), ("finledgerpoli-0.0.0.dist-info/METADATA",
          b"Name: finledgerpoli\nRequires-Dist: packaging\n"), ("finledgerpoli-0.0.0.dist-info/RECORD", b"")]
_SDIST = [("finledgerpoli-0.0.0", None), ("finledgerpoli-0.0.0/PKG-INFO", b"Name: finledgerpoli\n"),
          ("finledgerpoli-0.0.0/src/finassist/__init__.py", b"__version__ = '0.0.0'\n")]


def _archives(folder, wheel=_WHEEL, sdist=_SDIST, extra=()):
    folder.mkdir()
    with zipfile.ZipFile(folder / WHEEL, "w") as archive:
        for name, data in wheel:
            archive.writestr(name, data)
    with tarfile.open(folder / SDIST, "w:gz") as archive:
        for name, data in sdist:
            member = tarfile.TarInfo(name)
            if data is None:
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            elif isinstance(data, str):  # a link to that target
                member.type, member.linkname = tarfile.SYMTYPE, data
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    for name in extra:
        (folder / name).write_bytes(b"")
    return folder


def test_published_archives_must_equal_an_independent_build_member_for_member(tmp_path):
    assert distributions_match_rebuild(_archives(tmp_path / "dist"), _archives(tmp_path / "rebuilt"), "0.0.0") == 2


@pytest.mark.parametrize("published", [
    {"wheel": [*_WHEEL[:1], (_WHEEL[1][0], b"Name: finledgerpoli\nRequires-Dist: packaging\nRequires-Dist: other\n"),
               *_WHEEL[2:]]},
    {"wheel": [*_WHEEL, ("autoload.pth", b"import os\n")]},
    {"wheel": _WHEEL[:2]},
    {"sdist": [*_SDIST[:2], (_SDIST[2][0], b"__version__ = 'other'\n")]},
    {"sdist": _SDIST[:2]},
    {"sdist": [*_SDIST, ("finledgerpoli-0.0.0/setup.py", b"import os\n")]},
], ids=["added-dependency", "path-file", "missing-member", "sdist-changed", "sdist-missing", "sdist-extra"])
def test_an_archive_that_differs_from_the_rebuild_refuses(tmp_path, published):
    with pytest.raises(ValueError, match="independent build"):
        distributions_match_rebuild(_archives(tmp_path / "dist", **published), _archives(tmp_path / "rebuilt"), "0.0.0")


@pytest.mark.parametrize("sdist,match", [
    ([*_SDIST, ("finledgerpoli-0.0.0//etc/hosts", b"")], "plain relative path"),
    ([*_SDIST, ("finledgerpoli-0.0.0/./PKG-INFO", b"")], "plain relative path"),
    ([*_SDIST, ("finledgerpoli-0.0.0/../outside", b"")], "plain relative path"),
    ([*_SDIST, ("finledgerpoli-0.0.0/a\\b", b"")], "plain relative path"),
    ([*_SDIST, ("/finledgerpoli-0.0.0/x", b"")], "plain relative path"),
    ([*_SDIST, ("finledgerpoli-0.0.0/PKG-INFO", b"Name: other\n")], "repeats"),
    ([*_SDIST, ("finledgerpoli-0.0.0/src", "/etc")], "link"),
], ids=["double-slash", "dot-part", "dot-dot", "backslash", "absolute", "repeated", "link"])
def test_an_archive_member_that_could_mean_another_path_refuses(tmp_path, sdist, match):
    # Refused before any comparison, even when the rebuild holds the same member.
    with pytest.raises(ValueError, match=match):
        distributions_match_rebuild(_archives(tmp_path / "dist", sdist=sdist), _archives(tmp_path / "rebuilt", sdist=sdist),
                                    "0.0.0")


def test_member_order_alone_does_not_stop_an_honest_release(tmp_path):
    reordered = [_WHEEL[1], _WHEEL[0], _WHEEL[2]]
    assert distributions_match_rebuild(_archives(tmp_path / "dist", wheel=reordered), _archives(tmp_path / "rebuilt"),
                                       "0.0.0") == 2


@pytest.mark.parametrize("name,match", [
    ("finledgerpoli-0.0.0/C:x", "plain relative path"),
    ("finledgerpoli-0.0.0/src/CON.py", "plain relative path"),
    ("finledgerpoli-0.0.0/notes.", "plain relative path"),
    ("finledgerpoli-0.0.0/notes ", "plain relative path"),
    ("finledgerpoli-0.0.0/bell\x07", "plain relative path"),
    ("finledgerpoli-0.0.0/src/finassist/__INIT__.py", "repeats"),
    ("other/README.md", "outside its folder"),
], ids=["drive", "device", "trailing-dot", "trailing-space", "control", "case-collision", "outside"])
def test_an_archive_name_unsafe_on_any_system_refuses(tmp_path, name, match):
    sdist = [*_SDIST, (name, b"")]
    with pytest.raises(ValueError, match=match):
        distributions_match_rebuild(_archives(tmp_path / "dist", sdist=sdist), _archives(tmp_path / "rebuilt", sdist=sdist),
                                    "0.0.0")


def test_a_wheel_member_stored_as_a_link_refuses(tmp_path):
    folders = [_archives(tmp_path / name) for name in ("dist", "rebuilt")]
    for folder in folders:
        with zipfile.ZipFile(folder / WHEEL, "a") as archive:
            link = zipfile.ZipInfo("finassist/elsewhere")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "/etc")
    with pytest.raises(ValueError, match="link or a special file"):
        distributions_match_rebuild(*folders, "0.0.0")


def test_a_member_mode_that_differs_from_the_rebuild_refuses(tmp_path):
    dist, rebuilt = _archives(tmp_path / "dist"), _archives(tmp_path / "rebuilt")
    with zipfile.ZipFile(dist / WHEEL, "a") as archive:
        script = zipfile.ZipInfo("finassist/run.py")
        script.external_attr = (stat.S_IFREG | 0o4755) << 16
        archive.writestr(script, b"")
    with zipfile.ZipFile(rebuilt / WHEEL, "a") as archive:
        script = zipfile.ZipInfo("finassist/run.py")
        script.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(script, b"")
    with pytest.raises(ValueError, match="independent build"):
        distributions_match_rebuild(dist, rebuilt, "0.0.0")


@pytest.mark.parametrize("link,more", [
    ('<https://api.github.com/x?page=2>; rel="next"', True),
    ("<https://api.github.com/x?page=2>; rel=next", True),
    ('<https://api.github.com/x?page=2>; REL = "prev next"', True),
    ('<https://api.github.com/x?page=1>; rel="prev", <https://api.github.com/x?page=3>; rel="last"', False),
    ('<https://api.github.com/x?rel="next">; rel="prev"', False),
    ('<https://api.github.com/x;rel=next;v=1>; rel="prev"', False),
    ("", False),
], ids=["quoted", "bare", "spaced-and-several", "prev-and-last", "in-the-address", "parameters-in-the-address",
        "none"])
def test_a_link_header_names_a_next_page_however_it_is_written(link, more):
    assert release_checks._names_next(link) is more


def _tar(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data in members:
            member = tarfile.TarInfo(name)
            if data is None:
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


@pytest.mark.parametrize("stream,match", [
    (lambda clean: clean + _tar([("finledgerpoli-0.0.0/src/finassist/hidden.py", b"import os\n")]), "independent build"),
    (lambda clean: clean + b"not padding", "after its last member|not a plain archive"),
], ids=["archive-appended-after-the-end", "bytes-after-the-end"])
def test_an_sdist_that_another_reader_would_read_differently_refuses(tmp_path, stream, match):
    dist, rebuilt = _archives(tmp_path / "dist"), _archives(tmp_path / "rebuilt")
    (dist / SDIST).write_bytes(gzip.compress(stream(_tar(_SDIST))))
    with pytest.raises(ValueError, match=match):
        distributions_match_rebuild(dist, rebuilt, "0.0.0")


def test_an_sdist_with_bytes_after_its_gzip_stream_refuses(tmp_path):
    dist, rebuilt = _archives(tmp_path / "dist"), _archives(tmp_path / "rebuilt")
    (dist / SDIST).write_bytes((dist / SDIST).read_bytes() + b"trailing")
    with pytest.raises(ValueError, match="gzip"):
        distributions_match_rebuild(dist, rebuilt, "0.0.0")


@pytest.mark.parametrize("change,match", [
    (lambda raw: b"prepended" + raw, "outside its entries"),
    (lambda raw: raw[:-2] + b"\x07\x00comment", "end record"),
], ids=["bytes-before-the-entries", "comment"])
def test_a_wheel_that_another_reader_would_read_differently_refuses(tmp_path, change, match):
    dist, rebuilt = _archives(tmp_path / "dist"), _archives(tmp_path / "rebuilt")
    (dist / WHEEL).write_bytes(change((dist / WHEEL).read_bytes()))
    with pytest.raises(ValueError, match=match):
        distributions_match_rebuild(dist, rebuilt, "0.0.0")


@pytest.mark.parametrize("name,attributes,data,match", [
    ("finassist/run.py", (stat.S_IFDIR | 0o755) << 16, b"", "link or a special file"),
    ("finassist/folder/", (stat.S_IFDIR | 0o755) << 16, b"payload", "data in a directory"),
], ids=["file-marked-directory", "directory-with-data"])
def test_a_wheel_entry_whose_kind_and_contents_disagree_refuses(tmp_path, name, attributes, data, match):
    folders = [_archives(tmp_path / folder) for folder in ("dist", "rebuilt")]
    for folder in folders:
        with zipfile.ZipFile(folder / WHEEL, "a") as archive:
            entry = zipfile.ZipInfo(name)
            entry.external_attr = attributes
            archive.writestr(entry, data)
    with pytest.raises(ValueError, match=match):
        distributions_match_rebuild(*folders, "0.0.0")


@pytest.mark.parametrize("name", ["finledgerpoli-0.0.0/src/CON .py", "finledgerpoli-0.0.0/src/COM\u00b9.py",
                                  "finledgerpoli-0.0.0/CONIN$", "finledgerpoli-0.0.0/del\x7f",
                                  "finledgerpoli-0.0.0/c\u0301"], ids=["device-and-space", "device-superscript",
                                                                         "console", "delete", "combining"])
def test_more_names_unsafe_on_some_system_refuse(tmp_path, name):
    sdist = [*_SDIST, (name, b"")]
    if name.endswith("\u0301"):
        sdist.append(("finledgerpoli-0.0.0/\u0107", b""))  # the same name, composed
    with pytest.raises(ValueError, match="plain relative path|repeats"):
        distributions_match_rebuild(_archives(tmp_path / "dist", sdist=sdist), _archives(tmp_path / "rebuilt", sdist=sdist),
                                    "0.0.0")


def test_child_processes_import_only_the_installed_wheel_while_it_is_required(monkeypatch):
    from conftest import source_path
    monkeypatch.setenv("FINASSIST_REQUIRE_INSTALLED", "1")
    child = source_path({"PYTHONPATH": "src", "OTHER": "kept"})
    assert "PYTHONPATH" not in child and child["PYTHONSAFEPATH"] == "1" and child["OTHER"] == "kept"
    monkeypatch.delenv("FINASSIST_REQUIRE_INSTALLED")
    assert source_path({})["PYTHONPATH"] == str(ROOT / "src")


def test_dist_must_hold_exactly_the_release_archives(tmp_path):
    with pytest.raises(ValueError, match="exactly"):
        distributions_match_rebuild(_archives(tmp_path / "dist", extra=["other-1.0-py3-none-any.whl"]),
                                    _archives(tmp_path / "rebuilt"), "0.0.0")


def test_the_tests_must_import_the_installed_wheel_and_not_the_tree(tmp_path):
    installed = Path(sysconfig.get_path("purelib")) / "finassist" / "__init__.py"
    installed_package(tmp_path, installed)
    for location in (tmp_path / "src/finassist/__init__.py", tmp_path / "elsewhere/finassist/__init__.py"):
        with pytest.raises(ValueError, match="installed wheel"):
            installed_package(tmp_path, location)


def test_the_suite_refuses_to_start_on_the_tree_when_the_installed_wheel_is_required():
    environment = {**clean_environment(), "PYTHONPATH": str(ROOT / "src"), "FINASSIST_REQUIRE_INSTALLED": "1"}
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--collect-only",
                             "tests/test_release_requirements.py"], cwd=ROOT, env=environment, capture_output=True,
                            text=True, timeout=120, shell=False)
    assert result.returncode != 0 and "installed wheel" in result.stdout + result.stderr


def test_the_settings_are_read_with_the_token_and_any_failed_read_stops_the_release(monkeypatch):
    documents = {
        "environments/pypi": {"name": "pypi", "deployment_branch_policy": TAG_ONLY},
        "environments/pypi/deployment-branch-policies?per_page=100": {"total_count": 1, "branch_policies": RELEASE_TAGS},
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
    documents["environments/pypi/deployment-branch-policies?per_page=100"]["total_count"] = 2
    with pytest.raises(ValueError, match="not all read"):
        release_checks.check_settings("owner/repository", given)
    documents["environments/pypi/deployment-branch-policies?per_page=100"]["total_count"] = 1
    del documents["rulesets/8"]
    with pytest.raises(urllib.error.HTTPError):
        release_checks.check_settings("owner/repository", given)
    with pytest.raises(ValueError, match="repository"):
        release_checks.check_settings("owner/repository/../other", given)


def test_a_document_that_runs_on_to_another_page_refuses(monkeypatch):
    class Headers:
        def get_all(self, name):  # two Link headers: the second names the next page
            return ['<https://api.github.com/repositories/1/rulesets?page=1>; rel="first"',
                    '<https://api.github.com/repositories/1/rulesets?page=2>; rel="next"'] if name == "Link" else None

    class Response(io.BytesIO):
        headers = Headers()

        def __enter__(self):
            return self

        def __exit__(self, *exception):
            return False

    monkeypatch.setattr(release_checks.urllib.request, "urlopen", lambda request, timeout: Response(b"[]"))
    with pytest.raises(ValueError, match="another page"):
        release_checks.read_github("owner/repository", "rulesets?per_page=100", "x")


def test_release_workflow_is_tag_only_and_least_privilege():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    assert workflow.get("on", workflow.get(True)) == {"push": {"tags": ["v*"]}}
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"build", "gates", "publish"}
    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == ["build", "gates"] and publish["environment"]["name"] == "pypi"
    # The gates job holds no permission of its own, and tests the built archives, never the tree: they are compared
    # with an independent build of the tagged checkout, member for member, before the wheel is installed by its hash;
    # the whole suite runs against it and refuses to start on the tree; and the demo runs outside the checkout.
    gates = workflow["jobs"]["gates"]
    assert gates["needs"] == "build" and "permissions" not in gates and "environment" not in gates
    runs = [step.get("run", "") for step in gates["steps"]]
    order = [next(index for index, run in enumerate(runs) if text in run) for text in (
        "python scripts/ci_install.py dependencies", 'python -m build --no-isolation --outdir "$RUNNER_TEMP/rebuilt"',
        '--distributions-match-rebuild "$RUNNER_TEMP/release/dist" "$RUNNER_TEMP/rebuilt"',
        'python scripts/ci_install.py wheel "$RUNNER_TEMP/release/dist"', "python scripts/ci_test.py", "finassist demo")]
    assert order == sorted(order)
    assert not any("ci_install.py project" in run or "finassist scan" in run for run in runs)
    suite = next(step for step in gates["steps"] if step.get("run") == "python scripts/ci_test.py")
    assert suite["env"] == {"FINASSIST_REQUIRE_INSTALLED": "1"}
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
