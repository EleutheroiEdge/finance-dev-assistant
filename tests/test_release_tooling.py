"""Offline checks for release gates; never publish or request an OIDC token."""

from pathlib import Path
import gzip
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tarfile
import tomllib
import urllib.error
import zipfile

import pytest
import yaml

from scripts import normalize_sdist, release_checks
from scripts.normalize_sdist import normalized
from scripts.release_checks import (distributions_match_rebuild, installed_package, release_notes,
                                    sdist_builds_the_wheel, validate_environment, validate_tag, validate_tag_rules)
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
_HIDDEN = [("finledgerpoli-0.0.0/src/finassist/hidden.py", b"import os\n")]
_VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def _entry(name, mode=stat.S_IFREG | 0o644, extra=b""):
    entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    entry.external_attr, entry.extra = mode << 16, extra
    return entry


def _wheel(entries, comment=b""):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in entries:
            archive.writestr(name if isinstance(name, zipfile.ZipInfo) else _entry(name), data)
        archive.comment = comment
    return stream.getvalue()


def _tar(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in members:
            member = tarfile.TarInfo(name)
            if data is None:
                member.type = tarfile.DIRTYPE
            elif isinstance(data, str):  # a link to that target
                member.type, member.linkname = tarfile.SYMTYPE, data
            else:
                member.size = len(data)
            archive.addfile(member, io.BytesIO(data) if isinstance(data, bytes) else None)
    return stream.getvalue()


def _sdist(members):
    return gzip.compress(_tar(members), mtime=0)


def _archives(folder, wheel=_WHEEL, sdist=_SDIST, extra=()):
    folder.mkdir()
    (folder / WHEEL).write_bytes(_wheel(wheel))
    (folder / SDIST).write_bytes(_sdist(sdist))
    for name in extra:
        (folder / name).write_bytes(b"")
    return folder


def _published_and_rebuilt(tmp_path, **contents):
    """An honest release: the published archives are copies of the rebuild's."""
    rebuilt = _archives(tmp_path / "rebuilt", **contents)
    return Path(shutil.copytree(rebuilt, tmp_path / "dist")), rebuilt


def test_published_archives_must_equal_an_independent_build_byte_for_byte(tmp_path):
    distributions_match_rebuild(*_published_and_rebuilt(tmp_path), "0.0.0")


_CHANGES = {
    # What a build added, dropped or changed.
    "added-dependency": (WHEEL, lambda raw: _wheel([_WHEEL[0], (_WHEEL[1][0], _WHEEL[1][1] + b"Requires-Dist: other\n"),
                                                    _WHEEL[2]])),
    "path-file": (WHEEL, lambda raw: _wheel([*_WHEEL, ("autoload.pth", b"import os\n")])),
    "missing-member": (WHEEL, lambda raw: _wheel(_WHEEL[:2])),
    "reordered": (WHEEL, lambda raw: _wheel([_WHEEL[1], _WHEEL[0], _WHEEL[2]])),
    "mode": (WHEEL, lambda raw: _wheel([(_entry(_WHEEL[0][0], stat.S_IFREG | 0o4755), _WHEEL[0][1]), *_WHEEL[1:]])),
    "sdist-changed": (SDIST, lambda raw: _sdist([*_SDIST[:2], (_SDIST[2][0], b"__version__ = 'other'\n")])),
    "sdist-missing": (SDIST, lambda raw: _sdist(_SDIST[:2])),
    "sdist-extra": (SDIST, lambda raw: _sdist([*_SDIST, ("finledgerpoli-0.0.0/setup.py", b"import os\n")])),
    # Bytes one reader would find and another would not.
    "unicode-path-field": (WHEEL, lambda raw: _wheel([(_entry(_WHEEL[0][0], extra=b"\x75\x70\x09\x00\x01" + bytes(4)
                                                              + b"evil"), _WHEEL[0][1]), *_WHEEL[1:]])),
    "comment": (WHEEL, lambda raw: _wheel(_WHEEL, comment=b"hidden")),
    "bytes-before-the-entries": (WHEEL, lambda raw: b"prepended" + raw),
    "one-byte": (WHEEL, lambda raw: raw[:40] + bytes([raw[40] ^ 1]) + raw[41:]),
    "archive-after-the-end": (SDIST, lambda raw: gzip.compress(_tar(_SDIST) + _tar(_HIDDEN), mtime=0)),
    "zero-blocks-between-members": (SDIST, lambda raw: gzip.compress(_tar(_SDIST)[:512] + bytes(1024)
                                                                     + _tar(_SDIST)[512:], mtime=0)),
    "second-gzip-stream": (SDIST, lambda raw: raw + _sdist(_HIDDEN)),
    "bytes-after-the-gzip-stream": (SDIST, lambda raw: raw + b"trailing"),
}


@pytest.mark.parametrize("change", sorted(_CHANGES))
def test_any_byte_that_differs_from_the_rebuild_refuses(tmp_path, change):
    dist, rebuilt = _published_and_rebuilt(tmp_path)
    name, rewrite = _CHANGES[change]
    (dist / name).write_bytes(rewrite((dist / name).read_bytes()))
    assert (dist / name).read_bytes() != (rebuilt / name).read_bytes()
    with pytest.raises(ValueError, match="independent build"):
        distributions_match_rebuild(dist, rebuilt, "0.0.0")


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
    # Refused even though the rebuild holds the same member: the tagged tree itself must not make one.
    with pytest.raises(ValueError, match=match):
        distributions_match_rebuild(*_published_and_rebuilt(tmp_path, sdist=sdist), "0.0.0")


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
    with pytest.raises(ValueError, match=match):
        distributions_match_rebuild(*_published_and_rebuilt(tmp_path, sdist=[*_SDIST, (name, b"")]), "0.0.0")


@pytest.mark.parametrize("names", [
    ["finledgerpoli-0.0.0/src/CON .py"], ["finledgerpoli-0.0.0/src/COM\u00b9.py"], ["finledgerpoli-0.0.0/CONIN$"],
    ["finledgerpoli-0.0.0/del\x7f"], ["finledgerpoli-0.0.0/c\u0301", "finledgerpoli-0.0.0/\u0107"],
    ["finledgerpoli-0.0.0/\u0130.py", "finledgerpoli-0.0.0/i\u0307.py"],
], ids=["device-and-space", "device-superscript", "console", "delete", "combining", "dotted-capital"])
def test_more_names_unsafe_on_some_system_refuse(tmp_path, names):
    sdist = [*_SDIST, *((name, b"") for name in names)]
    with pytest.raises(ValueError, match="plain relative path|repeats"):
        distributions_match_rebuild(*_published_and_rebuilt(tmp_path, sdist=sdist), "0.0.0")


def test_a_wheel_member_stored_as_a_link_refuses(tmp_path):
    wheel = [*_WHEEL, (_entry("finassist/elsewhere", stat.S_IFLNK | 0o777), b"/etc")]
    with pytest.raises(ValueError, match="link or a special file"):
        distributions_match_rebuild(*_published_and_rebuilt(tmp_path, wheel=wheel), "0.0.0")


def test_a_wheel_name_that_runs_on_past_a_nul_byte_refuses(tmp_path):
    # Python's reader cuts such a name at the NUL; other readers keep all of it.
    dist, rebuilt = _published_and_rebuilt(tmp_path, wheel=[*_WHEEL, ("finassist/run.py?../evil.py", b"")])
    for folder in (dist, rebuilt):
        (folder / WHEEL).write_bytes((folder / WHEEL).read_bytes().replace(b"run.py?", b"run.py\0"))
    with pytest.raises(ValueError, match="plain relative path"):
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


_MEMBERS = [("p-1", None, 0o775), ("p-1/run.sh", b"echo\n", 0o775), ("p-1/PKG-INFO", b"Name: p\n", 0o664)]


def _built_sdist(members, mtime, owner, stamp):
    """An sdist as a build tool might write it: its own order, times and owners, and a dated gzip header."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, data, mode in members:
            member = tarfile.TarInfo(name)
            member.mtime, member.uid, member.gid, member.mode = mtime, owner, owner, mode
            member.uname, member.gname = f"user{owner}", f"group{owner}"
            if data is None:
                member.type = tarfile.DIRTYPE
            elif isinstance(data, str):  # a link to that target
                member.type, member.linkname = tarfile.SYMTYPE, data
            else:
                member.size = len(data)
            archive.addfile(member, io.BytesIO(data) if isinstance(data, bytes) else None)
    return gzip.compress(stream.getvalue(), mtime=stamp)


def test_normalizing_makes_two_builds_of_one_tree_agree_and_keeps_every_file():
    first = normalized(_built_sdist(_MEMBERS, 1_700_000_000, 1001, 5), 1_600_000_000)
    assert first == normalized(_built_sdist(_MEMBERS[::-1], 1_700_000_999, 0, 9), 1_600_000_000)
    assert first[3] == 0 and first[4:8] == bytes(4)  # the gzip header records no name and no time
    with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
        assert [(member.name, member.mode, member.mtime, member.uid, member.uname) for member in archive] == [
            ("p-1", 0o755, 1_600_000_000, 0, ""), ("p-1/PKG-INFO", 0o644, 1_600_000_000, 0, ""),
            ("p-1/run.sh", 0o755, 1_600_000_000, 0, "")]
        assert archive.extractfile("p-1/run.sh").read() == b"echo\n"
        assert archive.extractfile("p-1/PKG-INFO").read() == b"Name: p\n"


@pytest.mark.parametrize("members,match", [
    ([*_MEMBERS, ("p-1/elsewhere", "/etc", 0o777)], "link"),
    ([*_MEMBERS, ("p-1/run.sh", b"other\n", 0o644)], "repeats"),
], ids=["link", "repeated"])
def test_normalizing_refuses_an_sdist_with_a_link_or_a_repeated_member(members, match):
    with pytest.raises(ValueError, match=match):
        normalized(_built_sdist(members, 1_700_000_000, 0, 0), 1_600_000_000)


def test_normalize_rewrites_the_folders_one_sdist_in_place(tmp_path, monkeypatch, capsys):
    (tmp_path / "p-1.tar.gz").write_bytes(_built_sdist(_MEMBERS, 1_700_000_000, 1001, 5))
    (tmp_path / "p-1-py3-none-any.whl").write_bytes(b"left alone")
    monkeypatch.setattr(sys, "argv", ["normalize_sdist.py", str(tmp_path)])
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1600000000")
    normalize_sdist.main()
    assert (tmp_path / "p-1.tar.gz").read_bytes() == normalized(_built_sdist(_MEMBERS, 1, 0, 0), 1_600_000_000)
    assert (tmp_path / "p-1-py3-none-any.whl").read_bytes() == b"left alone"
    assert capsys.readouterr().out == "p-1.tar.gz normalized\n"


def test_an_sdist_that_does_not_build_the_published_wheel_refuses(tmp_path, monkeypatch):
    dist = _archives(tmp_path / "dist")

    def builds(entries):  # stands for `python -m build --wheel`, making a wheel of these entries
        def run(command, **options):
            outdir = Path(command[command.index("--outdir") + 1])
            outdir.mkdir(parents=True)
            (outdir / WHEEL).write_bytes(_wheel(entries))
        return run

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1600000000")
    monkeypatch.setattr(release_checks.subprocess, "run", builds(_WHEEL))
    sdist_builds_the_wheel(dist, "0.0.0", tmp_path / "same")
    monkeypatch.setattr(release_checks.subprocess, "run", builds([*_WHEEL, ("finassist/added.py", b"")]))
    with pytest.raises(ValueError, match="does not build the published wheel"):
        sdist_builds_the_wheel(dist, "0.0.0", tmp_path / "other")
    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        sdist_builds_the_wheel(dist, "0.0.0", tmp_path / "undated")


def test_child_processes_import_only_the_installed_wheel_while_it_is_required(monkeypatch):
    from conftest import pytest_configure, source_path
    monkeypatch.setenv("FINASSIST_REQUIRE_INSTALLED", "1")
    child = source_path({"PYTHONPATH": "src", "PYTHONSAFEPATH": "", "OTHER": "kept"})
    assert "PYTHONPATH" not in child and child["PYTHONSAFEPATH"] == "1" and child["OTHER"] == "kept"
    # The suite's own environment loses PYTHONPATH too, for the children that inherit it.
    monkeypatch.setenv("PYTHONPATH", "src")
    monkeypatch.setattr(release_checks, "installed_package", lambda root, location: None)
    pytest_configure(None)
    assert "PYTHONPATH" not in os.environ
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


DIGEST = "find . -type f -print0 | LC_ALL=C sort -z | xargs -0r sha256sum -z | sha256sum | cut -d ' ' -f 1"
ONLY_FILES = 'test -z "$(find . ! -type f ! -type d -print -quit)"'
REPRODUCIBLE = ("SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)", "export SOURCE_DATE_EPOCH",
                'git worktree add --detach "$RUNNER_TEMP/source" HEAD')


def _in_order(job, *texts):
    script = "\n".join(step.get("run", "") for step in job["steps"])
    positions = [script.index(text) for text in texts]
    assert positions == sorted(positions), texts


def test_release_workflow_is_tag_only_and_least_privilege():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    assert workflow.get("on", workflow.get(True)) == {"push": {"tags": ["v*"]}}
    assert workflow["permissions"] == {"contents": "read"}
    assert set(workflow["jobs"]) == {"build", "gates", "publish"}
    build, gates, publish = (workflow["jobs"][name] for name in ("build", "gates", "publish"))
    assert publish["needs"] == ["build", "gates"] and publish["environment"]["name"] == "pypi"
    # Both jobs build a clean checkout of the tag the same way, dated by its commit, and normalize the sdist, so an
    # honest release gives the same bytes twice.
    _in_order(build, *REPRODUCIBLE, 'python -m build --no-isolation --outdir dist "$RUNNER_TEMP/source"',
              "python scripts/normalize_sdist.py dist", "python -m twine check --strict dist/*")
    # The gates job holds no permission of its own, and tests the built archives, never the tree: it records their
    # digest, compares them with its own build byte for byte, builds the wheel from the published sdist, installs
    # the wheel by its hash, runs the whole suite against it, which refuses to start on the tree, and the demo
    # outside the checkout.
    assert gates["needs"] == "build" and "permissions" not in gates and "environment" not in gates
    _in_order(gates, DIGEST, "python scripts/ci_install.py dependencies", *REPRODUCIBLE,
              'python -m build --no-isolation --outdir "$RUNNER_TEMP/rebuilt" "$RUNNER_TEMP/source"',
              'python scripts/normalize_sdist.py "$RUNNER_TEMP/rebuilt"',
              '--distributions-match-rebuild "$RUNNER_TEMP/release/dist" "$RUNNER_TEMP/rebuilt"',
              '--sdist-builds-the-wheel "$RUNNER_TEMP/release/dist"',
              '--notes-output "$RUNNER_TEMP/notes.md"', 'cmp "$RUNNER_TEMP/notes.md" "$RUNNER_TEMP/release/release-notes.md"',
              'python scripts/ci_install.py wheel "$RUNNER_TEMP/release/dist"', "python scripts/ci_test.py",
              "finassist demo")
    checks = next(step["run"] for step in gates["steps"] if "--sdist-builds-the-wheel" in step.get("run", ""))
    assert "export SOURCE_DATE_EPOCH" in checks
    runs = [step.get("run", "") for step in gates["steps"]]
    assert not any("ci_install.py project" in run or "finassist scan" in run for run in runs)
    suite = next(step for step in gates["steps"] if step.get("run") == "python scripts/ci_test.py")
    assert suite["env"] == {"FINASSIST_REQUIRE_INSTALLED": "1"}
    downloads = [step["with"] for step in gates["steps"] if "download-artifact" in step.get("uses", "")]
    assert downloads == [{"name": "release-${{ github.sha }}", "path": "${{ runner.temp }}/release"}]
    assert next(step for step in gates["steps"] if step.get("run") == "finassist demo")["working-directory"] == (
        "${{ runner.temp }}")
    # The publishing job publishes only the files the gates job tested: right after downloading the artifact, it
    # checks the digest of every file it holds against the one the gates job recorded.
    recorded = next(step for step in gates["steps"] if step.get("id") == "gated")
    assert gates["outputs"] == {"digest": "${{ steps.gated.outputs.digest }}"} and DIGEST in recorded["run"]
    verify = publish["steps"][1]
    assert "download-artifact" in publish["steps"][0]["uses"] and DIGEST in verify["run"]
    assert all(ONLY_FILES in step["run"] and "set -euo pipefail" in step["run"] for step in (recorded, verify))
    assert verify["env"] == {"GATED": "${{ needs.gates.outputs.digest }}"} and '"$digest" = "$GATED"' in verify["run"]
    assert publish["environment"]["url"] == "https://pypi.org/project/finledgerpoli/"
    assert publish["permissions"] == {"contents": "write", "id-token": "write", "attestations": "write"}
    assert "permissions" not in build
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[^@]+@[a-f0-9]{40}", step["uses"])
    assert any("--check-environment" in step.get("run", "") for step in build["steps"])
    assert any("git diff --exit-code -- src/finassist/resources/dashboard" == step.get("run") for step in build["steps"])
    assert not any("secrets." in str(job) for job in workflow["jobs"].values())
    assert "gh release create" in publish["steps"][-1]["run"]
    publisher = publish["steps"][-2]
    assert publisher["uses"].startswith("pypa/gh-action-pypi-publish@")
    assert publisher["with"] == {"packages-dir": "release/dist/", "attestations": True}


def _step(script, folder, **environment):
    keep = {key: value for key, value in os.environ.items() if key not in {"GATED", "GITHUB_OUTPUT", "RUNNER_TEMP"}}
    return subprocess.run(["bash", "-c", script], cwd=folder, env={**keep, **environment}, capture_output=True,
                          text=True, timeout=60, shell=False).returncode


@pytest.mark.skipif(sys.platform != "linux", reason="the release's jobs run these steps on Linux")
def test_the_publishing_job_publishes_only_the_files_the_gates_job_tested(tmp_path):
    jobs = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))["jobs"]
    record = next(step["run"] for step in jobs["gates"]["steps"] if step.get("id") == "gated")
    verify = jobs["publish"]["steps"][1]["run"]
    gated = tmp_path / "gates"
    (gated / "release" / "dist").mkdir(parents=True)
    (gated / "release" / "dist" / WHEEL).write_bytes(b"wheel")
    (gated / "release" / "release-notes.md").write_bytes(b"notes")
    output = tmp_path / "output"
    assert _step(record, tmp_path, RUNNER_TEMP=str(gated), GITHUB_OUTPUT=str(output)) == 0
    digest = output.read_text(encoding="utf-8").strip().removeprefix("digest=")
    assert re.fullmatch(r"[0-9a-f]{64}", digest)

    def published(name, change=None):
        folder = Path(shutil.copytree(gated, tmp_path / name))
        if change:
            change(folder / "release")
        return folder

    assert _step(verify, published("same"), GATED=digest) == 0
    for name, change in (
            ("changed", lambda release: (release / "dist" / WHEEL).write_bytes(b"other")),
            ("added", lambda release: (release / "dist" / "extra.whl").write_bytes(b"")),
            ("link", lambda release: (release / "dist" / "extra.whl").symlink_to(release / "dist" / WHEEL)),
            ("newline", lambda release: (release / "dist" / "a\nb").write_bytes(b""))):
        assert _step(verify, published(name, change), GATED=digest) != 0, name
    assert _step(verify, published("no-digest"), GATED="") != 0
    assert _step(verify, published("unset")) != 0
    # Nor does the gates job record a digest for a link, or for an empty artifact.
    (gated / "release" / "dist" / "extra.whl").symlink_to(gated / "release" / "dist" / WHEEL)
    assert _step(record, tmp_path, RUNNER_TEMP=str(gated), GITHUB_OUTPUT=str(output)) != 0
    (tmp_path / "empty" / "release").mkdir(parents=True)
    assert _step(record, tmp_path, RUNNER_TEMP=str(tmp_path / "empty"), GITHUB_OUTPUT=str(output)) != 0


@pytest.mark.parametrize("epoch", ["", "soon", "1.5", "315532799", "\u00b9"])
def test_a_build_date_that_is_not_whole_seconds_from_1980_refuses(tmp_path, monkeypatch, epoch):
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        normalize_sdist.release_epoch(epoch)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", epoch)
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        sdist_builds_the_wheel(_archives(tmp_path / "dist"), "0.0.0", tmp_path / "work")
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        normalized(_built_sdist(_MEMBERS, 1_700_000_000, 0, 0), 0)
    assert normalize_sdist.release_epoch("315532800") == 315532800


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


EPOCH = "1767225600"  # a fixed time; the release dates both of its builds by the tagged commit


def _release_build(outdir):
    """This tree built as the release builds it: dated, with the sdist normalized."""
    environment = {**clean_environment(), "SOURCE_DATE_EPOCH": EPOCH}
    subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(outdir)], cwd=ROOT,
                   env=environment, capture_output=True, check=True, timeout=300, shell=False)
    subprocess.run([sys.executable, str(ROOT / "scripts/normalize_sdist.py"), str(outdir)], env=environment,
                   capture_output=True, check=True, timeout=60, shell=False)
    return outdir


@pytest.fixture(scope="module")
def release_build(tmp_path_factory):
    return _release_build(tmp_path_factory.mktemp("release") / "dist")


def test_built_source_distribution_contains_complete_action_bootstrap(release_build):
    archives = list(release_build.glob("finledgerpoli-*.tar.gz"))
    assert len(archives) == 1
    with tarfile.open(archives[0], "r:gz") as archive:
        prefix = archive.getmembers()[0].name.split("/")[0] + "/"
        for relative in ("actions/gate/action.yml", "actions/gate/run.py", "requirements-action.lock"):
            member = archive.extractfile(prefix + relative)
            assert member is not None and member.read() == (ROOT / relative).read_bytes()
        assert not any(".finassist" in Path(member.name).parts for member in archive.getmembers())


@pytest.mark.skipif(sys.platform != "linux", reason="releases are built on Linux; one build is enough elsewhere")
def test_two_release_builds_of_this_tree_are_byte_identical(release_build, tmp_path):
    distributions_match_rebuild(release_build, _release_build(tmp_path / "again"), _VERSION)


@pytest.mark.skipif(sys.platform != "linux", reason="releases are built on Linux; one build is enough elsewhere")
def test_the_release_sdist_builds_the_release_wheel(release_build, tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", EPOCH)
    sdist_builds_the_wheel(release_build, _VERSION, tmp_path)


@pytest.mark.parametrize("headers", ["", "## 0.3.01 - Unreleased\n\nWrong version", "## 0.3.0 - Unreleased\n\n", "## 0.3.0 - Unreleased\n\nOne\n\n## 0.3.0 - 2026-10-28\n\nTwo"])
def test_release_notes_refuse_missing_empty_or_duplicate_sections(tmp_path, headers):
    (tmp_path / "CHANGELOG.md").write_text(headers, encoding="utf-8", newline="\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "synthetic"\n', encoding="utf-8", newline="\n")
    with pytest.raises(ValueError, match="release notes"):
        release_notes(tmp_path, "0.3.0")
