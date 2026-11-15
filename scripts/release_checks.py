"""Read-only release preflights; never create tags, publishers or environments."""

import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sysconfig
import tarfile
import tomllib
import urllib.request
import zipfile


def validate_tag(root, tag):
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) or tag != "v" + metadata["version"]:
        raise ValueError("release tag must exactly match the stable project version")
    tree = ast.parse((root / "src/finassist/__init__.py").read_text(encoding="utf-8"))
    version = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets))
    if version != metadata["version"]:
        raise ValueError("package and project versions differ")
    return metadata["version"]


def validate_environment(document, policies):
    """The pypi environment deploys only `v*` release tags. A required reviewer may be added, and is not needed: the
    release's gates job and the protected tags stand in for one."""
    if document.get("name") != "pypi":
        raise ValueError("pypi environment must exist")
    if document.get("deployment_branch_policy") != {"protected_branches": False, "custom_branch_policies": True}:
        raise ValueError("pypi environment must deploy only from named release tags")
    if sorted((policy.get("type"), policy.get("name")) for policy in policies) != [("tag", "v*")]:
        raise ValueError("pypi environment must deploy only v* release tags")


def validate_tag_rules(rulesets):
    """Two active tag rulesets cover every `v*` tag. One blocks moving and deleting a release tag, fast-forward moves
    included, so a release tag names one commit for good: no one may bypass it, so it must not also restrict
    creation, whose ruleset needs a bypass for anyone to tag at all. The other restricts creating one to those its
    bypass list names. The workflow's own token can't read a ruleset's bypass list and sees none: a list it can see,
    or a ruleset it may bypass itself, refuses, and the maintainer checks the first list is empty before tagging."""
    def rules(ruleset):
        names = (ruleset.get("conditions") or {}).get("ref_name") or {}
        if (ruleset.get("target") != "tag" or ruleset.get("enforcement") != "active" or names.get("exclude")
                or not {"refs/tags/v*", "~ALL"} & set(names.get("include", []))):
            return {}
        return {rule.get("type"): rule.get("parameters") or {} for rule in ruleset.get("rules", [])}

    found = [(ruleset, rules(ruleset)) for ruleset in rulesets]
    if not any({"deletion", "update"} <= set(kinds) and "creation" not in kinds
               and not kinds["update"].get("update_allows_fetch_and_merge") and not ruleset.get("bypass_actors")
               and ruleset.get("current_user_can_bypass", "never") == "never" for ruleset, kinds in found):
        raise ValueError("release tags need an active ruleset, with no bypass, that blocks moving and deleting them")
    if not any("creation" in kinds for _ruleset, kinds in found):
        raise ValueError("release tags need an active ruleset that restricts creating them")


def _archive(path):
    """Each member of a release archive as (name, kind, bytes), in order. A name that could stand for anything but
    itself refuses: absolute, with a backslash, an empty, `.` or `..` part, or named twice."""
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path) as archive:
            members = [(item.filename, "directory" if item.is_dir() else "file",
                        b"" if item.is_dir() else archive.read(item)) for item in archive.infolist()]
    else:
        with tarfile.open(path, "r:gz") as archive:
            members = []
            for member in archive.getmembers():
                if not (member.isfile() or member.isdir()):
                    raise ValueError(f"{path.name} holds a link or a special file")
                members.append((member.name, "directory" if member.isdir() else "file",
                                archive.extractfile(member).read() if member.isfile() else b""))
    names = [name.removesuffix("/") for name, _kind, _data in members]
    if any("\\" in name or name.startswith("/") or {"", ".", ".."} & set(name.split("/")) for name in names):
        raise ValueError(f"{path.name} holds a name that is not a plain relative path")
    if len(names) != len(set(names)):
        raise ValueError(f"{path.name} repeats a member")
    return members


def distributions_match_rebuild(dist, rebuilt, version):
    """`dist` holds exactly the release's wheel and sdist, and each is, member for member, the archive an independent
    build of the tagged tree makes: the same names in the same order, the same kinds and the same bytes, metadata
    included. The build is reproducible, so anything a compromised or broken build added, dropped or changed refuses."""
    expected = sorted([f"finledgerpoli-{version}-py3-none-any.whl", f"finledgerpoli-{version}.tar.gz"])
    for folder in (dist, rebuilt):
        if sorted(path.name for path in Path(folder).iterdir()) != expected:
            raise ValueError("dist must hold exactly the release's wheel and sdist")
    for name in expected:
        if _archive(Path(dist) / name) != _archive(Path(rebuilt) / name):
            raise ValueError(f"{name} differs from an independent build of the tagged tree")
    return len(expected)


def installed_package(root, location):
    """The finassist the tests import is the installed wheel's, in site-packages, never the tree's `src`."""
    path, source = Path(location).resolve(), (root / "src").resolve()
    places = {Path(sysconfig.get_path(kind)).resolve() for kind in ("purelib", "platlib")}
    if path.is_relative_to(source) or not any(path.is_relative_to(place) for place in places):
        raise ValueError("the tests would import finassist from the tree, not from the installed wheel")


def read_github(repository, path, token):
    """One API document. One that runs on to another page refuses: what it leaves out could be what matters."""
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/{path}",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 fixed HTTPS API
        if 'rel="next"' in (response.headers.get("Link") or ""):
            raise ValueError(f"{path} runs on to another page")
        return json.load(response)


def check_settings(repository, token):
    """The release settings, read with the workflow's own token; any read that fails stops the release."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    policies = read_github(repository, "environments/pypi/deployment-branch-policies?per_page=100", token)
    if policies.get("total_count", 0) != len(policies.get("branch_policies", [])):
        raise ValueError("the pypi environment's deployment rules were not all read")
    validate_environment(read_github(repository, "environments/pypi", token), policies["branch_policies"])
    validate_tag_rules([read_github(repository, f"rulesets/{int(item['id'])}", token)
                        for item in read_github(repository, "rulesets?per_page=100", token)
                        if item.get("target") == "tag"])


def release_notes(root, version):
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = list(re.finditer(r"^## .+$", text, re.MULTILINE))
    pattern = r"## " + re.escape(version) + r" - (?:Unreleased|\d{4}-\d{2}-\d{2})"
    matches = [index for index, heading in enumerate(headings) if re.fullmatch(pattern, heading.group())]
    if len(matches) != 1:
        raise ValueError("release notes require one exact version section")
    index = matches[0]
    end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
    section = text[headings[index].end():end].strip()
    if not section:
        raise ValueError("release notes section must not be empty")
    if tuple(map(int, version.split("."))) >= (0, 5, 0):
        upgrading = list(re.finditer(r"^### Upgrading\n(.*?)(?=^### |\Z)", section, re.MULTILINE | re.DOTALL))
        if len(upgrading) != 1 or not upgrading[0][1].strip():
            raise ValueError("release notes require one nonempty Upgrading section")
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["name"]
    return "# " + project + " " + version + "\n" + section.strip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--check-environment", action="store_true")
    parser.add_argument("--notes-output", type=Path)
    parser.add_argument("--distributions-match-rebuild", type=Path, nargs=2, metavar=("DIST", "REBUILT"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    version = validate_tag(root, args.tag)
    if args.notes_output:
        args.notes_output.write_text(release_notes(root, version), encoding="utf-8", newline="\n")
    if args.distributions_match_rebuild:
        distributions_match_rebuild(*args.distributions_match_rebuild, version)
    if args.check_environment:
        check_settings(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"])
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"], check=True, shell=False
        )
    print(json.dumps({"version": version, "preflight": "passed", "settings_changed": False}))


if __name__ == "__main__":
    main()
