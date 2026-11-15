"""Read-only release preflights; never create tags, publishers or environments."""

import argparse
import ast
import configparser
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sysconfig
import tarfile
import tomllib
import urllib.request
import zipfile

# What a build adds to the tagged tree: the sdist's metadata, and the wheel's own dist-info files.
SDIST_GENERATED = frozenset({"PKG-INFO", "setup.cfg", *(f"src/finledgerpoli.egg-info/{name}" for name in (
    "PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt", "requires.txt", "top_level.txt"))})
WHEEL_METADATA = frozenset({"licenses/LICENSE", "METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD"})


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
    included, and no one may bypass it, so a release tag names one commit for good. The other restricts creating
    one to those its bypass list names. The workflow's own token can't read a ruleset's bypass list, so it sees none:
    a bypass list it can see refuses, and the maintainer checks the list is empty before tagging."""
    def rules(ruleset):
        names = (ruleset.get("conditions") or {}).get("ref_name") or {}
        if (ruleset.get("target") != "tag" or ruleset.get("enforcement") != "active" or names.get("exclude")
                or not {"refs/tags/v*", "~ALL"} & set(names.get("include", []))):
            return {}
        return {rule.get("type"): rule.get("parameters") or {} for rule in ruleset.get("rules", [])}

    found = [(ruleset, rules(ruleset)) for ruleset in rulesets]
    if not any("deletion" in kinds and "update" in kinds and not kinds["update"].get("update_allows_fetch_and_merge")
               and not ruleset.get("bypass_actors") for ruleset, kinds in found):
        raise ValueError("release tags need an active ruleset, with no bypass, that blocks moving and deleting them")
    if not any("creation" in kinds for _ruleset, kinds in found):
        raise ValueError("release tags need an active ruleset that restricts creating them")


def _members(names, kind):
    if len(names) != len(set(names)) or any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts
                                            for name in names):
        raise ValueError(f"the {kind} repeats a file or holds a path outside itself")


def distributions_match_tree(root, dist, version):
    """`dist` holds exactly the release's wheel and sdist, and each holds the tagged tree's bytes and nothing else but
    the metadata a build writes: what is published is what was tagged and tested."""
    name = f"finledgerpoli-{version}"
    wheel, sdist = Path(dist) / f"{name}-py3-none-any.whl", Path(dist) / f"{name}.tar.gz"
    if sorted(path.name for path in Path(dist).iterdir()) != sorted([wheel.name, sdist.name]):
        raise ValueError("dist must hold exactly the release's wheel and sdist")
    source = root / "src"
    package = {path.relative_to(source).as_posix(): path.read_bytes() for path in (source / "finassist").rglob("*")
               if path.is_file() and "__pycache__" not in path.parts}
    with zipfile.ZipFile(wheel) as archive:
        names = [item.filename for item in archive.infolist() if not item.is_dir()]
        _members(names, "wheel")
        files = {item: archive.read(item) for item in names}
    info = f"{name}.dist-info/"
    scripts = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["scripts"]
    entry = configparser.ConfigParser(delimiters=("=",))
    entry.optionxform = str
    entry.read_string(files.get(info + "entry_points.txt", b"").decode("utf-8"))
    if ({item: files[item] for item in files if item.startswith("finassist/")} != package
            or {item.removeprefix(info) for item in files if not item.startswith("finassist/")} != WHEEL_METADATA
            or files[info + "licenses/LICENSE"] != (root / "LICENSE").read_bytes()
            or files[info + "top_level.txt"] != b"finassist\n"
            or entry.sections() != ["console_scripts"] or dict(entry["console_scripts"]) != scripts):
        raise ValueError("the wheel's files differ from the tagged tree")
    with tarfile.open(sdist) as archive:
        members = archive.getmembers()
        _members([member.name for member in members], "sdist")
        prefix = name + "/"
        if any(not (member.isfile() or member.isdir()) or not (member.name + "/").startswith(prefix)
               for member in members):
            raise ValueError("the sdist holds a link or a path outside its folder")
        for member in members:
            relative = member.name[len(prefix):]
            if member.isfile() and relative not in SDIST_GENERATED and (
                    not (root / relative).is_file() or archive.extractfile(member).read() != (root / relative).read_bytes()):
                raise ValueError("the sdist's files differ from the tagged tree")
    return len(package)


def installed_package(root, location):
    """The finassist the tests import is the installed wheel's, in site-packages, never the tree's `src`."""
    path, source = Path(location).resolve(), (root / "src").resolve()
    places = {Path(sysconfig.get_path(kind)).resolve() for kind in ("purelib", "platlib")}
    if path.is_relative_to(source) or not any(path.is_relative_to(place) for place in places):
        raise ValueError("the tests would import finassist from the tree, not from the installed wheel")


def read_github(repository, path, token):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/{path}",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 fixed HTTPS API
        return json.load(response)


def check_settings(repository, token):
    """The release settings, read with the workflow's own token; any read that fails stops the release."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    validate_environment(read_github(repository, "environments/pypi", token), read_github(
        repository, "environments/pypi/deployment-branch-policies?per_page=100", token).get("branch_policies", []))
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
    parser.add_argument("--distributions-match-tree", type=Path, metavar="DIST")
    parser.add_argument("--imports-installed", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    version = validate_tag(root, args.tag)
    if args.notes_output:
        args.notes_output.write_text(release_notes(root, version), encoding="utf-8", newline="\n")
    if args.distributions_match_tree:
        distributions_match_tree(root, args.distributions_match_tree, version)
    if args.imports_installed:  # after `ci_install.py wheel`: where `import finassist` would load it from
        installed_package(root, importlib.util.find_spec("finassist").origin)
    if args.check_environment:
        check_settings(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"])
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"], check=True, shell=False
        )
    print(json.dumps({"version": version, "preflight": "passed", "settings_changed": False}))


if __name__ == "__main__":
    main()
