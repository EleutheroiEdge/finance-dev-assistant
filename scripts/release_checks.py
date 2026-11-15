"""Read-only release preflights; never create tags, publishers or environments."""

import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess
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
    """An active tag ruleset keeps every `v*` tag from being moved or deleted, so a release tag names one commit
    forever. A ruleset that shows anyone who can bypass it does not count."""
    for ruleset in rulesets:
        names = (ruleset.get("conditions") or {}).get("ref_name") or {}
        kinds = {rule.get("type") for rule in ruleset.get("rules", [])}
        if (ruleset.get("target") == "tag" and ruleset.get("enforcement") == "active" and not ruleset.get("bypass_actors")
                and {"refs/tags/v*", "~ALL"} & set(names.get("include", [])) and not names.get("exclude")
                and {"deletion", "update"} <= kinds):
            return
    raise ValueError("release tags need an active ruleset that blocks moving and deleting them")


def wheel_matches_tree(root, dist):
    """The one built wheel holds exactly the tree's package files, byte for byte: what is published is what was
    tagged and tested."""
    wheels = sorted(Path(dist).glob("finledgerpoli-*.whl"))
    if len(wheels) != 1:
        raise ValueError("expected exactly one built wheel")
    with zipfile.ZipFile(wheels[0]) as archive:
        packaged = {name: archive.read(name) for name in archive.namelist()
                    if name.startswith("finassist/") and not name.endswith("/")}
    source = root / "src"
    tree = {path.relative_to(source).as_posix(): path.read_bytes() for path in (source / "finassist").rglob("*")
            if path.is_file() and "__pycache__" not in path.parts}
    if set(packaged) != set(tree) or any(packaged[name] != data for name, data in tree.items()):
        raise ValueError("the wheel's package files differ from the tagged tree")
    return len(tree)


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
    parser.add_argument("--wheel-matches-tree", type=Path, metavar="DIST")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    version = validate_tag(root, args.tag)
    if args.notes_output:
        args.notes_output.write_text(release_notes(root, version), encoding="utf-8", newline="\n")
    if args.wheel_matches_tree:
        wheel_matches_tree(root, args.wheel_matches_tree)
    if args.check_environment:
        repository = os.environ["GITHUB_REPOSITORY"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid repository")

        def read(path):
            request = urllib.request.Request(
                f"https://api.github.com/repos/{repository}/{path}",
                headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json"},
            )
            with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 fixed HTTPS API
                return json.load(response)

        validate_environment(read("environments/pypi"),
                             read("environments/pypi/deployment-branch-policies").get("branch_policies", []))
        validate_tag_rules([read(f"rulesets/{int(item['id'])}") for item in read("rulesets")
                            if item.get("target") == "tag"])
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"], check=True, shell=False
        )
    print(json.dumps({"version": version, "preflight": "passed", "settings_changed": False}))


if __name__ == "__main__":
    main()
