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


def validate_environment(document):
    if document.get("name") != "pypi" or not any(
        rule.get("type") == "required_reviewers" and rule.get("reviewers")
        for rule in document.get("protection_rules", [])
    ):
        raise ValueError("pypi environment must exist and have a required human reviewer")


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
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["name"]
    return "# " + project + " " + version + "\n" + section.strip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--check-environment", action="store_true")
    parser.add_argument("--notes-output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    version = validate_tag(root, args.tag)
    if args.notes_output:
        args.notes_output.write_text(release_notes(root, version), encoding="utf-8", newline="\n")
    if args.check_environment:
        repository = os.environ["GITHUB_REPOSITORY"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid repository")
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/environments/pypi",
            headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 fixed HTTPS API
            validate_environment(json.load(response))
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"], check=True, shell=False
        )
    print(json.dumps({"version": version, "preflight": "passed", "settings_changed": False}))


if __name__ == "__main__":
    main()
