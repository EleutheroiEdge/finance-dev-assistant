"""A .gitignore change that only appends ordinary patterns can only make more paths ignored, so it no longer needs
separate review; any other change to a rule file still does. Git itself is the oracle for the first claim.
Synthetic repositories only.
"""

import os
import subprocess
import sys

import pytest

from conftest import command
from test_model_gate import gate_case, run  # noqa: F401 - fixture registration
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration
from finassist.onboarding import policy_preflight
from finassist.policy_ignores import only_appends_patterns
from finassist.scope import git_command, git_environment

CODE = "gate_ignore_change_requires_review"


def _commit(repo, files: dict) -> str:
    for name, content in files.items():
        target = repo / name
        if content is None:
            target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    if files:
        command(repo, "add", "--force", "--all", "--", *files)  # exactly these paths, deletions included
    command(repo, "commit", "-q", "--allow-empty", "-m", "Synthetic rule change")
    return command(repo, "rev-parse", "HEAD")


def _repo(tmp_path, before: dict, after: dict):
    repo = tmp_path / "repository"
    repo.mkdir()
    command(repo, "init", "-q", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    base = _commit(repo, {"README.md": b"synthetic\n", **before})
    return repo, base, _commit(repo, after)


APPENDS = [
    ({".gitignore": b"build/\n"}, {".gitignore": b"build/\n*.log\n"}),
    ({}, {"tools/.gitignore": b"*.log\n"}),  # a new rule file of ordinary patterns, refused before
    ({".gitignore": b"build/\n"}, {".gitignore": b"build/\n\n# reports are generated\nreports/\n"}),
    ({".gitignore": b"build/\n"}, {".gitignore": b"build/\n\\!literal-bang\n\\#literal-hash\n"}),
    ({".gitignore": b"build/\r\n"}, {".gitignore": b"build/\r\n*.log\r\n"}),
    ({".gitignore": b"*.log\n!keep.log\n"}, {".gitignore": b"*.log\n!keep.log\n*.tmp\n"}),
]
NOT_APPENDS = [
    ({".gitignore": b"*.log\n"}, {".gitignore": b"*.log\n!keep.log\n"}),  # an added negation
    ({}, {"src/.gitignore": b"!*.log\n"}),
    ({".gitignore": b"build/\n*.log\n"}, {".gitignore": b"build/\n"}),  # a removed line
    ({".gitignore": b"build/\n"}, {".gitignore": b"build\n"}),  # an edited line
    ({".gitignore": b"*.log\n!keep.log\n"}, {".gitignore": b"!keep.log\n*.log\n"}),  # reordered
    ({".gitignore": b"*.log\n"}, {".gitignore": b"*.tmp\n*.log\n"}),  # inserted before, not appended
    ({".gitignore": b"build/"}, {".gitignore": b"build/\n*.log\n"}),  # the older version has no final newline
    ({}, {".gitignore": b"\xef\xbb\xbf!keep.log\n"}),  # Git skips the mark, so this is a negation
    ({".gitignore": b"build/\n"}, {".gitignore": b"build/\n\xef\xbb\xbf*.log\n"}),
    ({".gitignore": b"build/\n"}, {".gitignore": b"build/\n\xff.log\n"}),  # not UTF-8
    ({".gitignore": b"build/\n"}, {".gitignore": b"build/\n*.log\x00!keep.log\n"}),
    ({".gitignore": b"build/\n"}, {".gitignore": None}),  # deleted
    ({".gitignore": b"build/\n"}, {".gitignore": b""}),  # emptied
]


def _changed(before: dict, after: dict) -> str:
    (name,) = {*before, *after} - {"README.md"}
    return name


@pytest.mark.parametrize("before,after", APPENDS)
def test_appended_ordinary_patterns_need_no_review(tmp_path, before, after):
    repo, base, head = _repo(tmp_path, before, after)
    assert only_appends_patterns(repo, {base}, head, _changed(before, after))


@pytest.mark.parametrize("before,after", NOT_APPENDS)
def test_any_other_rule_file_change_still_needs_review(tmp_path, before, after):
    repo, base, head = _repo(tmp_path, before, after)
    assert not only_appends_patterns(repo, {base}, head, _changed(before, after))


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs POSIX here")
def test_a_rule_file_that_becomes_a_link_still_needs_review(tmp_path):
    repo, base, _head = _repo(tmp_path, {".gitignore": b"build/\n", "rules.txt": b"build/\n*.log\n"}, {})
    (repo / ".gitignore").unlink()
    os.symlink("rules.txt", repo / ".gitignore")
    command(repo, "add", "--force", "--all", "--", ".gitignore")
    head = _commit(repo, {})
    assert not only_appends_patterns(repo, {base}, head, ".gitignore")


# Git as the oracle: wherever the predicate accepts, every path Git ignored before it still ignores, under either
# setting of core.ignorecase. The candidates cover nested files, existing negations, directories, ** and escapes.
CANDIDATES = ["a.log", "keep.log", "notes.tmp", "README.TXT", "build/x.txt", "logs/app.txt", "src/a.log",
              "src/keep.log", "src/deep/cache/x.bin", "cache/y.bin", "#literal-hash", "!literal-bang"]
ORACLE = [
    ({".gitignore": b"*.log\n!keep.log\n"}, {".gitignore": b"*.log\n!keep.log\nbuild/\n"}),
    ({".gitignore": b"*.log\n!keep.log\n"}, {"src/.gitignore": b"*.log\n"}),
    ({".gitignore": b"*.tmp\n"}, {".gitignore": b"*.tmp\nlogs/\n"}),
    ({".gitignore": b"*.tmp\n"}, {".gitignore": b"*.tmp\n**/cache\n"}),
    ({".gitignore": b"*.tmp\n"}, {".gitignore": b"*.tmp\n\\#literal-hash\n\\!literal-bang\n"}),
    ({".gitignore": b"*.log\r\n"}, {".gitignore": b"*.log\r\n*.tmp\r\n"}),
    ({".gitignore": b"*.tmp\n!notes.tmp\n"}, {".gitignore": b"*.tmp\n!notes.tmp\n*.txt\n"}),
]


def _ignored(directory, rules: dict, ignorecase: str) -> set[str]:
    directory.mkdir()
    subprocess.run(git_command(directory, "init", "-q"), env=git_environment(), check=True, capture_output=True)
    for name in CANDIDATES:
        (directory / name).parent.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text("synthetic\n", encoding="utf-8")
    for name, content in rules.items():
        if content is not None:
            (directory / name).parent.mkdir(parents=True, exist_ok=True)
            (directory / name).write_bytes(content)
    done = subprocess.run(git_command(directory, "-c", "core.ignorecase=" + ignorecase, "check-ignore", "--no-index",
                                      "-z", "--stdin"),
                          input=("\0".join(CANDIDATES) + "\0").encode(), env=git_environment(), capture_output=True)
    assert done.returncode in {0, 1}
    return {name for name in done.stdout.decode().split("\0") if name}


@pytest.mark.parametrize("ignorecase", ["false", "true"])
@pytest.mark.parametrize("before,after", ORACLE)
def test_git_ignores_at_least_as_much_after_an_accepted_change(tmp_path, before, after, ignorecase):
    repo, base, head = _repo(tmp_path, before, after)
    for name in {*before, *after} - {"README.md"}:
        assert only_appends_patterns(repo, {base}, head, name)
    merged = {**before, **after}
    assert _ignored(tmp_path / "before", before, ignorecase) <= _ignored(tmp_path / "after", merged, ignorecase)


def test_the_oracle_sees_what_a_refused_negation_would_have_done(tmp_path):
    before, after = {".gitignore": b"*.log\n"}, {".gitignore": b"*.log\n!keep.log\n"}
    repo, base, head = _repo(tmp_path, before, after)
    assert not only_appends_patterns(repo, {base}, head, ".gitignore")
    assert "keep.log" in _ignored(tmp_path / "before", before, "false") - _ignored(tmp_path / "after", after, "false")


# The gate and doctor ask the same question and give the same answer.
def _rule_change(case, files: dict) -> None:
    case["head"] = _commit(case["repo"], files)


def _both(case) -> tuple[bool, bool]:
    report, _calls = run(case)
    preflight = policy_preflight(case["repo"], case["base"], case["head"], "gate-policy.json", case["pin"])
    return CODE in report["reasons"], CODE in [entry["code"] for entry in preflight["blockers"]]


@pytest.mark.parametrize("files,needs_review", [
    ({"src/.gitignore": b"*.tmp\n"}, False),
    ({"src/.gitignore": b"!*.tmp\n"}, True),
    ({"src/.gitignore": b"*.tmp\n", "src/deep/.gitignore": b"!keep.tmp\n"}, True),  # one unsafe among safe ones
])
def test_the_gate_and_doctor_agree(gate_case, files, needs_review):  # noqa: F811
    _rule_change(gate_case, files)
    assert _both(gate_case) == (needs_review, needs_review)


def test_a_branch_behind_a_base_that_added_a_rule_still_needs_review(gate_case):  # noqa: F811
    # The base gains a rule after the branch was cut. Merge base to head changes no rule file; base to head drops
    # the rule, so the range would review without it. Both comparisons are checked.
    repo, head = gate_case["repo"], gate_case["head"]
    command(repo, "switch", "-q", "-c", "base-ahead", gate_case["base"])
    gate_case["base"] = _commit(repo, {"src/.gitignore": b"*.tmp\n"})
    command(repo, "switch", "-q", "--detach", head)
    assert _both(gate_case) == (True, True)
