"""Seeded runs of the confidential-figure screen on real changes, offline.

Recall: every number of five or more significant digits that a change ADDS to a reviewable text
file is listed alone; the screen must then refuse each file that adds it.
False alarms: with 1,000 random figures listed, no file version may be refused, unless an
independent check finds one of those figures' digits in the file. That is a collision, and the
run is inconclusive: use another --seed.

A path is admitted by its name before anything in it is read: a private, credential or data
path, by the product's own path policy, is never diffed or opened. Only counts are printed,
under an anonymous number for each repository: never a number, a line, a file name or a path.
Run it with the interpreter that has the finassist under test installed:

    python scripts/seeded_figure_screen.py --changes 25 REPO [REPO ...]

Exit status: 0 complete with no miss and no false alarm; 1 a miss or a false alarm; 2 incomplete
(a repository, branch or Git read failed, or a collision made a control unusable).
"""

from __future__ import annotations

import argparse
import collections
import hashlib
from pathlib import Path, PurePosixPath
import random
import re
import subprocess

from finassist.errors import AssistantError
from finassist.forbidden_tokens import TokenSnapshot, normalize_numeric_token, screen_source
from finassist.security import TEXT_SUFFIXES, check_model_path

MAX_FILE_BYTES = 400_000
_NUMBER = re.compile(r"(?<![\w.])\d[\d_,]*(?:\.\d[\d_]*)?(?![\w.])")
_GROUPED = re.compile(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?")
_NOT_DIGIT = re.compile(r"\D+")


class Incomplete(Exception):
    """A read failed, so this repository's counts are not a whole measurement."""


def git(repo: Path, *args: str) -> bytes:
    done = subprocess.run(["git", "-C", str(repo), "--literal-pathspecs", *args], capture_output=True, check=False)
    if done.returncode:
        raise Incomplete(args[0])
    return done.stdout


def listing(values) -> TokenSnapshot:
    return TokenSnapshot(frozenset(hashlib.sha256(normalize_numeric_token(value).encode()).hexdigest()
                                   for value in values))


def outcome(text: str, path: str, snapshot: TokenSnapshot) -> str | None:
    try:
        screen_source(text, path, snapshot)
    except AssistantError as exc:
        return exc.code
    return None


def admitted(path: str) -> str | None:
    """None when the path may be read here; otherwise why it is left out. Decided by name alone."""
    if PurePosixPath(path).suffix.lower() not in TEXT_SUFFIXES:
        return "paths_not_text"
    try:
        check_model_path(path, source_only=False)
    except AssistantError:
        return "paths_private"
    return None


ABSENT = object()  # The path has no file at that revision: nothing to read, and no gap in coverage.


def text_at(repo: Path, revision: str, path: str):
    """The file's text at a revision; ABSENT when there is none; None when it is too large or not UTF-8."""
    listed = git(repo, "ls-tree", "-z", "--long", revision, "--", path)
    if not listed:
        return ABSENT
    size = listed.split(b"\t", 1)[0].split()[-1]
    if not size.isdigit() or int(size) > MAX_FILE_BYTES:
        return None
    try:
        return git(repo, "cat-file", "blob", f"{revision}:{path}").decode("utf-8")
    except UnicodeError:
        return None


def added_numbers(repo: Path, base: str, head: str, path: str) -> set[str]:
    """Numbers of five or more significant digits on the lines the change adds to one admitted file."""
    found = set()
    diff = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", base, head, "--", path)
    for line in diff.decode("utf-8", "replace").splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            for match in _NUMBER.finditer(line[1:]):
                token = match.group().rstrip(",_")
                # `1,2,34567` is three numbers unless the commas group digits in threes.
                for part in ([token] if "," not in token or _GROUPED.fullmatch(token) else token.split(",")):
                    if len(re.sub(r"[^0-9]", "", part).strip("0")) >= 5:
                        found.add(part)
    return found


def seeded(repo: Path, branch: str, changes: int, decoys: TokenSnapshot, decoy_digits: frozenset[str]) -> collections.Counter:
    row = collections.Counter()
    tip = git(repo, "rev-parse", "--verify", "--quiet", branch + "^{commit}").decode().strip()
    commits = git(repo, "rev-list", "--first-parent", "-n", str(changes), tip).decode().split()
    for commit in commits:
        parents = git(repo, "rev-list", "--parents", "-n", "1", commit).decode().split()[1:]
        if not parents:
            continue
        row["changes"] += 1
        names = git(repo, "diff", "--no-renames", "--name-only", "-z", parents[0], commit).decode("utf-8", "replace")
        for path in filter(None, names.split("\0")):
            reason = admitted(path)
            if reason:
                row[reason] += 1
                continue
            after = text_at(repo, commit, path)
            for text in (text_at(repo, parents[0], path), after):
                if text is ABSENT:
                    continue
                if text is None:
                    row["file_versions_not_read"] += 1
                    continue
                row["file_versions"] += 1
                if outcome(text, path, decoys) == "forbidden_token_present":
                    # Independent of the screen: do a control figure's digits occur on any line of the file?
                    lines = [_NOT_DIGIT.sub("", line) for line in text.splitlines()]
                    present = any(figure in line for line in lines for figure in decoy_digits if len(line) >= len(figure))
                    row["control_collisions" if present else "false_alarms"] += 1
            if after is None or after is ABSENT:
                continue
            for token in sorted(added_numbers(repo, parents[0], commit, path)):
                try:
                    snapshot = listing([token])
                except AssistantError:
                    continue  # Not a number a list can hold.
                result = outcome(after, path, snapshot)
                row["seeded_refused" if result == "forbidden_token_present"
                    else "seeded_refused_unreadable" if result else "seeded_missed"] += 1
    if not row["changes"]:
        raise Incomplete("no changes")
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("repositories", nargs="+", type=Path)
    parser.add_argument("--changes", type=int, default=25, help="First-parent changes to use in each repository")
    parser.add_argument("--branch", default="origin/main")
    parser.add_argument("--seed", type=int, default=20261110, help="Seed for the 1,000 control figures")
    args = parser.parse_args(argv)
    if args.changes < 1:
        parser.error("--changes must be at least 1")
    generator = random.Random(args.seed)
    figures = [f"{generator.randrange(100_000, 99_999_999)}.{generator.randrange(100):02d}" for _ in range(1000)]
    decoys, decoy_digits = listing(figures), frozenset(figure.replace(".", "") for figure in figures)
    total, incomplete = collections.Counter(), 0
    for number, repo in enumerate(args.repositories, 1):
        try:
            row = seeded(repo.resolve(), args.branch, args.changes, decoys, decoy_digits)
        except Incomplete as failure:
            incomplete += 1
            print(f"== repository {number}: INCOMPLETE (git {failure})", flush=True)
            continue
        total.update(row)
        print(f"== repository {number}: {dict(sorted(row.items()))}", flush=True)
    print(f"ALL {dict(sorted(total.items()))} | repositories incomplete: {incomplete}")
    if incomplete or total["control_collisions"]:
        return 2
    return 1 if total["seeded_missed"] or total["false_alarms"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
