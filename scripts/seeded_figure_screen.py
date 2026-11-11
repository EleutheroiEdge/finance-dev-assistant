"""Seeded runs of the confidential-figure screen on real changes, offline.

Recall: every number of five or more significant digits that a change ADDS to a reviewable text
file is listed alone; the screen must then refuse each file that adds it.
False alarms: with 1,000 random figures listed, no file version may be refused, unless an
independent check finds one of those figures' digits in the file. That is a collision, and the
run is inconclusive: use another --seed. A control figure never ends in a zero, so its value has
one digit string however it is written, and the check reads digits in any script or escape.

A path is admitted by its name before anything in it is read: a private, credential or data
path, by the product's own path policy, is never diffed or opened. Only counts are printed,
under an anonymous number for each repository: never a number, a line, a file name or a path.
Run it with the interpreter that has the finassist under test installed:

    python scripts/seeded_figure_screen.py --changes 25 REPO [REPO ...]

With --tips, each history is read from the commit that file names for the repository, not from
--branch. Give the tips.txt that scripts/first_run_scenarios.py wrote, with the repositories in
the same order, to measure the same changes: both scripts then print the same fingerprint.

Exit status: 0 complete with no miss and no false alarm; 1 a miss or a false alarm; 2 incomplete
(a repository, branch or Git read failed, a history holds fewer changes than asked for, or a
collision made a control unusable).
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import html
import os
from pathlib import Path, PurePosixPath
import random
import re
import subprocess
import unicodedata

from finassist.errors import AssistantError
from finassist.forbidden_tokens import TokenSnapshot, normalize_numeric_token, screen_source
from finassist.security import TEXT_SUFFIXES, check_model_path

MAX_FILE_BYTES = 400_000
_NUMBER = re.compile(r"(?<![\w.])\d[\d_,]*(?:\.\d[\d_]*)?(?![\w.])")
_GROUPED = re.compile(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?")
_ESCAPE = re.compile(r"\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
# A measurement only reads, and reads the objects as they are. Without the first setting,
# `git status` may rewrite a repository's index and hold its lock for a moment, which another Git
# command in that checkout would then trip over. Without the second, a replacement ref would put
# another commit in the place of a pinned one, and the same tips would name other changes.
READ_ONLY_GIT = {"GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1"}


def git_environment() -> dict:
    """The environment of every Git command of a measurement.

    None of the caller's own Git settings come along: one of them could point a command at
    another repository, another index or another object store than the one that was named.
    """
    return {**{name: value for name, value in os.environ.items() if not name.startswith("GIT_")}, **READ_ONLY_GIT}


class Incomplete(Exception):
    """A read failed, so this repository's counts are not a whole measurement."""


def git(repo: Path, *args: str) -> bytes:
    done = subprocess.run(["git", "-C", str(repo), "--literal-pathspecs", *args], capture_output=True, check=False,
                          env=git_environment())
    if done.returncode:
        raise Incomplete("git " + args[0])
    return done.stdout


def read_tips(path: Path, count: int) -> list[str] | None:
    """The commits an earlier run wrote, one for each repository in order. None when the file is not that."""
    try:
        tips = path.read_text(encoding="utf-8").split()
    except (OSError, UnicodeError):
        return None
    return tips if len(tips) == count and all(_COMMIT.fullmatch(tip) for tip in tips) else None


def fingerprint(tips: list[str], changes: int) -> str:
    """Names a set of changes without naming a commit: the same tips, order and count give the same one."""
    return hashlib.sha256(("%d\n%s\n" % (changes, "\n".join(tips))).encode()).hexdigest()[:16]


def listing(values) -> TokenSnapshot:
    return TokenSnapshot(frozenset(hashlib.sha256(normalize_numeric_token(value).encode()).hexdigest()
                                   for value in values))


def control_figures(seed: int, count: int = 1000) -> list[str]:
    """Random figures of eight to ten digits with two decimal places, the last never a zero.

    A value that ends in a zero has more than one spelling: 123456.50 is 123456.5, and a figure
    ending .00 is a whole number. Without one, a figure's digits are the same in every spelling.
    """
    generator = random.Random(seed)
    return [f"{generator.randrange(100_000, 99_999_999)}.{generator.randrange(10)}{generator.randrange(1, 10)}"
            for _ in range(count)]


def _escaped_character(match: re.Match) -> str:
    try:
        return chr(int(match.group(1) or match.group(2) or match.group(3), 16))
    except (ValueError, OverflowError):
        # Past the last code point: not a character, so it stays as written. Before Python 3.13,
        # chr() raises OverflowError, not ValueError, for a number of 2**31 or more.
        return match.group()


_REFERENCE = re.compile(r"&#(?:([xX])([0-9a-fA-F]+)|([0-9]+))")


def _short_reference(match: re.Match) -> str:
    """The same numeric reference, short enough for html.unescape to convert.

    html.unescape converts the digits with int(), which refuses a number of more than 4,300
    digits. Leading zeros never change the number, and one with more digits than any code point
    has is written as a number just past the last one. What a reference means is left to HTML:
    which ones name a character, which are dropped and which become the replacement character.
    """
    marker = match.group(1) or ""
    digits = (match.group(2) if marker else match.group(3)).lstrip("0") or "0"
    if len(digits) > 7:
        digits = "110000" if marker else "1114112"
    return "&#" + marker + digits


def digit_lines(text: str) -> list[str]:
    """Each line's digits alone, as ASCII, read as written and with escapes and entities spelled out.

    This is the independent check for a control figure. It parses no notation: a figure is in a
    file when its digits occur in order on one line, whatever separates or decorates them. If the
    text cannot be spelled out, the measurement is incomplete: it is never taken to hold no control.
    """
    try:
        spelled = html.unescape(_REFERENCE.sub(_short_reference, _ESCAPE.sub(_escaped_character, text)))
    except (ValueError, OverflowError):
        raise Incomplete("a file could not be decoded for the collision check") from None
    return ["".join(str(unicodedata.decimal(character)) for character in line if character.isdecimal())
            for line in {*text.splitlines(), *spelled.splitlines()}]


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
    found, in_hunk = set(), False
    diff = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--no-color", base, head, "--", path)
    for line in diff.decode("utf-8", "replace").splitlines():
        # The file header ends at the first hunk. After it every line that starts with + is an added
        # line, including one whose own text starts with ++.
        in_hunk = in_hunk or line.startswith("@@")
        if in_hunk and line.startswith("+"):
            for match in _NUMBER.finditer(line[1:]):
                token = match.group().rstrip(",_")
                # `1,2,34567` is three numbers unless the commas group digits in threes.
                for part in ([token] if "," not in token or _GROUPED.fullmatch(token) else token.split(",")):
                    if len(re.sub(r"[^0-9]", "", part).strip("0")) >= 5:
                        found.add(part)
    return found


def seeded(repo: Path, tip: str, changes: int, decoys: TokenSnapshot, decoy_digits: frozenset[str]) -> collections.Counter:
    row = collections.Counter()
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
                    lines = digit_lines(text)
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
    if row["changes"] < changes:  # A short or shallow history: fewer changes than the totals would claim.
        raise Incomplete(f"history holds {row['changes']} of the {changes} changes asked for")
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("repositories", nargs="+", type=Path)
    parser.add_argument("--changes", type=int, default=25, help="First-parent changes to use in each repository")
    parser.add_argument("--branch", default="origin/main")
    parser.add_argument("--tips", type=Path,
                        help="tips.txt written by scripts/first_run_scenarios.py: read each history from the commit it "
                             "names for that repository, in the order given, not from --branch")
    parser.add_argument("--seed", type=int, default=20261110, help="Seed for the 1,000 control figures")
    args = parser.parse_args(argv)
    if args.changes < 1:
        parser.error("--changes must be at least 1")
    pinned = None
    if args.tips is not None:
        pinned = read_tips(args.tips, len(args.repositories))
        if pinned is None:
            parser.error("--tips must hold one full commit for each repository, in the order given")
    figures = control_figures(args.seed)
    decoys, decoy_digits = listing(figures), frozenset(figure.replace(".", "") for figure in figures)
    total, tips, incomplete = collections.Counter(), [], 0
    for number, repo in enumerate(args.repositories, 1):
        try:
            revision = pinned[number - 1] if pinned else args.branch
            tip = git(repo.resolve(), "rev-parse", "--verify", "--quiet", revision + "^{commit}").decode().strip()
            row = seeded(repo.resolve(), tip, args.changes, decoys, decoy_digits)
            tips.append(tip)
        except Incomplete as failure:
            incomplete += 1
            print(f"== repository {number}: INCOMPLETE ({failure})", flush=True)
            continue
        total.update(row)
        print(f"== repository {number}: {dict(sorted(row.items()))}", flush=True)
    print(f"ALL {dict(sorted(total.items()))} | repositories incomplete: {incomplete}")
    if not incomplete:
        print(f"reference set: {fingerprint(tips, args.changes)} ({len(tips)} repositories, {args.changes} changes each)")
    if incomplete or total["control_collisions"]:
        return 2
    return 1 if total["seeded_missed"] or total["false_alarms"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
