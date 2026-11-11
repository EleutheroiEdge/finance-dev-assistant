"""Seeded runs of the confidential-figure screen on real changes, offline.

Recall: every number of five or more significant digits that a change ADDS is listed alone; the
screen must then refuse the file that holds it.
False alarms: with 1,000 random figures that are in no file, no file version may be refused.

Only counts are printed: never a number, a line or a file name. Run it with the interpreter that
has the finassist under test installed:

    python scripts/seeded_figure_screen.py --changes 25 REPO [REPO ...]
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
from finassist.security import TEXT_SUFFIXES

MAX_FILE_BYTES = 400_000
_NUMBER = re.compile(r"(?<![\w.])\d[\d_,]*(?:\.\d[\d_]*)?(?![\w.])")
_GROUPED = re.compile(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?")


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False).stdout


def listing(values) -> TokenSnapshot:
    return TokenSnapshot(frozenset(hashlib.sha256(normalize_numeric_token(value).encode()).hexdigest()
                                   for value in values))


def outcome(text: str, path: str, snapshot: TokenSnapshot) -> str | None:
    try:
        screen_source(text, path, snapshot)
    except AssistantError as exc:
        return exc.code
    return None


def text_at(repo: Path, revision: str, path: str) -> str | None:
    data = git(repo, "show", f"{revision}:{path}")
    if not 0 < len(data) <= MAX_FILE_BYTES:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeError:
        return None


def added_numbers(repo: Path, base: str, head: str) -> dict[str, set[str]]:
    """Numbers of five or more significant digits on lines the change adds, with the files that add them."""
    found = collections.defaultdict(set)
    current = None
    diff = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", base, head).decode("utf-8", "replace")
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("+") and current and PurePosixPath(current).suffix.lower() in TEXT_SUFFIXES:
            for match in _NUMBER.finditer(line[1:]):
                token = match.group().rstrip(",_")
                # `1,2,34567` is three numbers unless the commas group digits in threes.
                for part in ([token] if "," not in token or _GROUPED.fullmatch(token) else token.split(",")):
                    if len(re.sub(r"[^0-9]", "", part).strip("0")) >= 5:
                        found[part].add(current)
    return found


def seeded(repo: Path, branch: str, changes: int, per_change: int, decoys: TokenSnapshot) -> collections.Counter:
    row = collections.Counter()
    for commit in git(repo, "rev-list", "--first-parent", "-n", str(changes), branch).decode().split():
        parents = git(repo, "rev-list", "--parents", "-n", "1", commit).decode().split()[1:]
        if not parents:
            continue
        found = added_numbers(repo, parents[0], commit)
        texts = {path: text_at(repo, commit, path) for paths in found.values() for path in paths}
        for token in sorted(found)[:per_change]:
            try:
                snapshot = listing([token])
            except AssistantError:
                continue  # Not a number a list can hold.
            results = {outcome(texts[path], path, snapshot) for path in found[token] if texts[path]}
            if "forbidden_token_present" in results:
                row["seeded_refused"] += 1
            elif results - {None}:
                row["seeded_refused_unreadable"] += 1
            elif results:
                row["seeded_missed"] += 1
        names = git(repo, "diff", "--no-renames", "--name-only", "-z", parents[0], commit).decode("utf-8", "replace")
        for path in filter(None, names.split("\0")):
            if PurePosixPath(path).suffix.lower() not in TEXT_SUFFIXES:
                continue
            for revision in (parents[0], commit):
                text = text_at(repo, revision, path)
                if text is not None:
                    row["file_versions"] += 1
                    row["false_alarms"] += outcome(text, path, decoys) == "forbidden_token_present"
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("repositories", nargs="+", type=Path)
    parser.add_argument("--changes", type=int, default=25, help="First-parent changes to use in each repository")
    parser.add_argument("--branch", default="origin/main")
    parser.add_argument("--per-change", type=int, default=60, help="Seeded numbers tried per change")
    args = parser.parse_args(argv)
    generator = random.Random(20261110)
    decoys = listing(f"{generator.randrange(100_000, 99_999_999)}.{generator.randrange(100):02d}" for _ in range(1000))
    total = collections.Counter()
    for repo in args.repositories:
        row = seeded(repo.resolve(), args.branch, args.changes, args.per_change, decoys)
        total.update(row)
        print(f"== {repo.resolve().name}: {dict(sorted(row.items()))}", flush=True)
    print(f"ALL {dict(sorted(total.items()))}")
    return 1 if total["seeded_missed"] or total["false_alarms"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
