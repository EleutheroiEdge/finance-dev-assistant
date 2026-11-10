"""Derive Dependabot's pip entry point from the reviewed development lock."""

import argparse
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
HEADER = (
    "# Derived by scripts/dependabot_requirements.py from requirements-dev.lock; no new dependency versions.\n"
    "# Dependabot finds requirement files by name and follows only includes that end in .txt or .in,\n"
    "# so the reviewed pins and hashes are repeated here. Change requirements-dev.lock, then rerun\n"
    "# the script.\n"
)
# pip's spellings for reading another requirements or constraints file.
INCLUDE = re.compile(r"(?m)^[ \t]*(?:-[rc]|--requirement|--constraint)")


def dependabot_requirements(source: str) -> str:
    """Return the lock's own text under a header, so no other file is needed to read it."""
    if INCLUDE.search(source):
        raise ValueError("development lock includes another requirements file")
    if "--hash=sha256:" not in source:
        raise ValueError("development lock is not hashed")
    return HEADER + source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = dependabot_requirements((ROOT / "requirements-dev.lock").read_text(encoding="utf-8"))
    path = ROOT / "requirements.txt"
    if args.check:
        if path.read_text(encoding="utf-8") != expected:
            raise SystemExit("Dependabot entry point drifted from the reviewed development lock")
    else:
        path.write_text(expected, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
