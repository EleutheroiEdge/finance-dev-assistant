"""Run the test suite as several pytest processes at once, one group of test files each.

The suite spends most of its time starting Git processes, which is slow on Windows and
macOS runners: the same tests take about 3 minutes on Linux and 26 on Windows when run
one after another. Hosted runners have several cores, so the files are dealt into groups
and each group runs in its own pytest process.

- A test file is never split: its tests stay in one process, in their usual order.
- Each group has its own temporary directory and writes no shared cache.
- No extra package is needed, so the hash-locked development environment is unchanged.
- Any group that fails, fails the run, and its whole output is printed.

Usage: python scripts/ci_test.py [--groups N] [-- extra pytest arguments]
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
MAX_GROUPS = 8


def deal(files: list[Path], count: int) -> list[list[Path]]:
    """Deal files into at most `count` groups of similar total size.

    Largest first, each to the lightest group so far. The result depends only on the file
    names and sizes, so the same commit is always dealt the same way.
    """
    groups: list[list[Path]] = [[] for _ in range(max(1, count))]
    weights = [0] * len(groups)
    for file in sorted(files, key=lambda item: (-item.stat().st_size, item.name)):
        lightest = weights.index(min(weights))
        groups[lightest].append(file)
        weights[lightest] += file.stat().st_size
    return [sorted(group) for group in groups if group]


def default_groups() -> int:
    return max(1, min(MAX_GROUPS, os.cpu_count() or 1))


def run(groups: list[list[Path]], extra: list[str], root: Path = ROOT) -> int:
    """Run every group at once; 0 only when each pytest process exits 0."""
    started = time.monotonic()
    # Short names, under the runner's own temporary directory when there is one: Windows paths
    # have a length limit, and the tests create repositories several levels down.
    with tempfile.TemporaryDirectory(prefix="ft-", dir=os.environ.get("RUNNER_TEMP") or None,
                                     ignore_cleanup_errors=True) as scratch:
        running = {}
        for number, group in enumerate(groups, 1):
            base = Path(scratch) / f"g{number}"
            base.mkdir()
            log = (base / "out.txt").open("wb")
            command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--basetemp={base / 't'}",
                       *(file.relative_to(root).as_posix() for file in group), *extra]
            running[number] = (subprocess.Popen(command, cwd=root, stdout=log, stderr=subprocess.STDOUT), log, group)
        failed = []
        while running:
            for number in sorted(running):
                process, log, group = running[number]
                code = process.poll()
                if code is None:
                    continue
                del running[number]
                log.close()
                output = Path(log.name).read_text(encoding="utf-8", errors="replace")
                lines = output.strip().splitlines()
                status = "passed" if code == 0 else f"FAILED (exit {code})"
                print(f"group {number}/{len(groups)}: {len(group)} files, finished at {time.monotonic() - started:.0f}s, "
                      f"{status}: {lines[-1] if lines else 'no output'}", flush=True)
                if code != 0:
                    failed.append((number, output))
            time.sleep(0.5)
        for number, output in sorted(failed):
            print(f"\n===== output of group {number} =====\n{output}", flush=True)
    print(f"{len(groups)} groups in {time.monotonic() - started:.0f}s; {len(failed)} failed", flush=True)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--groups", type=int, default=default_groups(),
                        help=f"pytest processes to run at once (default: the runner's cores, at most {MAX_GROUPS})")
    parser.add_argument("pytest_args", nargs="*", help="arguments passed to every pytest process, after --")
    args = parser.parse_args(argv)
    if not 1 <= args.groups <= MAX_GROUPS:
        parser.error(f"--groups must be from 1 to {MAX_GROUPS}")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # A failing test's output may hold text the console can't encode.
    files = sorted((ROOT / "tests").glob("test_*.py"))
    if not files:
        print("no test files found", file=sys.stderr)
        return 1
    return run(deal(files, args.groups), args.pytest_args)


if __name__ == "__main__":
    raise SystemExit(main())
