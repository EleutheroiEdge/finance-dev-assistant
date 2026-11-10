"""Run the test suite as several pytest processes at once, one group of test files each.

The suite spends most of its time starting Git processes, which is slow on Windows and
macOS runners: the same tests take about 3 minutes on Linux and 26 on Windows when run
one after another. Hosted runners have several cores, so the files are dealt into groups
and each group runs in its own pytest process.

- The files are the ones pytest itself would collect under `tests/`, at any depth.
- A test file is never split: its tests stay in one process, in their usual order.
- Each group has its own temporary directory and writes no shared cache.
- A test marked `@pytest.mark.alone` asserts a time limit. Those run afterwards in one
  process with nothing else running, so other groups can't slow them past their limit.
- No extra package is needed, so the hash-locked development environment is unchanged.
- Any process that fails, fails the run, and its whole output is printed.

Usage: python scripts/ci_test.py [--groups N] [-- extra pytest arguments]
"""

from __future__ import annotations

import argparse
import fnmatch
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parent.parent
MAX_GROUPS = 8
ALONE = "alone"
# pytest's defaults for which files are tests and which directories it never enters.
PYTHON_FILES = ("test_*.py", "*_test.py")
NO_RECURSE = ("*.egg", ".*", "_darcs", "build", "CVS", "dist", "node_modules", "venv", "{arch}", "__pycache__")


def check_settings(root: Path = ROOT) -> None:
    """Stop if the project's pytest settings would collect differently from `discover`.

    This script finds test files by pytest's default rules under `tests/`. A setting that
    changes those rules would let it skip tests in silence, so it refuses to run instead.
    """
    try:
        document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    settings = document.get("tool", {}).get("pytest", {}).get("ini_options", {})
    changed = sorted(key for key in ("python_files", "norecursedirs") if key in settings)
    if settings.get("testpaths", ["tests"]) != ["tests"]:
        changed.append("testpaths")
    if changed:
        raise SystemExit(f"scripts/ci_test.py finds tests by pytest's default rules under tests/, but pyproject.toml "
                         f"sets {', '.join(changed)}. Update discover() to match before running tests in groups.")


def discover(root: Path = ROOT) -> list[Path]:
    """Every file pytest would collect from `tests/`: its default name patterns, at any depth."""
    found = []
    for directory, names, files in os.walk(root / "tests"):
        names[:] = sorted(name for name in names if not any(fnmatch.fnmatch(name, pattern) for pattern in NO_RECURSE))
        found.extend(Path(directory) / name for name in files
                     if any(fnmatch.fnmatch(name, pattern) for pattern in PYTHON_FILES))
    return sorted(found)


def has_alone_tests(file: Path) -> bool:
    return f"pytest.mark.{ALONE}" in file.read_text(encoding="utf-8", errors="replace")


def deal(files: list[Path], count: int) -> list[list[Path]]:
    """Deal files into at most `count` groups of similar total size.

    Largest first, each to the lightest group so far. The result depends only on the file
    names and sizes, so the same commit is always dealt the same way.
    """
    groups: list[list[Path]] = [[] for _ in range(max(1, count))]
    weights = [0] * len(groups)
    for file in sorted(files, key=lambda item: (-item.stat().st_size, item.as_posix())):
        lightest = weights.index(min(weights))
        groups[lightest].append(file)
        weights[lightest] += file.stat().st_size
    return [sorted(group) for group in groups if group]


def default_groups() -> int:
    return max(1, min(MAX_GROUPS, os.cpu_count() or 1))


def _start(label: str, files: list[Path], marker: str, extra: list[str], root: Path, scratch: Path):
    base = scratch / label
    base.mkdir()
    log = (base / "out.txt").open("wb")
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--basetemp={base / 't'}", "-m", marker,
               *(file.relative_to(root).as_posix() for file in files), *extra]
    return subprocess.Popen(command, cwd=root, stdout=log, stderr=subprocess.STDOUT), log, len(files)


def _finish(label: str, entry, started: float, failed: list) -> None:
    process, log, count = entry
    code = process.wait()
    log.close()
    output = Path(log.name).read_text(encoding="utf-8", errors="replace")
    lines = output.strip().splitlines()
    # Any exit but 0 fails, including 5: no process here should find that it has no tests to run.
    status = "passed" if code == 0 else f"FAILED (exit {code})"
    print(f"{label}: {count} files, finished at {time.monotonic() - started:.0f}s, {status}: "
          f"{lines[-1] if lines else 'no output'}", flush=True)
    if code != 0:
        failed.append((label, output))


def run(groups: list[list[Path]], extra: list[str], root: Path = ROOT) -> int:
    """Run every group at once, then the time-limited tests by themselves; 0 only when every process exits 0."""
    started = time.monotonic()
    timed = [file for group in groups for file in group if has_alone_tests(file)]
    failed: list[tuple[str, str]] = []
    # Short names, under the runner's own temporary directory when there is one: Windows paths
    # have a length limit, and the tests create repositories several levels down.
    with tempfile.TemporaryDirectory(prefix="ft-", dir=os.environ.get("RUNNER_TEMP") or None,
                                     ignore_cleanup_errors=True) as scratch:
        running = {f"group {number}/{len(groups)}": _start(f"g{number}", group, f"not {ALONE}", extra, root, Path(scratch))
                   for number, group in enumerate(groups, 1)}
        while running:
            for label in sorted(running):
                if running[label][0].poll() is not None:
                    _finish(label, running.pop(label), started, failed)
            time.sleep(0.5)
        if timed:
            _finish("time-limited tests, alone", _start("alone", sorted(timed), ALONE, extra, root, Path(scratch)),
                    started, failed)
        for label, output in sorted(failed):
            print(f"\n===== output of {label} =====\n{output}", flush=True)
    print(f"{len(groups)} groups{' and the time-limited tests' if timed else ''} in "
          f"{time.monotonic() - started:.0f}s; {len(failed)} failed", flush=True)
    return 1 if failed else 0


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--groups", type=int, default=default_groups(),
                        help=f"pytest processes to run at once (default: the runner's cores, at most {MAX_GROUPS})")
    parser.add_argument("pytest_args", nargs="*", help="arguments passed to every pytest process, after --")
    args = parser.parse_args(argv)
    if not 1 <= args.groups <= MAX_GROUPS:
        parser.error(f"--groups must be from 1 to {MAX_GROUPS}")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # A failing test's output may hold text the console can't encode.
    check_settings(root)
    files = discover(root)
    if not files:
        print("no test files found", file=sys.stderr)
        return 1
    return run(deal(files, args.groups), args.pytest_args, root)


if __name__ == "__main__":
    raise SystemExit(main())
