"""Run the checks CI runs, with one command, from any directory.

    python scripts/ci.py lint         Ruff, as the workflow's `lint` job runs it
    python scripts/ci.py test         the test suite, in parallel groups
    python scripts/ci.py all          every stage, in the order CI runs them
    python scripts/ci.py lint test    any stages, in the order given

The stages are lint, test, demo, scan and wheel. Each is one command, and it is the command
the `checks` workflow runs on Linux: its `lint` job calls `python scripts/ci.py lint`, and
tests/test_ci_entry.py fails when a stage here and its step in .github/workflows/ci.yml stop
being the same command. The first stage that fails stops the run with that stage's exit code.

Install first, the way CI does, into the interpreter that runs this script. Locally that is
a virtual environment:

    python scripts/ci_install.py dependencies
    python scripts/ci_install.py project

`python` in a stage is the interpreter running this script. `ruff` and `finassist` are taken
only from that interpreter's own scripts directory, where the two commands above put them,
so a program of the same name elsewhere on PATH or in the checkout is never run.

Not covered: the Windows and macOS rows of the matrix, and the dashboard and isolation jobs.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import sysconfig
import time

ROOT = Path(__file__).resolve().parent.parent
# In CI's order: the lint job first, then the steps of the test job that follow installation.
STAGES: dict[str, tuple[str, ...]] = {
    "lint": ("ruff", "check", "src", "tests", "scripts", "actions"),
    "test": ("python", "scripts/ci_test.py"),
    "demo": ("finassist", "demo"),
    "scan": ("finassist", "scan", "--repo", "."),
    "wheel": ("python", "scripts/wheel_smoke.py"),
}
ALL = "all"


def command_line(stage: str) -> str:
    """The stage as the workflow writes it in a `run:` step."""
    return " ".join(STAGES[stage])


def expand(names: list[str]) -> list[str]:
    """The stages to run, in the order asked for; `all` stands for every stage in CI's order."""
    stages: list[str] = []
    for name in names:
        stages.extend(STAGES if name == ALL else [name])
    return stages


def program(name: str) -> str:
    """The file to run for the first word of a stage; no search of PATH or the current directory."""
    if name == "python":
        return sys.executable
    directory = Path(sysconfig.get_path("scripts"))
    for candidate in (directory / name, directory / (name + ".exe")):
        if candidate.is_file():
            return str(candidate)
    raise SystemExit(f"{name} is not installed beside {sys.executable}. Run `python scripts/ci_install.py "
                     f"dependencies` and `python scripts/ci_install.py project` with this interpreter first.")


def run(stages: list[str], root: Path = ROOT) -> int:
    """Run each stage from the repository root; stop at the first that fails and return its exit code."""
    started = time.monotonic()
    for stage in stages:
        name, *arguments = STAGES[stage]
        command = [program(name), *arguments]
        print(f"+ [{stage}] {command_line(stage)}", flush=True)
        began = time.monotonic()
        code = subprocess.run(command, cwd=root, check=False, shell=False).returncode
        print(f"[{stage}] {'passed' if code == 0 else f'FAILED (exit {code})'} in {time.monotonic() - began:.0f}s",
              flush=True)
        if code != 0:
            return code
    print(f"{len(stages)} stage{'' if len(stages) == 1 else 's'} passed in {time.monotonic() - started:.0f}s: "
          f"{', '.join(stages)}", flush=True)
    return 0


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("stages", nargs="+", choices=[*STAGES, ALL], metavar="stage",
                        help=f"one or more of {', '.join(STAGES)}, or {ALL} for every one in that order")
    return run(expand(parser.parse_args(argv).stages), root)


if __name__ == "__main__":
    raise SystemExit(main())
