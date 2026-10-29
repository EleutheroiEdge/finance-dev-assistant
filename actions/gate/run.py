"""Bootstrap only trusted pinned action source, never the target PR's package."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv


def _bootstrap(environment) -> int:
    if sys.platform != "linux" or sys.version_info < (3, 11) or environment.get("GITHUB_ACTIONS") != "true":
        print("finassist CI setup refused: Linux GitHub runner with Python 3.11+ required", file=sys.stderr)
        return 2
    # -I removes the target cwd/PYTHONPATH from imports. Install only the action's
    # own trusted checkout with an isolated pip and hash-locked binary dependencies.
    root = Path(__file__).resolve().parents[2]
    directory = Path(tempfile.mkdtemp(prefix="finassist-action-", dir=environment["RUNNER_TEMP"]))
    executable = directory / "venv" / "bin" / "python"
    allowed = {key: environment[key] for key in ("PATH", "SYSTEMROOT", "TEMP", "TMP") if key in environment}
    allowed.update(PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    try:
        venv.EnvBuilder(with_pip=True).create(directory / "venv")
        with (directory / "install.log").open("wb") as log:
            commands = [
                [str(executable), "-I", "-m", "pip", "--isolated", "install", "--disable-pip-version-check",
                 "--index-url", "https://pypi.org/simple", "--only-binary=:all:", "--require-hashes",
                 "-r", str(root / "requirements-action.lock")],
                [str(executable), "-I", "-m", "pip", "--isolated", "install", "--disable-pip-version-check",
                 "--no-deps", "--no-build-isolation", str(root)],
            ]
            for command in commands:
                subprocess.run(command, cwd=directory, env=allowed, stdout=log, stderr=log,
                               check=True, timeout=300, shell=False)
        return subprocess.run([str(executable), "-I", "-m", "finassist.github_actions"],
                              cwd=directory, env=dict(environment), check=False, shell=False).returncode
    except (OSError, subprocess.SubprocessError):
        print("finassist CI setup failed: dependency or trusted-package installation unavailable", file=sys.stderr)
        return 2


def bootstrap(environment) -> int:
    try:
        return _bootstrap(environment)
    except (OSError, ValueError, KeyError):
        print("finassist CI setup failed: runner input or private workspace unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(bootstrap(os.environ))
