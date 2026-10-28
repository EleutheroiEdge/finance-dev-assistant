"""Build/install in a disposable native venv on every supported OS."""

from pathlib import Path
import subprocess
import sys
import tempfile
import venv

with tempfile.TemporaryDirectory(prefix="finassist-install-") as directory:
    root = Path(directory)
    wheels = root / "wheels"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            ".",
            "--wheel-dir",
            str(wheels),
        ],
        check=True,
        shell=False,
    )
    environment = root / "environment"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    wheel = next(wheels.glob("*.whl"))
    subprocess.run(
        [str(python), "-m", "pip", "install", "-c", "requirements-dev.lock", str(wheel)],
        check=True,
        shell=False,
    )
    subprocess.run([str(python), "scripts/package_smoke.py", "examples"], check=True, shell=False)
