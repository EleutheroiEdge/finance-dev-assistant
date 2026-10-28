"""Build and test a clean installed wheel on each supported operating system."""

from pathlib import Path
import subprocess
import sys
import tempfile
import venv


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True, shell=False)


root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="dashboard-install-") as directory:
    temporary = Path(directory).resolve()
    wheels = temporary / "wheels"
    run(
        sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", root, "--wheel-dir", wheels
    )
    environment = temporary / "venv"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    wheel = next(wheels.glob("finassist-*.whl"))
    run(python, "-m", "pip", "install", "-c", root / "requirements-dev.lock", wheel)
    run(python, root / "scripts/dashboard_smoke.py")
