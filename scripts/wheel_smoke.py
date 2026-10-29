"""Build/install in a disposable native venv on every supported OS."""

from pathlib import Path
import sys
import tempfile
import venv

from ci_install import build_wheel, install_requirements, install_wheel, run

with tempfile.TemporaryDirectory(prefix="finassist-install-") as directory:
    root = Path(directory)
    wheel = build_wheel(root / "wheels")
    environment = root / "environment"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    install_requirements(python)
    install_wheel(python, wheel)
    run(python, "scripts/package_smoke.py", "examples")
