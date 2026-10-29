"""Build and test a clean installed wheel on each supported operating system."""

from pathlib import Path
import sys
import tempfile
import venv

from ci_install import ROOT, build_wheel, install_requirements, install_wheel, run

with tempfile.TemporaryDirectory(prefix="dashboard-install-") as directory:
    temporary = Path(directory).resolve()
    wheel = build_wheel(temporary / "wheels")
    environment = temporary / "venv"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    install_requirements(python)
    install_wheel(python, wheel)
    run(python, ROOT / "scripts/dashboard_smoke.py")
