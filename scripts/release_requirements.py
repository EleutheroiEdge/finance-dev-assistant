"""Build and verify a release requirements asset from the exact wheel; never publish."""

import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename


def run(*args):
    # Fixed public package index; ignore ambient package-manager overrides.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("UV_", "PIP_"))}
    subprocess.run([str(arg) for arg in args], check=True, shell=False, env=environment)


def wheel_identity(wheel: Path) -> tuple[str, str]:
    name, version, _, _ = parse_wheel_filename(wheel.name)
    if name != "finledgerpoli" or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", str(version)):
        raise ValueError("Expected a stable finledgerpoli release wheel")
    with zipfile.ZipFile(wheel) as archive:
        entries = [info for info in archive.infolist() if info.filename.endswith(".dist-info/METADATA")]
        if len(entries) != 1 or entries[0].file_size > 128_000:
            raise ValueError("Expected one bounded wheel metadata document")
        metadata = BytesParser().parsebytes(archive.read(entries[0]))
    if (metadata.get_all("Name") != ["finledgerpoli"] or metadata.get_all("Version") != [str(version)]):
        raise ValueError("Wheel filename and metadata disagree")
    return str(version), hashlib.sha256(wheel.read_bytes()).hexdigest()


def validate_dependencies(text: str) -> None:
    # Output must be portable registry pins, never local paths, options or unhashed requirements.
    for line in text.replace("\\\n", "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(.+?)((?:\s+--hash=sha256:[0-9a-f]{64})+)", line)
        if not match:
            raise ValueError("Dependency lock contains an unhashed or unsupported requirement")
        requirement = Requirement(match[1])
        pins = list(requirement.specifier)
        if (requirement.url or len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version
                or canonicalize_name(requirement.name) == "finledgerpoli"):
            raise ValueError("Dependency lock must contain exact runtime registry pins only")


def verify_install(wheel: Path, requirements: Path, dependencies: Path, root: Path) -> None:
    environment = root / "environment"
    venv.EnvBuilder(with_pip=True).create(environment)
    binaries = environment / ("Scripts" if sys.platform == "win32" else "bin")
    python = binaries / ("python.exe" if sys.platform == "win32" else "python")
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir()
    # Resolve no package during installation. Download only the already hash-pinned
    # runtime dependencies, then use the exact unpublished wheel built by this job.
    if dependencies.read_text(encoding="utf-8").strip():
        run(python, "-m", "pip", "--isolated", "download", "--disable-pip-version-check",
            "--require-hashes", "--only-binary=:all:", "--index-url", "https://pypi.org/simple",
            "-r", dependencies, "--dest", wheelhouse)
    shutil.copyfile(wheel, wheelhouse / wheel.name)
    run(python, "-m", "pip", "--isolated", "install", "--disable-pip-version-check",
        "--require-hashes", "--only-binary=:all:", "--no-index", "--find-links", wheelhouse,
        "-r", requirements)
    run(python, "-m", "pip", "--isolated", "check")
    run(binaries / ("finassist.exe" if sys.platform == "win32" else "finassist"), "doctor")


def generate(wheel: Path, output: Path) -> Path:
    wheel = wheel.resolve(strict=True)
    version, wheel_hash = wheel_identity(wheel)
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"finledgerpoli-{version}-requirements.txt"
    if target.exists():
        raise ValueError("Refusing to replace an existing release requirements asset")
    with tempfile.TemporaryDirectory(prefix="finassist-release-lock-") as directory:
        root = Path(directory)
        source = root / "requirements.in"
        # uv reads dependencies from this exact wheel's METADATA, not pyproject.toml
        # or a possibly different distribution already published under the version.
        source.write_text("finledgerpoli @ " + wheel.as_uri() + "\n", encoding="utf-8")
        config = root / "uv.toml"
        config.write_text("", encoding="utf-8")
        dependencies = root / "dependencies.txt"
        run(sys.executable, "-m", "uv", "pip", "compile", source, "--config-file", config,
            "--default-index", "https://pypi.org/simple", "--keyring-provider", "disabled",
            "--universal", "--python-version", "3.11", "--no-python-downloads", "--no-build",
            "--generate-hashes", "--no-emit-package", "finledgerpoli", "--no-header", "--no-annotate",
            "--output-file", dependencies)
        locked = dependencies.read_text(encoding="utf-8")
        validate_dependencies(locked)
        asset = root / target.name
        asset.write_text(
            f"# Exact finledgerpoli {version} release wheel and runtime dependencies.\n"
            "# Universal resolution for Python >=3.11; hashes include platform distributions.\n"
            "# Release job verifies installation on its Python/OS; availability on others may differ.\n"
            f"finledgerpoli=={version} --hash=sha256:{wheel_hash}\n" + locked,
            encoding="utf-8", newline="\n")
        verify_install(wheel, asset, dependencies, root)
        # No final asset exists until the real clean-venv installation and doctor pass.
        with target.open("xb") as stream:
            stream.write(asset.read_bytes())
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, default=Path("release-assets"))
    args = parser.parse_args()
    wheels = list(args.dist.glob("*.whl"))
    if len(wheels) != 1:
        parser.error("Expected exactly one release wheel")
    asset = generate(wheels[0], args.output)
    print(json.dumps({"requirements_asset": str(asset),
                      "sha256": hashlib.sha256(asset.read_bytes()).hexdigest(), "clean_install_verified": True}))


if __name__ == "__main__":
    main()
