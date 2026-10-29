"""Hash-verify CI dependencies and locally built wheels; never publish artifacts."""

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import platform
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
# npm registry distribution integrity values for the native packages used by the CI matrix.
PNPM_INTEGRITY = {
    "linux-x64": "sha512-+M5N74hM4fc87AAckxx/UIW+dUnWf2eko+HchJs/NZUxehLhekNyMI/GNaNXlvd+kWR+97XXBD51XRkkNiUtrA==",
    "darwin-arm64": "sha512-+7iiEEBgYN9szPWUnAuN6eOVMTI6Hrki5bcuC9n9xl9tTnT53Tpxpo45Hml+W4IrAU0d+Tmd0sPnVIbX59PD6w==",
    "darwin-x64": "sha512-SK7TxJiR12GbJZGffRFHItkc+Mx+99v6xMMJ9/X//8NwWV1wo17a2bwfGI8qZpl17YwsrmPEFOOqhzE1GIlrtQ==",
    "win32-x64": "sha512-SWoDMT0oD7NrDSIoPpkKD09D9fAQKNjwFZ3lezlCUhAfXxMv70zsfrNT2/P+GoCK2kefXF9OysUZkH1l5vvvfA==",
}


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True, shell=False)


def install_requirements(python, root=ROOT):
    run(python, "-m", "pip", "install", "--disable-pip-version-check", "--require-hashes",
        "--only-binary=:all:", "-r", root / "requirements-dev.lock")


def build_wheel(output, root=ROOT):
    run(sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", output, root)
    wheels = list(Path(output).glob("finledgerpoli-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("Expected exactly one locally built wheel")
    return wheels[0]


def install_wheel(python, wheel):
    """Source artifacts are built locally; pip verifies their exact bytes without resolving deps."""
    wheel = Path(wheel).resolve()
    with tempfile.TemporaryDirectory(prefix="finassist-wheel-hash-") as directory:
        requirement = Path(directory) / "wheel.txt"
        requirement.write_text(wheel.as_uri() + " --hash=sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest() + "\n",
                               encoding="utf-8", newline="\n")
        run(python, "-m", "pip", "install", "--disable-pip-version-check", "--require-hashes",
            "--no-deps", "--force-reinstall", "-r", requirement)


def pnpm_target(system=None, machine=None):
    system = system or sys.platform
    machine = (machine or platform.machine()).lower()
    architecture = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    target = f"{system}-{architecture}"
    if target not in PNPM_INTEGRITY:
        raise RuntimeError("No reviewed pnpm binary for this platform")
    return target


def unpack_pnpm(directory):
    target = pnpm_target()
    url = f"https://registry.npmjs.org/@pnpm/exe.{target}/-/exe.{target}-12.9.1.tgz"
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 fixed HTTPS host and allowlisted target
        data = response.read(64_000_001)
    if len(data) > 64_000_000 or not hmac.compare_digest(
        hashlib.sha512(data).digest(), base64.b64decode(PNPM_INTEGRITY[target].split("-", 1)[1], validate=True)
    ):
        raise RuntimeError("pnpm archive integrity mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 20_000 or sum(member.size for member in members) > 128_000_000:
            raise RuntimeError("pnpm archive limits exceeded")
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or not path.parts or path.parts[0] != "package" or ".." in path.parts
                    or "\\" in member.name or not (member.isfile() or member.isdir())):
                raise RuntimeError("pnpm archive contains unsafe paths")
        metadata = archive.extractfile("package/package.json")
        if metadata is None:
            raise RuntimeError("pnpm package metadata missing")
        package = json.load(metadata)
        if (package.get("version") != "12.9.1" or package.get("name") != "@pnpm/exe." + target
                or package.get("dependencies")
                or package.get("optionalDependencies")):
            raise RuntimeError("Unexpected pnpm package metadata")
        # Only the verified, dependency-free package is unpacked. No installer or lifecycle scripts run.
        archive.extractall(directory, filter="data")
    entrypoint = Path(directory) / "package" / ("pnpm.exe" if target.startswith("win32-") else "pnpm")
    if not entrypoint.is_file():
        raise RuntimeError("pnpm entrypoint missing")
    return entrypoint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=["project", "pnpm", "pnpm-run"])
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.tool == "project":
        with tempfile.TemporaryDirectory(prefix="finassist-ci-wheel-") as directory:
            install_wheel(sys.executable, build_wheel(directory))
    elif args.tool == "pnpm-run":
        run(os.environ["PNPM_CLI"], *args.arguments)
    else:
        directory = tempfile.mkdtemp(prefix="finassist-ci-pnpm-", dir=os.environ.get("RUNNER_TEMP"))
        entrypoint = unpack_pnpm(directory)
        if os.environ.get("GITHUB_ENV"):
            with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8", newline="\n") as output:
                output.write("PNPM_CLI=" + str(entrypoint) + "\n")
        print(entrypoint)


if __name__ == "__main__":
    main()
