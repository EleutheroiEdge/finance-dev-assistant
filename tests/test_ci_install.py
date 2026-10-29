"""CI must verify downloaded tools and built wheel bytes without changing release authority."""

import base64
import hashlib
import io
from pathlib import Path
import re
import tarfile
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
import pytest
import yaml

from scripts import ci_install

ROOT = Path(__file__).resolve().parent.parent


def locked_requirements():
    text = (ROOT / "requirements-dev.lock").read_text(encoding="utf-8").replace("\\\n", "")
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        hashes = re.findall(r"--hash=sha256:([a-f0-9]{64})", line)
        assert hashes, line
        requirement = Requirement(line.split("--hash=", 1)[0].strip())
        assert len(requirement.specifier) == 1
        assert next(iter(requirement.specifier)).operator == "=="
        result[canonicalize_name(requirement.name)] = requirement
    return result


def test_all_python_tools_are_exact_hash_pins_with_platform_dependencies():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    requirements = locked_requirements()
    assert project["build-system"]["requires"] == ["setuptools==84.2.1", "wheel==0.48.0"]
    for group in [project["build-system"]["requires"], project["project"]["dependencies"],
                  project["project"]["optional-dependencies"]["dev"], project["dependency-groups"]["ci"]]:
        for item in group:
            requirement = Requirement(item)
            assert requirements[canonicalize_name(requirement.name)].specifier == requirement.specifier
    assert str(requirements["pytest"].specifier) == "==9.2.0"
    assert {"colorama", "pywin32-ctypes", "backports-tarfile", "importlib-metadata", "zipp", "maturin"} <= requirements.keys()
    assert requirements["colorama"].marker.evaluate({"sys_platform": "win32", "os_name": "nt"})


def test_workflows_keep_hash_verification_and_existing_check_identities():
    for name in ["ci.yml", "release.yml"]:
        workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))
        assert workflow["permissions"] == {"contents": "read"}
        steps = [step for job in workflow["jobs"].values() for step in job["steps"]]
        assert any(step.get("run") == "python scripts/ci_install.py dependencies" for step in steps)
        assert any(step.get("run") == "python scripts/ci_install.py project" for step in steps)
        assert any(step.get("run") == "python scripts/ci_install.py pnpm" for step in steps)
        for step in steps:
            command = step.get("run", "")
            if "pip install" in command:
                assert "--require-hashes --only-binary=:all: -r requirements-dev.lock" in command
            assert "npm install --global" not in command and "-e ." not in command
            if "uses" in step:
                assert re.fullmatch(r"[^@]+@[a-f0-9]{40}", step["uses"].split()[0])
        if name == "ci.yml":
            assert set(workflow["jobs"]) == {"test", "dashboard", "isolation"}
            assert [item["check_name"] for item in workflow["jobs"]["test"]["strategy"]["matrix"]["include"]] == [
                "test (3.11)", "test (3.12)", "test (3.13)", "platform (Windows, 3.11)",
                "platform (Windows, 3.12)", "platform (Windows)", "platform (macOS, 3.11)",
                "platform (macOS, 3.12)", "platform (macOS)",
            ]
        else:
            assert any(step.get("run") == "python -m build --no-isolation" for step in steps)


def test_local_wheel_install_verifies_artifact_without_fetching_dependencies(tmp_path, monkeypatch):
    wheel = tmp_path / "finledgerpoli-0.3.1-py3-none-any.whl"
    wheel.write_bytes(b"synthetic local wheel")
    calls = []

    def execute(*args):
        calls.append(args)
        assert "--require-hashes" in args and "--no-deps" in args
        requirement = Path(args[-1]).read_text(encoding="utf-8")
        assert requirement == wheel.as_uri() + " --hash=sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest() + "\n"

    monkeypatch.setattr(ci_install, "run", execute)
    ci_install.install_wheel("synthetic-python", wheel)
    assert len(calls) == 1


def test_third_party_install_refuses_unhashed_source_builds(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ci_install, "run", lambda *args: calls.append(args))
    ci_install.install_requirements("synthetic-python", tmp_path, windows=False)
    assert calls == [("synthetic-python", "-m", "pip", "install", "--disable-pip-version-check",
                      "--require-hashes", "--only-binary=:all:", "-r", tmp_path / "requirements-dev.lock")]


@pytest.mark.parametrize("payload", [b"corrupted synthetic archive", b"x" * 64_000_001])
def test_pnpm_rejects_changed_or_oversized_archive_before_install(tmp_path, monkeypatch, payload):
    monkeypatch.setattr(ci_install.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(payload))
    monkeypatch.setattr(ci_install, "run", lambda *args: pytest.fail("Bad archive must not reach npm"))
    with pytest.raises(RuntimeError, match="integrity mismatch"):
        ci_install.unpack_pnpm(tmp_path)


def pnpm_archive(extra=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in [("package/package.json", b'{"version":"12.9.1","name":"@pnpm/exe.linux-x64"}'),
                           ("package/pnpm", b"synthetic entrypoint")]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if extra:
            archive.addfile(extra)
    return stream.getvalue()


def mock_pnpm_archive(monkeypatch, payload):
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
    monkeypatch.setitem(ci_install.PNPM_INTEGRITY, "linux-x64", integrity)
    monkeypatch.setattr(ci_install, "pnpm_target", lambda: "linux-x64")
    monkeypatch.setattr(ci_install.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(payload))
    monkeypatch.setattr(ci_install, "run", lambda *args: pytest.fail("No bootstrap installer may run"))


def test_pnpm_verified_archive_unpacks_without_installer_or_lifecycle_scripts(tmp_path, monkeypatch):
    mock_pnpm_archive(monkeypatch, pnpm_archive())
    entrypoint = ci_install.unpack_pnpm(tmp_path)
    assert entrypoint == tmp_path / "package/pnpm"
    assert entrypoint.read_bytes() == b"synthetic entrypoint"


@pytest.mark.parametrize("name,kind", [("../outside", tarfile.REGTYPE), ("/outside", tarfile.REGTYPE),
                                      ("package/link", tarfile.SYMTYPE), ("package/hard", tarfile.LNKTYPE)])
def test_pnpm_rejects_unsafe_archive_members_even_with_matching_digest(tmp_path, monkeypatch, name, kind):
    extra = tarfile.TarInfo(name)
    extra.type = kind
    mock_pnpm_archive(monkeypatch, pnpm_archive(extra))
    with pytest.raises(RuntimeError, match="unsafe paths"):
        ci_install.unpack_pnpm(tmp_path)
    assert not (tmp_path / "package").exists()


def test_runner_retains_digest_and_requires_hashes():
    dockerfile = (ROOT / "examples/runner.Dockerfile").read_text(encoding="utf-8")
    assert "# Upstream tag: python:3.13.7-slim" in dockerfile
    assert re.search(r"^FROM python@sha256:[a-f0-9]{64}$", dockerfile, re.MULTILINE)
    assert "--require-hashes --only-binary=:all:" in dockerfile


@pytest.mark.parametrize("system,machine,target", [("linux", "x86_64", "linux-x64"),
    ("darwin", "arm64", "darwin-arm64"), ("darwin", "x86_64", "darwin-x64"),
    ("win32", "AMD64", "win32-x64")])
def test_pnpm_platforms_have_fixed_reviewed_integrity(system, machine, target):
    assert ci_install.pnpm_target(system, machine) == target
    digest = base64.b64decode(ci_install.PNPM_INTEGRITY[target].split("-", 1)[1], validate=True)
    assert len(digest) == 64


def test_pnpm_unknown_platform_never_falls_back_to_network_downloads():
    with pytest.raises(RuntimeError, match="No reviewed pnpm binary"):
        ci_install.pnpm_target("unknown", "unknown")


def test_windows_source_build_bootstraps_hash_locked_backend_without_isolation(tmp_path, monkeypatch):
    requirement = "maturin==1.15.0 --hash=sha256:" + "a" * 64
    (tmp_path / "requirements-dev.lock").write_text(requirement + "\n", encoding="utf-8")
    monkeypatch.setattr(ci_install.shutil, "which", lambda name: "synthetic-cargo")
    calls = []

    def execute(*args):
        calls.append(args)
        assert "--require-hashes" in args
        if len(calls) == 1:
            assert "--only-binary=:all:" in args
            assert Path(args[-1]).read_text(encoding="utf-8") == requirement + "\n"

    monkeypatch.setattr(ci_install, "run", execute)
    ci_install.install_requirements("synthetic-python", tmp_path, windows=True)
    assert len(calls) == 2
    assert "--no-binary=comrak" in calls[1] and "--no-build-isolation" in calls[1]
    assert "--config-settings=maturin.build-args=--locked" in calls[1]


def test_windows_missing_rust_never_downloads_an_unlocked_toolchain(tmp_path, monkeypatch):
    monkeypatch.setattr(ci_install.shutil, "which", lambda name: None)
    monkeypatch.setattr(ci_install, "run", lambda *args: pytest.fail("Missing Rust must stop before installs"))
    with pytest.raises(RuntimeError, match="existing Rust toolchain"):
        ci_install.install_requirements("synthetic-python", tmp_path, windows=True)
