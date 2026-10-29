"""Synthetic regressions for native process, filesystem and container boundaries."""

from dataclasses import replace
import io
import os
from pathlib import Path
import queue
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from conftest import command
from finassist.cli import main
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.patching import apply_patch_artifact, rollback_patch
from finassist.platform_support import canonical_system_path
from finassist.posix_process import zombie_group_only
from finassist.runner import run_bounded, run_recipe
from finassist.security import canonical, digest, regular_path
from finassist import windows_runner


@pytest.mark.parametrize("code,output", [(0, ""), (1, "Z\n"), (1, ""), (0, "S\n")])
def test_empty_or_failed_ps_never_proves_a_zombie_only_group(monkeypatch, code, output):
    monkeypatch.setattr("finassist.posix_process.find_tool", lambda _: "ps")
    monkeypatch.setattr(
        "finassist.posix_process.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, code, output, ""),
    )
    assert zombie_group_only(123) is False


def test_zombie_probe_includes_processes_without_a_terminal(monkeypatch):
    monkeypatch.setattr("finassist.posix_process.find_tool", lambda _: "ps")

    def run(argv, **kwargs):
        assert "-x" in argv
        return subprocess.CompletedProcess(argv, 0, "Z\nZ+\n", "")

    monkeypatch.setattr("finassist.posix_process.subprocess.run", run)
    assert zombie_group_only(123)


def fake_windows(monkeypatch, *, blocks=(None,), closing_fails=False):
    events = []
    stream = io.BytesIO()
    process = SimpleNamespace(
        stdout=stream,
        returncode=0,
        pid=123,
        _handle=1,
        poll=lambda: 0,
        wait=lambda **_: 0,
        kill=lambda: events.append("kill"),
    )

    class Job:
        def attach(self, child):
            events.append("attach")

        def resume(self, child):
            events.append("resume")

        def close(self):
            events.append("close")
            if closing_fails:
                raise AssistantError("windows_job_cleanup_failed")

    class Reader:
        def __init__(self, target, **kwargs):
            self.stopped = dict(
                zip(
                    target.__code__.co_freevars,
                    (cell.cell_contents for cell in target.__closure__),
                    strict=True,
                )
            )["stopped"]

        def start(self):
            events.append("reader")

        def join(self, **kwargs):
            events.append("join")
            assert self.stopped.is_set()

    def popen(*args, **kwargs):
        events.append(("create", kwargs["creationflags"]))
        return process

    pending = queue.Queue()
    for block in blocks:
        pending.put(block)
    monkeypatch.setattr(windows_runner, "Job", Job)
    monkeypatch.setattr(windows_runner.subprocess, "Popen", popen)
    monkeypatch.setattr(windows_runner.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200, raising=False)
    monkeypatch.setattr(windows_runner.threading, "Thread", Reader)
    monkeypatch.setattr(windows_runner.queue, "Queue", lambda **kwargs: pending)
    return events, stream


def test_windows_child_is_suspended_until_job_assignment(monkeypatch, tmp_path):
    events, _ = fake_windows(monkeypatch)
    windows_runner.run_windows(["synthetic.exe"], cwd=tmp_path, env={}, timeout=1, max_bytes=100)
    assert events[0][1] & 0x4  # CREATE_SUSPENDED
    assert events.index("attach") < events.index("resume") < events.index("reader")


def test_windows_pipe_and_reader_cleanup_survive_job_close_failure(monkeypatch, tmp_path):
    events, stream = fake_windows(monkeypatch, closing_fails=True)
    with pytest.raises(AssistantError, match="windows_job_cleanup_failed"):
        windows_runner.run_windows(["synthetic.exe"], cwd=tmp_path, env={}, timeout=1, max_bytes=100)
    assert "join" in events and stream.closed


def test_windows_completed_output_queue_is_drained_before_deadline(monkeypatch, tmp_path):
    fake_windows(monkeypatch, blocks=(*([b"x"] * 10), None))
    ticks = iter(range(100))
    monkeypatch.setattr(windows_runner.time, "monotonic", lambda: next(ticks))
    result = windows_runner.run_windows(["synthetic.exe"], cwd=tmp_path, env={}, timeout=0.5, max_bytes=100)
    assert result["passed"] and result["output"] == "x" * 10


@pytest.mark.parametrize("backend", ["docker", "podman"])
def test_container_cli_retains_host_selectors_only_outside_the_container(tmp_path, monkeypatch, backend):
    selectors = {
        "HOME": str(tmp_path),
        "USERPROFILE": str(tmp_path),
        "APPDATA": str(tmp_path / "config"),
        "LOCALAPPDATA": str(tmp_path / "local"),
        "DOCKER_HOST": "unix:///synthetic/socket",
        "DOCKER_CONFIG": str(tmp_path / "docker"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "XDG_RUNTIME_DIR": str(tmp_path / "runtime"),
    }
    for name, value in selectors.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    monkeypatch.setattr("finassist.runner.find_tool", lambda _: backend)

    def supervise(argv, **kwargs):
        for name, value in selectors.items():
            if name.startswith("DOCKER_") and backend != "docker":
                continue
            if name.startswith("XDG_") and backend != "podman":
                continue
            assert kwargs["env"][name] == value
        assert "OPENAI_API_KEY" not in kwargs["env"]
        assert "--env=HOME=/tmp" in argv
        assert not any("--env=" + name + "=" in arg for name in selectors if name != "HOME" for arg in argv)
        return {"passed": True, "output": "", "exit_code": 0}

    monkeypatch.setattr("finassist.runner.run_bounded", supervise)
    monkeypatch.setattr(
        "finassist.runner.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0 if "rm" in argv else 1, b"", b""),
    )
    result = run_recipe(
        replace(Config(), recipes={"unit": ["python", "test.py"]}, runner_image="sha256:" + "a" * 64),
        "unit",
        tmp_path,
        backend=backend,
    )
    assert result["receipt"]["cleanup_verified"]


@pytest.mark.parametrize("fails", [False, True])
def test_container_cleanup_happens_inside_temporary_scope(tmp_path, monkeypatch, fails):
    import tempfile

    original = tempfile.TemporaryDirectory
    active = []

    class Directory:
        def __enter__(self):
            self.directory = original()
            active.append(True)
            return self.directory.name

        def __exit__(self, *args):
            active.pop()
            self.directory.cleanup()

    monkeypatch.setattr("finassist.runner.tempfile.TemporaryDirectory", lambda **kwargs: Directory())
    monkeypatch.setattr("finassist.runner.find_tool", lambda _: "docker")

    def supervise(*args, **kwargs):
        if fails:
            raise AssistantError("synthetic_supervision_failure")
        return {"passed": True, "output": "", "exit_code": 0}

    def cleanup(argv, **kwargs):
        assert active, "container cleanup must happen before temporary state disappears"
        return subprocess.CompletedProcess(argv, 0 if "rm" in argv else 1, b"", b"")

    monkeypatch.setattr("finassist.runner.run_bounded", supervise)
    monkeypatch.setattr("finassist.runner.subprocess.run", cleanup)
    config = replace(Config(), recipes={"unit": ["python", "test.py"]}, runner_image="sha256:" + "a" * 64)
    if fails:
        with pytest.raises(AssistantError, match="synthetic_supervision_failure"):
            run_recipe(config, "unit", tmp_path)
    else:
        assert run_recipe(config, "unit", tmp_path)["receipt"]["cleanup_verified"]


def test_reparse_attribute_is_checked_without_python_junction_helper(tmp_path, monkeypatch):
    target = tmp_path / "junction"
    target.mkdir()
    original = Path.lstat

    def lstat(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        if path == target:
            return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400)
        return value

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(Path, "is_junction", lambda _: False, raising=False)
    with pytest.raises(AssistantError, match="linked_path"):
        regular_path(target / "file.json")


def test_scan_rejects_tracked_links_even_when_checkout_is_a_regular_file(repository, tmp_path, capsys):
    repo, _, _ = repository
    target = tmp_path / "target.txt"
    target.write_bytes(b"synthetic-target")
    blob = command(repo, "hash-object", "-w", str(target))
    command(repo, "config", "core.symlinks", "false")
    command(repo, "update-index", "--add", "--cacheinfo", "120000," + blob + ",src/link.py")
    command(repo, "checkout-index", "--force", "--", "src/link.py")
    assert not (repo / "src/link.py").is_symlink()
    assert main(["scan", "--repo", str(repo)]) == 1
    assert "linked_or_special_git_object" in capsys.readouterr().out


def test_canonical_paths_normalize_parents_without_following_user_links(tmp_path):
    assert canonical_system_path(tmp_path / "folder/../source") == tmp_path / "source"


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS fixed OS aliases")
@pytest.mark.parametrize("name", ["var", "tmp", "etc"])
def test_macos_fixed_system_aliases_are_canonical(name):
    alias = Path("/") / name
    if alias.is_symlink():
        assert canonical_system_path(alias / "folder/../source") == Path("/private") / name / "source"


@pytest.mark.parametrize("global_autocrlf", [False, True])
def test_crlf_source_applies_and_rolls_back_exact_bytes(repository, tmp_path, monkeypatch, global_autocrlf):
    repo, _, _ = repository
    target = repo / "src/crlf.py"

    def raw_git(*args):
        return (
            subprocess.check_output(
                [
                    "git",
                    "-c",
                    "core.hooksPath=" + os.devnull,
                    "-c",
                    "core.fsmonitor=false",
                    "-C",
                    str(repo),
                    *args,
                ]
            )
            .decode("utf-8")
            .strip()
        )

    if global_autocrlf:
        home = tmp_path / "home"
        home.mkdir()
        (home / ".gitconfig").write_text("[core]\n\tautocrlf = true\n", encoding="utf-8", newline="\n")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
        raw_git("config", "--local", "--unset-all", "core.autocrlf")
    else:
        raw_git("config", "core.autocrlf", "false")
    target.write_bytes(b"value = 1\r\n")
    raw_git("add", "src/crlf.py")
    raw_git("commit", "-m", "Synthetic CRLF source")
    head = command(repo, "rev-parse", "HEAD")
    original = target.read_bytes()
    # Produce the literal patch in Git's own effective newline policy.
    target.write_bytes(b"value = 2\r\n")
    patch = subprocess.check_output(["git", "-C", str(repo), "diff", "--", "src/crlf.py"]).decode("utf-8")
    target.write_bytes(original)
    artifact = {"head": head, "patch": patch, "summary": "Synthetic CRLF fix"}
    approved = digest(canonical(artifact))
    apply_patch_artifact(repo, artifact, approved, Config())
    assert target.read_bytes() == b"value = 2\r\n"
    rollback_patch(repo, approved)
    assert target.read_bytes() == original


def test_descendants_cannot_outlive_their_completed_supervised_parent(tmp_path):
    marker = tmp_path / "escaped.txt"
    child = "import pathlib,sys,time; time.sleep(0.8); pathlib.Path(sys.argv[1]).write_bytes(b'escaped')"
    parent = "import subprocess,sys; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); print('parent completed')"
    result = run_bounded(
        [sys.executable, "-c", parent, child, str(marker)], cwd=tmp_path, env=dict(os.environ), timeout=5
    )
    assert result["passed"]
    time.sleep(1.1)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="native Windows Job object lifecycle")
def test_many_fast_windows_children_do_not_race_job_attachment(tmp_path):
    for _ in range(15):
        assert run_bounded([sys.executable, "-c", "pass"], cwd=tmp_path, env=dict(os.environ), timeout=5)[
            "passed"
        ]


def test_new_crlf_source_keeps_carriage_returns_without_whitespace_errors(repository):
    repo, _, head = repository
    patch = "diff --git a/src/new.py b/src/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/src/new.py\n@@ -0,0 +1 @@\n+value = 1\r\n"
    artifact = {"head": head, "patch": patch, "summary": "Synthetic CRLF addition"}
    approved = digest(canonical(artifact))
    apply_patch_artifact(repo, artifact, approved, Config())
    assert (repo / "src/new.py").read_bytes() == b"value = 1\r\n"
    rollback_patch(repo, approved)
    assert not (repo / "src/new.py").exists()


def test_doctor_refuses_batch_tool_shims(monkeypatch, capsys):
    import json

    monkeypatch.setattr("finassist.platform_support.shutil.which", lambda name: name + ".cmd")
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["docker_binary_present"] is False and report["podman_binary_present"] is False


def test_readonly_replacement_restores_the_attribute_on_windows(tmp_path, monkeypatch):
    import stat
    from finassist.security import write_private

    target = tmp_path / "readonly.txt"
    target.write_bytes(b"before")
    target.chmod(0o444)
    original = Path.replace

    def replace(source, destination):
        if not destination.stat().st_mode & stat.S_IWRITE:
            raise PermissionError("synthetic Windows read-only destination")
        return original(source, destination)

    monkeypatch.setattr(Path, "replace", replace)
    monkeypatch.setattr("finassist.security.sys.platform", "win32")
    try:
        write_private(target, b"after", replace=True)
        assert target.read_bytes() == b"after"
        assert not target.stat().st_mode & stat.S_IWRITE
    finally:
        target.chmod(0o600)


def test_shipped_resource_bytes_survive_autocrlf_checkouts(tmp_path):
    root = tmp_path.resolve()
    project = Path(__file__).resolve().parents[1]
    attributes = project / ".gitattributes"
    (root / ".gitattributes").write_bytes(attributes.read_bytes() if attributes.exists() else b"")
    expected = {}
    for source in (project / "src/finassist/resources").rglob("*"):
        if source.is_file():
            name = source.relative_to(project)
            expected[name] = source.read_bytes()
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(expected[name])

    def git(*args):
        subprocess.run(
            ["git", "-c", "core.autocrlf=true", "-c", "core.hooksPath=" + os.devnull, "-C", str(root), *args],
            check=True,
            capture_output=True,
        )

    git("init")
    git("add", "--", ".gitattributes", "src")
    for name in expected:
        (root / name).unlink()
    git("checkout-index", "--all", "--force")
    assert all((root / name).read_bytes() == data for name, data in expected.items())


def test_ci_and_protection_proposal_cover_each_native_python_version():
    import json
    import yaml

    root = Path(__file__).resolve().parents[1]
    rows = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]["test"][
        "strategy"
    ]["matrix"]["include"]
    for system in ("ubuntu-24.04", "windows-latest", "macos-latest"):
        assert {row["python"] for row in rows if row["os"] == system} == {"3.11", "3.12", "3.13"}
    proposal = json.loads((root / "docs/maintainers/branch-protection-proposal.json").read_text(encoding="utf-8"))
    assert {row["check_name"] for row in rows} | {"isolation"} <= {
        row["context"] for row in proposal["body"]["required_status_checks"]["checks"]
    }
    assert proposal["applied"] is False


def test_readonly_source_rolls_back_bytes_and_permissions(repository):
    import stat

    repo, _, head = repository
    path = repo / "src/cash.py"
    before = path.read_bytes()
    patch = "diff --git a/src/cash.py b/src/cash.py\n--- a/src/cash.py\n+++ b/src/cash.py\n@@ -1,2 +1,2 @@\n def balance(opening, deposits):\n-    return opening - deposits\n+    return opening + deposits\n"
    artifact = {"head": head, "patch": patch, "summary": "Synthetic read-only rollback"}
    approved = digest(canonical(artifact))
    path.chmod(0o444)
    try:
        apply_patch_artifact(repo, artifact, approved, Config())
        rollback_patch(repo, approved)
        assert path.read_bytes() == before
        assert not path.stat().st_mode & stat.S_IWRITE
    finally:
        path.chmod(0o600)
