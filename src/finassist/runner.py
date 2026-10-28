"""Explicit test recipes. Candidate code runs in a network-disabled container by default."""

from __future__ import annotations

import os
import math
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time
import uuid

from .config import Config
from .errors import AssistantError
from .security import canonical, digest, pinned_image, regular_path
from .platform_support import clean_environment, find_tool
from .posix_process import ExitObserver


def run_bounded(argv: list[str], *, cwd: Path, env: dict, timeout: float, max_bytes: int = 1_000_000) -> dict:
    """Native process supervision for trusted commands; not a security sandbox."""
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or type(max_bytes) is not int
        or max_bytes <= 0
    ):
        raise AssistantError("invalid_run_limits")
    if os.name == "nt":
        from .windows_runner import run_windows

        return run_windows(
            argv, cwd=cwd, env={**clean_environment(), **env}, timeout=timeout, max_bytes=max_bytes
        )
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        shell=False,
    )
    output, timed_out, overflow = bytearray(), False, False
    selector = selectors.DefaultSelector()
    observer = None
    try:
        observer = ExitObserver(process.pid)
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            ready = selector.select(0.02)
            for key, _ in ready:
                block = os.read(key.fd, 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                room = max_bytes - len(output)
                output.extend(block[:room])
                if len(block) > room:
                    overflow = True
            if overflow:
                break
            # Observe exit without reaping the leader. Its reserved PID prevents
            # the process-group number being reused before both cleanup signals.
            if observer.poll():
                if not ready or not selector.get_map():
                    break
            if time.monotonic() - started > timeout:
                timed_out = True
                break
    finally:
        # Keep the leader unreaped until all group signals are complete. Escaped
        # descendants still require OS/container isolation.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
            if sig == signal.SIGTERM:
                time.sleep(0.1)
        try:
            process.wait(timeout=2)
        finally:
            selector.close()
            process.stdout.close()
            if observer is not None:
                observer.close()
    return {
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "output_limit_exceeded": overflow,
        "passed": process.returncode == 0 and not timed_out and not overflow,
        "output": output.decode("utf-8", errors="replace"),
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def run_recipe(
    config: Config, name: str, snapshot: Path, *, backend: str = "docker", approve_local: bool = False
) -> dict:
    config.validate()
    if name not in config.recipes:
        raise AssistantError("recipe_not_configured")
    source = regular_path(snapshot).resolve()
    if not source.is_dir() or "," in str(source):
        raise AssistantError("invalid_snapshot_directory")
    recipe = config.recipes[name]
    if backend not in {"docker", "podman", "local"}:
        raise AssistantError("unsupported_runner")
    env = clean_environment()
    if backend == "local":
        if not approve_local:
            raise AssistantError("local_execution_not_approved")
        import sys

        argv, cwd = ([sys.executable, *recipe[1:]] if recipe[0] == "python" else recipe), source
        isolation = "none: trusted local execution explicitly approved"
    else:
        pinned_image(config.runner_image)
        executable = find_tool(backend)
        if backend == "docker":
            # The CLI consumes its existing Desktop context internally. No file
            # content, credential or context is copied into the container.
            env["DOCKER_CONFIG"] = os.environ.get("DOCKER_CONFIG", str(Path.home() / ".docker"))
            if os.environ.get("DOCKER_CONTEXT"):
                env["DOCKER_CONTEXT"] = os.environ["DOCKER_CONTEXT"]
        else:
            env["XDG_CONFIG_HOME"] = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
            if os.environ.get("XDG_RUNTIME_DIR"):
                env["XDG_RUNTIME_DIR"] = os.environ["XDG_RUNTIME_DIR"]
        container_name = "finassist-" + uuid.uuid4().hex
        argv = [
            executable,
            "run",
            "--name",
            container_name,
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=128",
            "--memory=1g",
            "--cpus=2",
            "--user=65534:65534",
            "--tmpfs=/tmp:rw,nosuid,nodev,size=256m",
            "--mount",
            f"type=bind,src={source.as_posix()},dst=/workspace,readonly",
            "--workdir=/workspace",
            "--env=HOME=/tmp",
            "--env=PYTHONDONTWRITEBYTECODE=1",
            "--",
            config.runner_image,
            *recipe,
        ]
        cwd, isolation = source, "network-disabled read-only container; image must already be present"
    cleanup_verified = backend == "local"
    try:
        with tempfile.TemporaryDirectory(prefix="finassist-home-") as private_home:
            env["HOME"] = private_home
            if backend == "local":
                env["PYTHONPATH"] = str(source / "src") + os.pathsep + str(source)
            result = run_bounded(argv, cwd=cwd, env=env, timeout=config.timeout_seconds)
    finally:
        if backend != "local":
            # A terminated CLI does not prove daemon-owned container exit.
            # Cleanup is attempted even when supervision itself raises.
            try:
                cleanup = subprocess.run(
                    [executable, "rm", "--force", container_name],
                    capture_output=True,
                    env=env,
                    timeout=15,
                    check=False,
                )
                inspect = subprocess.run(
                    [executable, "container", "inspect", container_name],
                    capture_output=True,
                    env=env,
                    timeout=15,
                    check=False,
                )
                cleanup_verified = inspect.returncode != 0 and (
                    cleanup.returncode == 0 or b"No such container" in cleanup.stderr
                )
            except (OSError, subprocess.SubprocessError):
                cleanup_verified = False
    if not cleanup_verified:
        result["passed"] = False
    # A recipe's log is local evidence, never automatically forwarded to a model.
    receipt = {
        "recipe": name,
        "argv_hash": digest(canonical(recipe)),
        "runner_image": config.runner_image if backend != "local" else None,
        "isolation": isolation,
        **{k: v for k, v in result.items() if k != "output"},
        "cleanup_verified": cleanup_verified,
        "output_hash": digest(result["output"].encode()),
    }
    return {"receipt": receipt, "output": result["output"]}
