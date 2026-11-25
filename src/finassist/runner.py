"""Explicit test recipes. Candidate code runs in a network-disabled container by default."""

from __future__ import annotations

import os
import math
from pathlib import Path, PureWindowsPath
import re
import selectors
import signal
import subprocess
import tempfile
import time
import uuid

from .config import Config
from .errors import AssistantError
from .security import canonical, digest, pinned_image, regular_path
from .platform_support import clean_environment, container_environment, find_tool, locate_tool
from .posix_process import ExitObserver, non_reaping_wait_available, signal_group


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
    # Refuse before launch: a recipe must not start on a platform where it can't be supervised.
    if not non_reaping_wait_available():
        raise AssistantError("non_reaping_wait_required")
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
    pipe_nonblocking = False
    try:
        observer = ExitObserver(process.pid)
        os.set_blocking(process.stdout.fileno(), False)
        pipe_nonblocking = True
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
            signal_group(process.pid, sig, observer)
            if sig == signal.SIGTERM:
                time.sleep(0.1)
        try:
            process.wait(timeout=2)
            # A process-exit event can arrive before the final pipe-readiness
            # notification (notably with kqueue). Drain available bytes directly
            # after group cleanup, without waiting on inherited open handles.
            if pipe_nonblocking:
                while True:
                    try:
                        block = os.read(process.stdout.fileno(), 65536)
                    except BlockingIOError:
                        break
                    if not block:
                        break
                    room = max_bytes - len(output)
                    output.extend(block[:room])
                    if len(block) > room:
                        overflow = True
                        break
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


# Run by the recipe's interpreter before the recipe: this exit code means it can't find the module.
_MODULE_MISSING = 97
# Started isolated (-I) and outside the snapshot, so the interpreter's own start-up reads none of the
# snapshot; only then are the snapshot's folders searched for the name, which runs no code of theirs.
_PROBE = ("import importlib.util, sys; sys.path[:0] = sys.argv[2:]; "
          "sys.exit(0 if importlib.util.find_spec(sys.argv[1]) else 97)")
_BATCH = {".cmd", ".bat"}
# As the system's own limit on links followed while reading one path (Linux allows 40).
_MAX_LINK_HOPS = 40


def _batch(name: str, *, windows: bool | None = None) -> bool:
    """A .cmd or .bat file; Windows ignores trailing dots and spaces, so "x.cmd ." is one too."""
    windows = os.name == "nt" if windows is None else windows
    name = name.rstrip(" .") if windows else name
    return (PureWindowsPath(name) if windows else Path(name)).suffix.lower() in _BATCH


def _program(name: str, environment: dict) -> str:
    """The program a local recipe's first argument names; a bare name comes from an absolute PATH entry only."""
    path = Path(name)
    if os.name == "nt" and path.anchor and not path.is_absolute():
        # "C:tool" is relative to that drive's current directory, which can be the snapshot, and
        # "\tool" to the current drive, whichever that is when the program starts.
        raise AssistantError("recipe_program_not_found", {"program": name[:64]})
    if _batch(name):
        raise AssistantError("batch_tool_not_supported")
    if os.sep in name or (os.altsep and os.altsep in name) or path.is_absolute():
        found = name
    else:
        found = locate_tool(name, environment)
        if found is None:
            raise AssistantError("recipe_program_not_found", {"program": name[:64]})
    # Batch files start a command interpreter despite shell=False, as in find_tool, however they are named.
    if _batch(found):
        raise AssistantError("batch_tool_not_supported")
    return found


def _interpreter(config: Config, environment: dict) -> str:
    """The interpreter a local recipe's leading `python` means; see `recipe_python`."""
    import sys

    if config.recipe_python == "finassist":
        found = sys.executable or None
    elif config.recipe_python:
        if _batch(config.recipe_python):
            raise AssistantError("batch_tool_not_supported")
        path = Path(config.recipe_python)
        found = str(path) if path.is_file() and (os.name == "nt" or os.access(path, os.X_OK)) else None
    else:
        found = locate_tool("python", environment) or locate_tool("python3", environment)
    if not found:
        raise AssistantError("recipe_python_not_found", {"setting": config.recipe_python or "path"})
    if _batch(found):
        raise AssistantError("batch_tool_not_supported")
    return found


def _is_link(item: Path) -> bool:
    return item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction())


def _plain_windows(text: str) -> str:
    """A Windows path without its extended-length prefix: \\\\?\\UNC\\server\\share is \\\\server\\share."""
    if text[:8].upper() == "\\\\?\\UNC\\":
        return "\\\\" + text[8:]
    if text[:4] in {"\\\\?\\", "\\??\\"}:
        return text[4:]
    return text


def _start(target, current):
    """Where an absolute link target starts: its own anchor, or with a root and no drive, current's drive."""
    return type(current)(target.anchor if target.drive else current.drive + target.root)


def _entries(program: str) -> set[Path]:
    """Every directory entry the system reads to reach the program, each as its link-free folder plus its name.

    The path is read one part at a time, as the system reads it: a link is followed one hop at a time, its
    target read from the folder the link is in, and a `..` goes up from the folder the system is really in,
    not from the link it came through. An entry is recorded before it is followed, so a link anywhere (a
    linked folder above, a chain of links, a `..` inside a link's target) leaves every entry it passed. A
    link that can't be read, or more links than the system itself would follow, is refused.
    """
    raw = Path(_plain_windows(program) if os.name == "nt" else program)
    current, pending, hops, seen = Path(raw.anchor), list(raw.parts[1:]), 0, set()
    while pending:
        part = pending.pop(0)
        if part == "..":
            current = current.parent
            continue
        entry = current / part
        seen.add(entry)
        if not _is_link(entry):
            current = entry
            continue
        hops += 1
        try:
            if hops > _MAX_LINK_HOPS:
                raise OSError("too many links")
            target = os.readlink(entry)
        except OSError as exc:
            raise AssistantError("recipe_program_not_found", {"program": program[:64]}) from exc
        target = Path(_plain_windows(target) if os.name == "nt" else target)
        if target.anchor:
            current, pending = _start(target, current), [*target.parts[1:], *pending]
        else:
            pending = [*target.parts, *pending]
    seen.add(current)
    return seen


def _identity(item: Path, *, follow: bool) -> tuple[int, int] | None:
    """Which file on disk a path is, or with follow=False which entry, a link being itself; None if unreadable."""
    try:
        found = os.stat(item) if follow else os.lstat(item)
    except (OSError, ValueError):
        return None
    return (found.st_dev, found.st_ino) if found.st_ino else None


def _is(item: Path, folder: Path) -> bool:
    """Whether item is the folder: by name, whatever the case, or on disk, however item is written."""
    if [part.casefold() for part in item.parts] == [part.casefold() for part in folder.parts]:
        return True
    identity = _identity(item, follow=True)
    return identity is not None and identity == _identity(folder, follow=True)


def _below(entry: Path, root: Path) -> Path | None:
    """The folder of entry that is root's own child, or entry itself when it is one; None outside root."""
    for child in (entry, *entry.parents):
        if child != child.parent and _is(child.parent, root):
            return child
    return None


def _names(root: Path, child: Path) -> set[str]:
    """Each name root's own listing has for child: the name written, another case, a Windows short name's
    long one, or a second name of the same file. A listing that can't be read is refused."""
    identity = _identity(child, follow=False)
    try:
        listed = {item.name for item in os.scandir(root)
                  if identity is not None and _identity(Path(item.path), follow=False) == identity}
    except OSError as exc:
        raise AssistantError("recipe_program_inside_change") from exc
    return {child.name, *listed}


def _outside_change(program: str, snapshot: Path, repo: Path | None, head: str | None) -> None:
    """Refuse a program the change under review could supply.

    One rule, applied to every entry the system reads on the way to the program (see `_entries`): none
    may be the snapshot or below it, and none may be, or be below, a top-level entry of the repository
    that Git tracks, in the index or at the reviewed commit. An ignored `.venv` holds nothing tracked and
    is allowed; a folder holding any tracked file, link or submodule is not. Entries are matched by name
    without regard to case and by which file they are on disk, so another spelling of the same folder is
    the same folder. The path is read three ways and each must pass: as written; tidied first, as
    Windows drops `..` and trailing dots before it reads the disk; and as the system itself resolves
    it, for a kind of link this reading does not know. A doubt (an unreadable link or listing, a Git
    folder named as the repository) is a refusal.
    """
    from .scope import git

    spellings = {program, os.path.abspath(program), os.path.realpath(program)}
    if os.name == "nt" and not PureWindowsPath(program.rstrip(" .")).suffix:
        spellings |= {item.rstrip(" .") + ".exe" for item in spellings}  # Windows runs "C:\\tools\\x" as x.exe
    entries = set().union(*(_entries(item) for item in spellings))
    if any(_is(item, snapshot) or _below(item, snapshot) is not None for item in entries):
        raise AssistantError("recipe_program_inside_change")
    if repo is None or git(repo, "rev-parse", "--is-bare-repository") == "true":
        return  # A bare repository has no files on disk to run.
    # The top of the checkout, wherever inside it `repo` points: Git lists a subfolder's own files from
    # a subfolder. A Git folder has no checkout to compare with, so this read fails and nothing runs.
    root = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    children = {child for child in (_below(item, root) for item in entries) if child is not None}
    if not children:
        return
    committed = set()
    if head is not None:
        listed = git(root, "ls-tree", "-z", "--name-only", head, binary=True)
        committed = {name.decode("utf-8", "surrogateescape").casefold() for name in listed.split(b"\0") if name}
    for name in sorted(set().union(*(_names(root, child) for child in children))):
        if name.casefold() in committed or git(root, "ls-files", "-z", "--", ":(literal,icase)" + name, binary=True):
            raise AssistantError("recipe_program_inside_change")


def _probe_module(interpreter: str, recipe: list[str], *, cwd: Path, env: dict, timeout: float, home: Path) -> None:
    """Refuse by name, before the run, when `python -m MODULE` can't find MODULE's top-level package.

    The interpreter starts isolated, outside the snapshot and without its PYTHONPATH, then looks up only the
    top-level name in the snapshot's folders, so no code of the project runs. When the lookup fails some
    other way, the interpreter is started once more on its own: if that works, the recipe runs so its
    saved record holds the failure.
    """
    if len(recipe) < 3 or recipe[1] != "-m" or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", recipe[2]):
        return
    module = recipe[2].split(".")[0]
    limit = min(timeout, 30)
    alone = {key: value for key, value in env.items() if key != "PYTHONPATH"}
    result = run_bounded([interpreter, "-I", "-c", _PROBE, module, str(cwd / "src"), str(cwd)], cwd=home,
                         env=alone, timeout=limit)
    if result["passed"]:
        return
    if result["exit_code"] == _MODULE_MISSING and not result["timed_out"]:
        raise AssistantError("recipe_python_module_missing", {"module": module})
    if not run_bounded([interpreter, "-I", "-c", ""], cwd=home, env=alone, timeout=limit)["passed"]:
        raise AssistantError("recipe_python_unusable")


def run_recipe(
    config: Config, name: str, snapshot: Path, *, backend: str = "docker", approve_local: bool = False,
    repo: Path | None = None, head: str | None = None,
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
        program = _interpreter(config, env) if recipe[0] == "python" else _program(recipe[0], env)
        # A relative path such as ./run-tests.sh names the change's own script, as before. A path with
        # a root, written in the recipe or found on PATH, is checked in full.
        if Path(program).anchor:
            _outside_change(program, source, repo, head)
        argv, cwd = [program, *recipe[1:]], source
        isolation = "none: trusted local execution explicitly approved"
    else:
        pinned_image(config.runner_image)
        executable = find_tool(backend)
        env = container_environment(backend)
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
            f"--pids-limit={config.runner_pids}",
            f"--memory={config.runner_memory_mb}m",
            f"--cpus={config.runner_cpus}",
            "--user=65534:65534",
            f"--tmpfs=/tmp:rw,nosuid,nodev,size={config.runner_tmp_mb}m",
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
    with tempfile.TemporaryDirectory(prefix="finassist-home-") as private_home:
        if backend == "local":
            env["HOME"] = private_home
            env["PYTHONPATH"] = str(source / "src") + os.pathsep + str(source)
            if recipe[0] == "python":
                _probe_module(argv[0], recipe, cwd=cwd, env=env, timeout=config.timeout_seconds,
                              home=Path(private_home))
        try:
            result = run_bounded(argv, cwd=cwd, env=env, timeout=config.timeout_seconds)
        finally:
            if backend != "local":
                # The host CLI keeps its context/storage selectors until both
                # cleanup calls complete; none become container variables.
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
