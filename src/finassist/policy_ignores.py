"""Current and immutable Git ignore screening shared by policy gates."""
from pathlib import Path, PurePosixPath
import subprocess
import tempfile

from .errors import AssistantError
from .scope import git, git_command, git_environment, read_entry


def _ignored(repo: Path, paths: list[str]) -> bool:
    result = subprocess.run(git_command(repo, "check-ignore", "--no-index", "-z", "--stdin"),
                            input=("\0".join(paths) + "\0").encode(), capture_output=True,
                            timeout=30, env=git_environment(), check=False)
    if result.returncode not in {0, 1}:
        raise AssistantError("gate_ignore_check_unavailable")
    return result.returncode == 0


def _ignored_set(repo: Path, paths: list[str]) -> set[str]:
    if not paths:
        return set()
    result = subprocess.run(git_command(repo, "check-ignore", "--no-index", "-z", "--stdin"),
                            input=("\0".join(paths) + "\0").encode(), capture_output=True,
                            timeout=30, env=git_environment(), check=False)
    if result.returncode not in {0, 1}:
        raise AssistantError("gate_ignore_check_unavailable")
    try:
        return {path for path in result.stdout.decode("utf-8", errors="strict").split("\0") if path}
    except UnicodeError as exc:
        raise AssistantError("gate_ignore_check_unavailable") from exc


def ignored_paths(repo: Path, revisions: set[str], paths: list[str]) -> set[str]:
    """The paths that current or immutable ignore rules exclude, by the same rules as
    screen_ignores, without refusing. Each revision's .gitignore files are listed once."""
    ignored = _ignored_set(repo, paths)
    directories = {parent for path in paths for parent in PurePosixPath(path).parents}
    for sha in revisions:
        listing = git(repo, "ls-tree", "-r", "-z", "--name-only", sha, binary=True).split(b"\0")
        rules = [name for name in (raw.decode("utf-8", errors="replace") for raw in listing if raw)
                 if PurePosixPath(name).name == ".gitignore" and PurePosixPath(name).parent in directories]
        with tempfile.TemporaryDirectory(prefix="finassist-ignore-") as temporary:
            snapshot = Path(temporary)
            git(snapshot, "init", "--quiet", "--template=")
            for name in rules:
                raw, _ = read_entry(repo, sha, name, 128_000)
                if raw is not None:
                    target = snapshot / str(PurePosixPath(name).parent)
                    target.mkdir(parents=True, exist_ok=True)
                    (target / ".gitignore").write_bytes(raw)
            ignored |= _ignored_set(snapshot, paths)
    return ignored


def screen_ignores(repo: Path, revisions: set[str], paths: list[str]) -> None:
    if _ignored(repo, paths):
        raise AssistantError("gate_ignored_path")
    # Read immutable ignore rules from the policy base AND merge base. A stale
    # PR or dirty checkout cannot remove baseline exclusions to authorize source.
    directories = {parent for path in paths for parent in PurePosixPath(path).parents}
    for sha in revisions:
        with tempfile.TemporaryDirectory(prefix="finassist-ignore-") as temporary:
            snapshot = Path(temporary)
            git(snapshot, "init", "--quiet", "--template=")
            for parent in directories:
                target = snapshot / str(parent)
                target.mkdir(parents=True, exist_ok=True)
                name = str(parent / ".gitignore")
                raw, _ = read_entry(repo, sha, name, 128_000)
                if raw is not None:
                    (target / ".gitignore").write_bytes(raw)
            if _ignored(snapshot, paths):
                raise AssistantError("gate_ignored_path")
