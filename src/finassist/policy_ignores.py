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


def _rule_file(repo: Path, sha: str, path: str) -> bytes | None:
    """A .gitignore's bytes at a revision: b"" when absent, None when it is not an ordinary file within bounds."""
    try:
        raw, _mode = read_entry(repo, sha, path, 128_000)
    except AssistantError:
        return None
    return b"" if raw is None else raw


def only_appends_patterns(repo: Path, revisions: set[str], head: str, path: str) -> bool:
    """Whether a changed .gitignore only appends ordinary patterns, blank lines or comments to its version at each
    revision, so that it can only make more paths ignored.

    Git uses the last matching pattern, so a pattern added after every existing line keeps each earlier rule's
    meaning, and an ordinary (not negated) one can only ignore a path that was not. The older version must be the
    exact first bytes of the newer one, ending at a line boundary. Anything else still needs a person: a removed,
    edited or reordered line, an added negation, a deleted, emptied or linked file, an older version without a
    final newline, added text that is not UTF-8 or that holds a byte-order mark (which Git skips at the start of
    a file, so it could hide a negation) or a NUL. Nothing read here is reported.
    """
    newer = _rule_file(repo, head, path)
    if not newer:
        return False
    for sha in revisions:
        older = _rule_file(repo, sha, path)
        if older is None or not newer.startswith(older) or (older and not older.endswith(b"\n")):
            return False
        try:
            added = newer[len(older):].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return False
        if "\ufeff" in added or "\0" in added or any(line.startswith("!") for line in added.split("\n")):
            return False
    return True


def screen_ignores(repo: Path, revisions: set[str], paths: list[str]) -> None:
    if not paths:
        return  # Nothing will be read, so no ignore rule can apply.
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
