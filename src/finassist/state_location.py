"""The private state folder shared by every command that reads or writes it."""

from pathlib import Path

from .errors import AssistantError

# These commands stored state in the working directory. review and propose do too,
# even though they accept --repo, because their --state-dir default pointed there.
# Doctor and init hardcoded the same place. Other commands that accept --repo
# stored state in <repo>/.finassist.
_WORKING_DIRECTORY_COMMANDS = frozenset({
    "audit", "doctor", "evaluate", "evidence", "init", "propose", "reconcile-budget",
    "review", "state",
})


def state_location(args) -> tuple[Path, str]:
    """Return the state folder and the rule that selected it.

    Precedence is the global audit directory, the command's state directory,
    the directory holding --config, the repository root, then the working
    directory. An inherited folder is refused when the folder this command
    used to use still holds a spending ledger and the new folder does not.
    Nothing is created here.
    """
    chosen, origin = _choose(args)
    if origin not in {"audit_dir", "state_dir"}:
        _refuse_moved_ledger(args, chosen)
    return chosen, origin


def _choose(args) -> tuple[Path, str]:
    if (audit_dir := getattr(args, "audit_dir", None)) is not None:
        return Path(audit_dir), "audit_dir"
    if (state_dir := getattr(args, "state_dir", None)) is not None:
        return Path(state_dir), "state_dir"
    if (config := getattr(args, "config", None)) is not None:
        return Path(config).expanduser().absolute().parent / ".finassist", "config"
    root = _repository_root(_search_start(args))
    if root is not None:
        return root / ".finassist", "repository"
    return Path.cwd() / ".finassist", "working_directory"


def _search_start(args) -> Path:
    repo = getattr(args, "repo", None)
    if repo is not None:
        return Path(repo)
    return Path.cwd()


def _repository_root(start: Path) -> Path | None:
    """Nearest ancestor, including start, that contains a .git directory or file."""
    current = Path(start).expanduser().absolute()
    if not current.is_dir():
        current = current.parent
    for candidate in (current, *current.parents):
        marker = candidate / ".git"
        if marker.is_dir() or marker.is_file():
            return candidate
    return None


def _refuse_moved_ledger(args, chosen: Path) -> None:
    previous = _previous_directory(args)
    if _same(previous, chosen) or not _holds_ledger(previous) or _holds_ledger(chosen):
        return
    error = AssistantError("state_location_moved")
    error.local_details["previous"] = str(Path(previous).expanduser().absolute())
    error.local_details["selected"] = str(Path(chosen).expanduser().absolute())
    raise error


def _previous_directory(args) -> Path:
    if getattr(args, "command", None) in _WORKING_DIRECTORY_COMMANDS:
        return Path.cwd() / ".finassist"
    repo = getattr(args, "repo", None)
    if repo is not None:
        return Path(repo) / ".finassist"
    return Path.cwd() / ".finassist"


def _same(left: Path, right: Path) -> bool:
    return Path(left).expanduser().absolute().resolve() == Path(right).expanduser().absolute().resolve()


def _holds_ledger(folder: Path) -> bool:
    return (Path(folder) / "audit.sqlite").is_file()
