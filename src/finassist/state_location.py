"""The private state folder shared by every command that reads or writes it."""

from pathlib import Path

from .errors import AssistantError

# Where each command kept its state before this rule. audit, evaluate, evidence, reconcile-budget, review, propose
# and state defaulted --state-dir to .finassist in the working directory, and doctor and init used the same place.
# The other commands with --repo used <repo>/.finassist.
_WORKING_DIRECTORY_COMMANDS = frozenset({
    "audit", "doctor", "evaluate", "evidence", "init", "propose", "reconcile-budget", "review", "state",
})
_EXPLICIT = frozenset({"audit_dir", "state_dir"})


def state_location(args, *, refuse: bool = True) -> tuple[Path, str]:
    """The state folder and the rule that chose it: "audit_dir", "state_dir", "config", "repository" or
    "working_directory".

    Precedence is the global --audit-dir, the command's --state-dir, the repository holding --config (or, outside a
    repository, its folder), the repository holding --repo or the working directory, then the working directory. Nothing is created here. With refuse, an inherited folder is refused while
    the folder this command used before holds a spending ledger: two ledgers would each enforce the budget alone.
    An explicit folder is never refused.
    """
    chosen, origin = _choose(args)
    if refuse and (previous := moved_from(args, chosen, origin)) is not None:
        # The rules by name are public; the two paths are for this machine only.
        error = AssistantError("state_location_moved", {"previous": previous_rule(args), "selected": origin})
        error.local_details.update(previous=str(previous), selected=str(chosen.expanduser().absolute()))
        raise error
    return chosen, origin


def moved_from(args, chosen: Path, origin: str) -> Path | None:
    """The folder this command used before the shared rule, when it holds a ledger and is not the chosen one."""
    if origin in _EXPLICIT:
        return None
    previous = _previous_directory(args).expanduser().absolute()
    if _same(previous, chosen) or not (previous / "audit.sqlite").is_file():
        return None
    return previous


def _choose(args) -> tuple[Path, str]:
    if (audit_dir := getattr(args, "audit_dir", None)) is not None:
        return Path(audit_dir), "audit_dir"
    if (state_dir := getattr(args, "state_dir", None)) is not None:
        return Path(state_dir), "state_dir"
    if (config := getattr(args, "config", None)) is not None:
        # The repository that holds the configuration, so a file kept in a subfolder such as .github/ shares the
        # ledger of commands that name no configuration. Outside a repository: the configuration's own folder.
        folder = Path(config).expanduser().absolute().parent
        return (_repository_root(folder) or folder) / ".finassist", "config"
    root = _repository_root(_search_start(args))
    if root is not None:
        return root / ".finassist", "repository"
    return Path.cwd() / ".finassist", "working_directory"


def _search_start(args) -> Path:
    repo = getattr(args, "repo", None)
    return Path(repo) if repo is not None else Path.cwd()


def _repository_root(start: Path) -> Path | None:
    """The nearest ancestor, start included, holding a .git directory or file. Git itself is not run."""
    current = Path(start).expanduser().absolute()
    if not current.is_dir():
        current = current.parent
    for candidate in (current, *current.parents):
        marker = candidate / ".git"
        if marker.is_dir() or marker.is_file():
            return candidate
    return None


def previous_rule(args) -> str:
    """The rule by which this command chose its folder before the shared rule."""
    if getattr(args, "command", None) in _WORKING_DIRECTORY_COMMANDS or getattr(args, "repo", None) is None:
        return "working_directory"
    return "repo_option"


def _previous_directory(args) -> Path:
    if previous_rule(args) == "repo_option":
        return Path(args.repo) / ".finassist"
    return Path.cwd() / ".finassist"


def _same(left: Path, right: Path) -> bool:
    return Path(left).expanduser().absolute().resolve() == Path(right).expanduser().absolute().resolve()
