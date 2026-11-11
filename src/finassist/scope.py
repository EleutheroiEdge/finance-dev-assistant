"""Immutable Git context extraction; no checkout, hooks, filters or network."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
import os
import re
import subprocess

from .config import Config
from .platform_support import find_tool, clean_environment
from .errors import AssistantError, local_details
from .forbidden_tokens import TokenGuard, screen_related, screen_source, screen_text
from .security import PUBLIC_ASSETS, canonical, check_name, check_private_name, check_text, digest, local_name


def git_environment() -> dict[str, str]:
    environment = {
        **clean_environment(),
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return environment


def _newline_options(repo: Path) -> list[str]:
    # Query only two enumerated formatting settings in the host's normal Git
    # config scopes. Source/status/apply still run with hooks, filters, global
    # configuration and untrusted GIT_* overrides disabled.
    environment = clean_environment()
    for name in ("HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME"):
        if name in os.environ:
            environment[name] = os.environ[name]
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = []
    for key, allowed in (
        ("core.autocrlf", {"true", "false", "input"}),
        ("core.eol", {"lf", "crlf", "native"}),
    ):
        try:
            value = subprocess.run(
                [
                    find_tool("git"),
                    "-c",
                    "core.hooksPath=" + os.devnull,
                    "-c",
                    "core.fsmonitor=false",
                    "-C",
                    str(repo),
                    "config",
                    "--get",
                    key,
                ],
                capture_output=True,
                env=environment,
                timeout=10,
                check=False,
            )
            text = value.stdout.decode("ascii").strip().lower()
            if key == "core.autocrlf":
                text = {
                    "yes": "true",
                    "on": "true",
                    "1": "true",
                    "": "true",
                    "no": "false",
                    "off": "false",
                    "0": "false",
                }.get(text, text)
            if value.returncode == 1:
                continue
            if value.returncode != 0 or text not in allowed:
                raise AssistantError("git_newline_policy_invalid")
            result.extend(["-c", key + "=" + text])
        except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
            raise AssistantError("git_newline_policy_unavailable") from exc
    return result


@lru_cache(maxsize=8)
def _supports_no_lazy_fetch(executable: str) -> bool:
    # Metadata-only capability probe: upstream added this option/env in2.45,
    # not2.44. Probe rather than trusting vendor/backport version strings.
    try:
        result = subprocess.run([executable, "--no-lazy-fetch", "--version"],
                                env=git_environment(), capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AssistantError("git_capability_check_failed") from exc
    if result.returncode not in {0, 129}:
        raise AssistantError("git_capability_check_failed")
    return result.returncode == 0


def _offline_git_options(repo: Path, executable: str) -> list[str]:
    if _supports_no_lazy_fetch(executable):
        return ["--no-lazy-fetch"]
    # Older Git silently ignores the environment variable. Read only config
    # names before any object/ref command; no Git object lookup or remote IO.
    # Do not cache this check: repository settings can change between calls.
    try:
        result = subprocess.run([
            executable, "--no-optional-locks", "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=" + os.devnull, "-C", str(repo), "config",
            "--name-only", "--get-regexp",
            r"^(remote\..*\.(promisor|partialclonefilter)|extensions\.partialclone)$",
        ], env=git_environment(), capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AssistantError("git_read_failed") from exc
    if result.returncode == 0:
        raise AssistantError("git_partial_clone_unsupported")
    if result.returncode != 1:
        raise AssistantError("git_read_failed")
    return []


def git_command(repo: Path, *args: str) -> list[str]:
    executable = find_tool("git")
    offline = _offline_git_options(repo, executable)
    newline = _newline_options(repo) if args and args[0] in {"status", "apply"} else []
    return [
        executable,
        *offline,
        "--no-replace-objects",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=" + os.devnull,
        *newline,
        "-C",
        str(repo),
        *args,
    ]


def git(repo: Path, *args: str, binary: bool = False):
    try:
        done = subprocess.run(
            git_command(repo, *args),
            env=git_environment(),
            capture_output=True,
            timeout=30,
            check=True,
        )
        return done.stdout if binary else done.stdout.decode("utf-8", errors="strict").strip()
    except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
        raise AssistantError("git_read_failed") from exc


def resolve(repo: Path, ref: str) -> str:
    if not ref or ref.startswith("-") or "\0" in ref:
        raise AssistantError("invalid_revision")
    try:
        result = subprocess.run(
            git_command(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", ref + "^{commit}"),
            env=git_environment(), capture_output=True, timeout=30, check=False,
        )
        sha = result.stdout.decode("ascii").strip()
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise AssistantError("git_read_failed") from exc
    # --verify --quiet uses1 for an unavailable commit; Git/config/process
    # failures must not masquerade as missing objects (or authorize a fetch).
    if result.returncode == 1:
        raise AssistantError("git_commit_unavailable")
    if result.returncode != 0:
        raise AssistantError("git_read_failed")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
        raise AssistantError("invalid_revision")
    return sha


def read_entry(
    repo: Path, sha: str, path: str, max_bytes: int, config: Config | None = None
) -> tuple[bytes | None, str | None]:
    safe_relative = (config or Config()).check_path(path)
    entries = git(repo, "--literal-pathspecs", "ls-tree", "-z", sha, "--", safe_relative, binary=True)
    if not entries:
        return None, None
    header = entries.split(b"\t", 1)[0].decode()
    mode, kind, oid = header.split()
    if kind != "blob" or mode not in {"100644", "100755"}:
        raise AssistantError("linked_or_special_git_object")
    size = int(git(repo, "cat-file", "-s", oid))
    if size > max_bytes:
        raise AssistantError("file_limit_exceeded", {"limit": max_bytes, "bytes": size})
    data = git(repo, "cat-file", "blob", oid, binary=True)
    if len(data) != size:
        raise AssistantError("blob_changed")
    return data, mode


def read_blob(repo: Path, sha: str, path: str, max_bytes: int, config: Config | None = None) -> bytes | None:
    return read_entry(repo, sha, path, max_bytes, config)[0]


@dataclass(frozen=True)
class ContextFile:
    path: str
    status: str
    before: str | None
    after: str | None
    before_hash: str | None
    after_hash: str | None
    before_mode: str | None
    after_mode: str | None


# Path refusals that mean "private", which skip-and-report withholds instead of refusing.
# Any other refusal, including a name that itself looks like a credential, still refuses.
WITHHELD_CODES = frozenset({"private_path", "private_or_binary_path", "private_profile_path", "gate_private_path"})
WITHHELD_REASON = "private_path_policy"
# Refusals that mean only "this file cannot be reviewed", with the reason each gets when
# unreviewable_paths is skip-and-report: the file is left out unread and named in the packet.
# Every route asks left_out(); none keeps its own list. Any other refusal stands.
UNREVIEWABLE_REASONS = {"unsupported_file_type": "unsupported_file_type",
                        "file_limit_exceeded": "file_limit_exceeded",
                        "non_text_blob": "non_text_blob",
                        "gate_path_not_allowed": "outside_allowlist"}
_NAMED = 20  # Example names kept per refusal code in local output.


def left_out(config: Config, code: str) -> str | None:
    """The reason to leave a file out for this refusal, or None when the refusal stands."""
    if config.unreviewable_paths != "skip-and-report":
        return None
    return UNREVIEWABLE_REASONS.get(code)


def omission_reason(config: Config, path: str) -> str | None:
    """Why a path is left out of a packet by its name alone, or None when its content decides.

    The packet builder, both preflights and the gate use this one order, so a path gets the
    same reason wherever it is reported: generated, then a binary asset, then the allow list.
    """
    if config.generated(path):
        return "generated_artifact_excluded"
    if Path(path).suffix.lower() in PUBLIC_ASSETS:
        return "binary_asset_excluded"
    if not config.allows(path):
        return "outside_allowlist"
    return None


def require_regular(repo: Path, revisions: tuple[str, str], path: str) -> None:
    """Refuse a symbolic link, a submodule or another special entry at either revision. No blob is read."""
    for revision in revisions:
        entries = git(repo, "--literal-pathspecs", "ls-tree", "-z", revision, "--", path, binary=True)
        if entries:
            mode, kind, _oid = entries.split(b"\t", 1)[0].decode().split()
            if kind != "blob" or mode not in {"100644", "100755"}:
                raise AssistantError("linked_or_special_git_object")


def omission_for(repo: Path, revisions: tuple[str, str], path: str, config: Config, code: str) -> str | None:
    """The reason to leave this file out for a refusal, or None when the refusal stands.

    A file is left out only as an ordinary file: a link, a submodule or another special entry at
    either revision still refuses, whatever reason the file would have been left out for.
    """
    reason = left_out(config, code)
    if reason is not None:
        require_regular(repo, revisions, path)
    return reason


# A version over the byte limit, or not UTF-8, cannot be read. That is known for one version at a
# time, and it must not stop the other version from being screened.
_UNREADABLE = frozenset({"file_limit_exceeded", "non_text_blob"})


def read_sides(repo: Path, revisions: tuple[str, str], path: str, config: Config, screen=None) -> list[tuple]:
    """Both versions of one changed file, as (bytes, mode, text), read and screened.

    The one reader for plan and both preflights, so each refuses or leaves out the same file
    for the same reason. Each version is read, decoded and screened for credentials, and by
    `screen(text, path)` when the caller lists confidential figures. A version over the byte
    limit is decided from its object header and never read.

    A version that cannot be read does not hide the other one: the readable version is still
    screened, and a credential or a listed figure in it refuses. Only then is the unreadable
    version's own refusal raised, which a caller may turn into leaving the file out.
    """
    limit = config.file_byte_limit(path)
    sides, unreadable = [], None
    for version, revision in zip(("base", "head"), revisions, strict=True):
        try:
            data, mode = read_entry(repo, revision, path, limit, config)
            text = None
            if data is not None:
                try:
                    text = data.decode("utf-8")
                except UnicodeError as exc:
                    raise AssistantError("non_text_blob") from exc
        except AssistantError as exc:
            if exc.code not in _UNREADABLE:
                raise
            unreadable = unreadable or exc
            continue
        if text is not None:
            try:
                check_text(text, extra_patterns=config.extra_sensitive_patterns, source_path=path)
            except AssistantError as exc:
                exc.local_details.setdefault("version", version)  # The lines are counted in this version.
                raise
            if screen is not None:
                screen(text, path)
        sides.append((data, mode, text))
    if unreadable is not None:
        raise unreadable
    return sides


def _private_name(config: Config, path: str) -> bool:
    """Whether this name alone makes the path private, by the rules the gate uses. Never reads it.

    That is the configuration's path rules plus the gate's private directories and file
    names (data, private, client, household and similar), so plan and gate withhold alike.
    """
    try:
        config.check_path(path, source_only=False, metadata_only=True)
        check_private_name(path)
    except AssistantError as exc:
        return exc.code in WITHHELD_CODES
    return False


def _refused_names(refused: list, config: Config) -> AssistantError:
    """One error for every name refused before anything is read.

    It keeps the first refusal's code and details and adds the refused count. The names,
    grouped by code and screened like any local name, go only into local details.
    """
    first = refused[0][0]
    error = AssistantError(first.code, {**first.public_details, "refused_count": len(refused)})
    groups: dict[str, dict] = {}
    for exc, path in refused:
        group = groups.setdefault(exc.code, {"code": exc.code, "count": 0, "paths": []})
        group["count"] += 1
        if len(group["paths"]) < _NAMED:
            group["paths"].append(local_name(path, config.extra_sensitive_patterns))
    error.local_details["refused_paths"] = list(groups.values())
    return error


def _screened_name(config: Config, path: str) -> bool:
    """Whether a related-context candidate's name passes every name rule. Never reads it."""
    try:
        config.check_path(path, metadata_only=True)
        check_private_name(path)
        check_name(path, extra_patterns=config.extra_sensitive_patterns)
    except AssistantError:
        return False
    return True


def _grep_names(repo: Path, head: str, names: list[str], paths: list[str]) -> list[str]:
    """Screened paths whose head blob mentions any name as a word. Only the listed paths are read."""
    found = []
    patterns = [argument for name in names[:200] for argument in ("-e", name)]
    for start in range(0, len(paths), 200):
        command = git_command(repo, "--literal-pathspecs", "grep", "-l", "-z", "-I", "-F", "-w", "--no-color",
                              "--no-textconv", *patterns, head, "--", *paths[start:start + 200])
        try:
            done = subprocess.run(command, env=git_environment(), capture_output=True, timeout=30)
            if done.returncode not in {0, 1}:  # 1 means no match.
                raise AssistantError("git_read_failed")
            listed = done.stdout.decode("utf-8", errors="strict").split("\0")
        except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
            raise AssistantError("git_read_failed") from exc
        found += [entry.removeprefix(head + ":") for entry in listed if entry]
    return sorted(set(found) & set(paths))


def checkout_roots(repo: Path) -> tuple[Path, ...]:
    """The checkout, its common Git directory and every linked worktree: all one repository."""
    common = Path(git(repo, "rev-parse", "--git-common-dir"))
    entries = git(repo, "worktree", "list", "--porcelain", "-z", binary=True).decode().split("\0")
    return (repo, common if common.is_absolute() else repo / common,
            *(Path(entry.removeprefix("worktree ")) for entry in entries if entry.startswith("worktree ")))


def config_token_guard(config: Config, repo: Path) -> TokenGuard | None:
    """The figure screen a configuration asks for, or None when it lists no figures."""
    rules = config.forbidden_token_rules
    if not rules:
        return None
    return TokenGuard.load(rules, checkout_roots(repo))


def _related(repo: Path, head: str, files: list[dict], config: Config, room: int, admit=None, screen=None,
             left: frozenset = frozenset()) -> dict:
    """`left` holds the changed paths that were left out: they are never searched or read as context."""
    from .related import candidates, related_block

    listing = git(repo, "ls-tree", "-r", "-z", "--name-only", head, binary=True)
    tracked = set()
    for raw in listing.split(b"\0"):
        try:
            name = raw.decode("utf-8")
        except UnicodeError:
            continue
        if name.endswith(".py") and name not in left and _screened_name(config, name):
            tracked.add(name)
    if admit is not None:  # A gate's deny and ignore rules, applied before any search or read.
        tracked &= set(admit(sorted(tracked)))

    def read(path: str) -> str:
        data, _mode = read_entry(repo, head, path, config.file_byte_limit(path), config)
        if data is None:
            raise AssistantError("related_source_missing")
        try:
            text = data.decode("utf-8")
        except UnicodeError as exc:
            raise AssistantError("non_text_blob") from exc
        check_text(text, extra_patterns=config.extra_sensitive_patterns, source_path=path)
        if screen is not None:  # Forbidden figures: the whole file, as for a changed file.
            screen(text, path)
        return text

    changed = {file["path"] for file in files}
    readable = sorted(path for path in tracked if path not in changed and config.allows(path)
                      and not config.generated(path))
    ranked, skipped = candidates(repo, head, files, config, tracked, read,
                                 lambda names: _grep_names(repo, head, names, readable))
    # About as much context as changed code (1:1), with a 16 KB floor so a small change still gets
    # some, never over the configured cap or the room left in the packet.
    own = sum(len((file["after"] if file["after"] is not None else file["before"]).encode()) for file in files)
    return related_block(ranked, skipped, max(0, min(config.related_max_bytes, max(own, 16_000), room)))


def build_packet(
    repo: Path, base: str, head: str, config: Config, *, withhold: frozenset = frozenset(),
    withheld_names: list | None = None, related_admit=None, token_guard: TokenGuard | None = None,
) -> dict:
    """Review the head's own change from its merge base, not unrelated base additions.

    Every caller gets the configuration's figure screen: instructions, both versions of every
    file, each related candidate's whole file and every snippet line. A gate passes its policy's
    guard instead.
    """
    config.validate()
    guard = token_guard if token_guard is not None else config_token_guard(config, repo)
    if guard is not None:
        screen_text(config.instructions(), guard.snapshot)
    base_sha, head_sha = resolve(repo, base), resolve(repo, head)
    ancestor = git(repo, "merge-base", base_sha, head_sha)
    # No rename collapsing: both old deletion and new addition are screened.
    raw = git(
        repo,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--name-status",
        "-z",
        ancestor,
        head_sha,
        binary=True,
    )
    tokens = raw.decode("utf-8", errors="strict").split("\0")
    # Every later command refuses a packet over 2,000 changed paths, so none is built.
    if len(tokens) // 2 > 2000:
        raise AssistantError("packet_file_count_limit")
    files, omitted, changed = [], [], []
    withheld = 0
    skipping = config.private_paths == "skip-and-report"
    selected, refused = [], []
    screen = None if guard is None else (lambda text, name: screen_source(text, name, guard.snapshot))
    # Every name is checked before any file is read, so one refusal can name every refused path.
    for pos in range(0, len(tokens) - 1, 2):
        status, path = tokens[pos : pos + 2]
        if skipping and (path in withhold or _private_name(config, path)):
            # A name matching a configured sensitive pattern refuses: it is never withheld or shown.
            check_name(path, extra_patterns=config.extra_sensitive_patterns)
            # Withheld before anything is read: no blob, size or hash, and no name in the packet.
            withheld += 1
            if withheld_names is not None:
                withheld_names.append(path)
            continue
        try:
            config.check_path(path, source_only=False, metadata_only=True)
            check_name(path, extra_patterns=config.extra_sensitive_patterns)
        except AssistantError as exc:
            refused.append((exc, path))
            continue
        selected.append((status, path))
    if refused:
        raise _refused_names(refused, config)
    for status, path in selected:
        changed.append(path)
        reason = omission_reason(config, path)
        if reason is not None:
            omitted.append({"path": path, "reason": reason})
            continue
        try:
            (before, before_mode, before_text), (after, after_mode, after_text) = read_sides(
                repo, (ancestor, head_sha), path, config, screen)
        except AssistantError as exc:
            try:
                reason = omission_for(repo, (ancestor, head_sha), path, config, exc.code)
            except AssistantError as special:  # A link or submodule: never left out.
                exc, reason = special, None
            if reason is None:
                # Local output only (plan and watch print it); never in a packet, report or audit row.
                exc.local_details.setdefault("path", local_name(path, config.extra_sensitive_patterns))
                raise exc
            # It cannot be reviewed, and the configuration leaves such files out: named, never sent.
            omitted.append({"path": path, "reason": reason})
            continue
        files.append(
            asdict(
                ContextFile(
                    path,
                    status,
                    before_text,
                    after_text,
                    digest(before) if before is not None else None,
                    digest(after) if after is not None else None,
                    before_mode,
                    after_mode,
                )
            )
        )
    packet = {
        "schema_version": 2,
        "base": base_sha,
        "head": head_sha,
        "merge_base": ancestor,
        "profile": config.profile,
        "generated_paths": list(config.generated_paths),
        "allow_paths": list(config.allow_paths),
        "changed_paths": changed,
        "files": files,
        "omitted": omitted,
        "data_class": "screened-source",
        "classification_limit": "Pattern screening does not prove source contains no private information.",
    }
    if withheld:
        packet["withheld"] = {"count": withheld, "reason": WITHHELD_REASON}
    if config.related_context == "related":
        # 16 KiB is kept for the block's own fields and the names of skipped candidates.
        room = config.max_packet_bytes - len(canonical(packet)) - 16_384
        packet["related"] = _related(repo, head_sha, files, config, room, related_admit, screen,
                                     frozenset(row["path"] for row in omitted))
        if guard is not None:
            screen_related(packet, guard.snapshot)
    encoded = canonical(packet)
    if len(encoded) > config.max_packet_bytes:
        raise AssistantError("packet_limit_exceeded", {"limit": config.max_packet_bytes, "bytes": len(encoded)})
    return {**packet, "packet_hash": digest(encoded)}


def plan_packet(repo: Path, base: str, head: str, config: Config, config_path: Path | None,
                output: str) -> tuple[dict, dict]:
    """The packet plan writes, and its local summary of withheld names and settings with no effect."""
    from .health import config_warnings

    warnings = config_warnings(config, config_path, file_selected=config_path is not None)
    withheld = []  # Private names stay in this local summary, never in the packet.
    with local_details(config_warnings=warnings):  # A setting with no effect often explains a refusal.
        packet = build_packet(repo, base, head, config, withheld_names=withheld)
    summary = {"packet_hash": packet["packet_hash"], "output": output, "triage": triage(packet, config)}
    if withheld:
        summary["withheld_paths"] = [local_name(name, config.extra_sensitive_patterns) for name in withheld]
    if warnings:
        summary["config_warnings"] = warnings
    return packet, summary


def verify_packet(packet: dict, config: Config | None = None) -> None:
    active_config = config is not None
    config = (config or Config()).validate()
    keys = {
        "schema_version",
        "base",
        "head",
        "merge_base",
        "profile",
        "changed_paths",
        "files",
        "omitted",
        "data_class",
        "classification_limit",
        "generated_paths",
        "packet_hash",
    }
    if isinstance(packet, dict) and "allow_paths" in packet:
        keys.add("allow_paths")
    if isinstance(packet, dict) and "withheld" in packet:
        keys.add("withheld")
    if isinstance(packet, dict) and "related" in packet:
        keys.add("related")
    if (
        not isinstance(packet, dict)
        or set(packet) != keys
        or type(packet["schema_version"]) is not int
        or packet["schema_version"] not in {1, 2}
    ):
        raise AssistantError("packet_schema_invalid")
    for key in ("base", "head", "merge_base"):
        if not isinstance(packet[key], str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", packet[key]):
            raise AssistantError("packet_schema_invalid")
    if not all(isinstance(packet[k], list) for k in ("files", "omitted", "changed_paths")):
        raise AssistantError("packet_schema_invalid")
    if len(packet["changed_paths"]) > 2000:
        raise AssistantError("packet_file_count_limit")
    changed = packet["changed_paths"]
    if any(not isinstance(path, str) for path in changed) or len(set(changed)) != len(changed):
        raise AssistantError("packet_coverage_invalid")
    if "withheld" in packet:
        withheld = packet["withheld"]
        if config.private_paths != "skip-and-report":
            raise AssistantError("packet_withheld_not_allowed")
        if (not isinstance(withheld, dict) or set(withheld) != {"count", "reason"}
                or type(withheld["count"]) is not int or not 1 <= withheld["count"] <= 2000 - len(changed)
                or withheld["reason"] != WITHHELD_REASON):
            raise AssistantError("packet_schema_invalid")
    if "related" in packet:
        if config.related_context != "related":
            raise AssistantError("packet_related_not_allowed")
        from .related import verify_related

        verify_related(packet["related"], changed, config, lambda path: not _screened_name(config, path))
    elif active_config and config.related_context == "related":
        raise AssistantError("packet_related_missing")
    if packet["generated_paths"] != list(config.generated_paths):
        raise AssistantError("packet_generated_paths_mismatch")
    if "allow_paths" not in packet:
        if active_config:
            raise AssistantError("packet_allow_paths_missing")
    elif not isinstance(packet["allow_paths"], list) or packet["allow_paths"] != list(config.allow_paths):
        raise AssistantError("packet_allow_paths_mismatch")
    if packet["profile"] != config.profile:
        raise AssistantError("packet_profile_mismatch")
    for name in changed:
        check_name(name, extra_patterns=config.extra_sensitive_patterns)
    accounted = []
    for item in packet["omitted"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "reason"}
            or not isinstance(item["reason"], str)
        ):
            raise AssistantError("packet_schema_invalid")
        if item["reason"] == WITHHELD_REASON:  # Reserved for the count-only withheld record.
            raise AssistantError("packet_schema_invalid")
        accounted.append(config.check_path(item["path"], source_only=False, metadata_only=True))
        if item["reason"] == "generated_artifact_excluded" and not config.generated(item["path"]):
            raise AssistantError("generated_omission_invalid")
    for item in packet["files"]:
        file_keys = {"path", "status", "before", "after", "before_hash", "after_hash"}
        if packet["schema_version"] == 2:
            file_keys |= {"before_mode", "after_mode"}
        if not isinstance(item, dict) or set(item) != file_keys or item["status"] not in {"A", "D", "M", "T"}:
            raise AssistantError("packet_schema_invalid")
        accounted.append(config.check_path(item["path"]))
        if not config.allows(item["path"]):
            raise AssistantError("packet_outside_allowlist")
        if config.generated(item["path"]):
            raise AssistantError("generated_source_in_packet")
        if item["before"] is None and item["after"] is None:
            raise AssistantError("packet_schema_invalid")
        for side in ("before", "after"):
            if item[side] is not None and not isinstance(item[side], str):
                raise AssistantError("packet_schema_invalid")
            if packet["schema_version"] == 2:
                expected_modes = {None} if item[side] is None else {"100644", "100755"}
                if item[side + "_mode"] not in expected_modes:
                    raise AssistantError("packet_mode_invalid")
    if len(set(accounted)) != len(accounted) or set(accounted) != set(changed):
        raise AssistantError("packet_coverage_invalid")
    expected = packet.get("packet_hash")
    if digest(canonical({k: v for k, v in packet.items() if k != "packet_hash"})) != expected:
        raise AssistantError("packet_integrity_failed")
    for file in packet["files"]:
        config.check_path(file["path"])
        for side in ("before", "after"):
            data = file[side]
            if (digest(data.encode()) if data is not None else None) != file[side + "_hash"]:
                raise AssistantError("file_integrity_failed")
            if data is not None:
                size, limit = len(data.encode()), config.file_byte_limit(file["path"])
                if size > limit:
                    raise AssistantError("file_limit_exceeded", {"limit": limit, "bytes": size})
                check_text(data, extra_patterns=config.extra_sensitive_patterns, source_path=file["path"])


def triage(packet: dict, config: Config | None = None) -> dict:
    verify_packet(packet, config)
    risks = set()
    for path in packet["changed_paths"]:
        lower = path.lower()
        for tokens, risk in (
            (("auth", "tenant", "session", "upload"), "security-boundary"),
            (("tax", "lot", "trade", "cash", "money", "ledger"), "financial-correctness"),
            (("price", "source", "research", "filing"), "evidence-and-freshness"),
            (("migration", "schema", "database"), "data-migration"),
            (("workflow", "deploy", "docker"), "release-and-supply-chain"),
        ):
            if any(token in lower for token in tokens):
                risks.add(risk)
    return {
        "risks": sorted(risks),
        "recommended_checks": ["baseline-vs-candidate", "failure-paths", "output-reconciliation"],
        "coverage_complete": not review_omissions(packet),
        "changes_present": bool(packet["changed_paths"]),
        "next_action": "inspect context, select test recipes, reproduce material findings",
    }


def review_omissions(packet: dict) -> list[dict]:
    """Call after verification: configured generated artifacts are outside scope.

    Withheld private paths are an omission too, so every coverage check (readiness,
    workflows, the CI gate) stays incomplete. The row carries a count, never a name.
    """
    rows = [row for row in packet["omitted"] if row["reason"] != "generated_artifact_excluded"]
    if packet.get("withheld"):
        rows.append({"path": None, "reason": WITHHELD_REASON, "count": packet["withheld"]["count"]})
    return rows
