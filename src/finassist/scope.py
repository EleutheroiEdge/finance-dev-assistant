"""Immutable Git context extraction; no checkout, hooks, filters or network."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import os
import re
import subprocess

from .config import Config
from .platform_support import find_tool, clean_environment
from .errors import AssistantError
from .security import PUBLIC_ASSETS, canonical, check_path, check_text, digest


def git_environment() -> dict[str, str]:
    environment = {
        **clean_environment(),
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
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


def git_command(repo: Path, *args: str) -> list[str]:
    newline = _newline_options(repo) if args and args[0] in {"status", "apply"} else []
    return [
        find_tool("git"),
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
    sha = git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
        raise AssistantError("invalid_revision")
    return sha


def read_entry(repo: Path, sha: str, path: str, max_bytes: int) -> tuple[bytes | None, str | None]:
    safe_relative = check_path(path)
    entries = git(repo, "--literal-pathspecs", "ls-tree", "-z", sha, "--", safe_relative, binary=True)
    if not entries:
        return None, None
    header = entries.split(b"\t", 1)[0].decode()
    mode, kind, oid = header.split()
    if kind != "blob" or mode not in {"100644", "100755"}:
        raise AssistantError("linked_or_special_git_object")
    size = int(git(repo, "cat-file", "-s", oid))
    if size > max_bytes:
        raise AssistantError("file_limit_exceeded")
    data = git(repo, "cat-file", "blob", oid, binary=True)
    if len(data) != size:
        raise AssistantError("blob_changed")
    return data, mode


def read_blob(repo: Path, sha: str, path: str, max_bytes: int) -> bytes | None:
    return read_entry(repo, sha, path, max_bytes)[0]


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


def build_packet(repo: Path, base: str, head: str, config: Config) -> dict:
    """Review the head's own change from its merge base, not unrelated base additions."""
    config.validate()
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
    files, omitted, changed = [], [], []
    for pos in range(0, len(tokens) - 1, 2):
        status, path = tokens[pos : pos + 2]
        changed.append(path)
        check_path(path, source_only=False, metadata_only=True)
        check_text(path, extra_patterns=config.extra_sensitive_patterns)
        if Path(path).suffix.lower() in PUBLIC_ASSETS:
            omitted.append({"path": path, "reason": "binary_asset_excluded"})
            continue
        if not config.allows(path):
            omitted.append({"path": path, "reason": "outside_allowlist"})
            continue
        before, before_mode = read_entry(repo, ancestor, path, config.max_file_bytes)
        after, after_mode = read_entry(repo, head_sha, path, config.max_file_bytes)
        decoded = []
        for data in (before, after):
            try:
                text = data.decode("utf-8") if data is not None else None
            except UnicodeError as exc:
                raise AssistantError("non_text_blob") from exc
            if text is not None:
                check_text(text, extra_patterns=config.extra_sensitive_patterns)
            decoded.append(text)
        files.append(
            asdict(
                ContextFile(
                    path,
                    status,
                    *decoded,
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
        "changed_paths": changed,
        "files": files,
        "omitted": omitted,
        "data_class": "screened-source",
        "classification_limit": "Pattern screening does not prove source contains no private information.",
    }
    encoded = canonical(packet)
    if len(encoded) > config.max_packet_bytes:
        raise AssistantError("packet_limit_exceeded")
    return {**packet, "packet_hash": digest(encoded)}


def verify_packet(packet: dict) -> None:
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
        "packet_hash",
    }
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
    accounted = []
    for item in packet["omitted"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "reason"}
            or not isinstance(item["reason"], str)
        ):
            raise AssistantError("packet_schema_invalid")
        accounted.append(check_path(item["path"], source_only=False, metadata_only=True))
    for item in packet["files"]:
        file_keys = {"path", "status", "before", "after", "before_hash", "after_hash"}
        if packet["schema_version"] == 2:
            file_keys |= {"before_mode", "after_mode"}
        if not isinstance(item, dict) or set(item) != file_keys or item["status"] not in {"A", "D", "M", "T"}:
            raise AssistantError("packet_schema_invalid")
        accounted.append(check_path(item["path"]))
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
        check_path(file["path"])
        for side in ("before", "after"):
            data = file[side]
            if (digest(data.encode()) if data is not None else None) != file[side + "_hash"]:
                raise AssistantError("file_integrity_failed")
            if data is not None:
                check_text(data)


def triage(packet: dict) -> dict:
    verify_packet(packet)
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
        "coverage_complete": not packet["omitted"],
        "changes_present": bool(packet["changed_paths"]),
        "next_action": "inspect context, select test recipes, reproduce material findings",
    }
