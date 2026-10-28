"""Immutable Git context extraction; no checkout, hooks, filters or network."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
import subprocess

from .config import Config
from .errors import AssistantError
from .security import canonical, check_path, check_text, digest


def git(repo: Path, *args: str, binary: bool = False):
    try:
        done = subprocess.run(
            ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(repo), *args],
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


def read_blob(repo: Path, sha: str, path: str, max_bytes: int) -> bytes | None:
    safe_relative = check_path(path)
    entries = git(repo, "ls-tree", "-z", sha, "--", safe_relative, binary=True)
    if not entries:
        return None
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
    return data


@dataclass(frozen=True)
class ContextFile:
    path: str
    status: str
    before: str | None
    after: str | None
    before_hash: str | None
    after_hash: str | None


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
        check_path(path)
        if not config.allows(path):
            omitted.append({"path": path, "reason": "outside_allowlist"})
            continue
        before = read_blob(repo, ancestor, path, config.max_file_bytes)
        after = read_blob(repo, head_sha, path, config.max_file_bytes)
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
                )
            )
        )
    packet = {
        "schema_version": 1,
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
    if not isinstance(packet, dict) or set(packet) != keys or packet["schema_version"] != 1:
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
        accounted.append(check_path(item["path"]))
    for item in packet["files"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "status", "before", "after", "before_hash", "after_hash"}
            or item["status"] not in {"A", "D", "M", "T"}
        ):
            raise AssistantError("packet_schema_invalid")
        accounted.append(check_path(item["path"]))
        if item["before"] is None and item["after"] is None:
            raise AssistantError("packet_schema_invalid")
        for side in ("before", "after"):
            if item[side] is not None and not isinstance(item[side], str):
                raise AssistantError("packet_schema_invalid")
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
