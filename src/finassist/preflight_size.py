"""Advisory request lower bounds from already classified paths, without reading blobs."""

from pathlib import Path

from .error_hints import error_fields
from .errors import AssistantError
from .scope import git

# Leave ample room for the executable and fixed arguments on Windows. Count
# UTF-8 bytes twice, plus quoting/separators, to bound escaped path arguments.
_PATH_ARGUMENT_BUDGET = 8_000


def _path_batches(paths: list[str]) -> list[list[str]]:
    batches, batch, used = [], [], 0
    for path in paths:
        cost = 2 * len(path.encode("utf-8")) + 3
        if cost > _PATH_ARGUMENT_BUDGET:
            raise ValueError("path argument too long")
        if batch and used + cost > _PATH_ARGUMENT_BUDGET:
            batches.append(batch)
            batch, used = [], 0
        batch.append(path)
        used += cost
    if batch:
        batches.append(batch)
    return batches


def size_warning(repo: Path, revisions: tuple[str, str], paths: list[str], rows: list[dict],
                 limit: int, limit_setting: str) -> dict | None:
    """Sum both versions only when at least one size refusal is the sole path blocker.

    Omitted/withheld files never contribute. This is not a request estimate or a
    screening result: unread content may still refuse after a file limit is raised.
    Failed metadata reads suppress the advisory; they must not change blockers.
    """
    refused = [row for row in rows if row["status"] == "refused"]
    if (not refused or any(row["code"] != "file_limit_exceeded" for row in refused)
            or any(row["status"] == "unchecked" for row in rows)):
        return None
    total, seen = 0, set()
    try:
        selected = [path for path, row in zip(paths, rows, strict=True)
                    if row["status"] in {"included", "refused"}]
        expected = {path.encode("utf-8") for path in selected}
        if len(expected) != len(selected):
            return None
        batches = _path_batches(selected)
        for revision in revisions:
            for batch in batches:
                wanted, found = {path.encode("utf-8") for path in batch}, set()
                raw = git(repo, "--literal-pathspecs", "ls-tree", "-l", "-z", revision, "--", *batch, binary=True)
                if raw and not raw.endswith(b"\0"):
                    return None
                # Git returns tree order, not argument order. Match the literal
                # NUL-delimited name, including any tabs inside that name.
                for entry in raw.split(b"\0")[:-1]:
                    header, name = entry.split(b"\t", 1)
                    if name not in wanted or name in found:
                        return None
                    mode, kind, _oid, size = header.decode("ascii").split()
                    if kind != "blob" or mode not in {"100644", "100755"}:
                        return None
                    count = int(size)
                    if count < 0:
                        return None
                    total += count
                    found.add(name)
                seen.update(found)
        # Added/deleted files may be absent at one revision, never at both.
        if seen != expected:
            return None
    except (AssistantError, OSError, ValueError, LookupError):
        return None
    if total <= limit:
        return None
    return {"code": "request_lower_bound_exceeded", "lower_bound_bytes": total, "limit": limit, "limit_setting": limit_setting,
            **error_fields("request_lower_bound_exceeded")}
