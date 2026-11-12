"""Advisory request lower bounds from already classified paths, without reading blobs."""

from pathlib import Path

from .error_hints import error_fields
from .errors import AssistantError
from .scope import git


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
    total = 0
    try:
        for path, row in zip(paths, rows, strict=True):
            if row["status"] not in {"included", "refused"}:
                continue
            for revision in revisions:
                entry = git(repo, "--literal-pathspecs", "ls-tree", "-l", "-z", revision, "--", path, binary=True)
                if not entry:  # An added/deleted file has only one version.
                    continue
                mode, kind, _oid, size = entry.split(b"\t", 1)[0].decode("ascii").split()
                if kind != "blob" or mode not in {"100644", "100755"}:
                    return None
                count = int(size)
                if count < 0:
                    return None
                total += count
    except (AssistantError, OSError, ValueError, LookupError):
        return None
    if total <= limit:
        return None
    return {"code": "request_lower_bound_exceeded", "lower_bound_bytes": total, "limit": limit, "limit_setting": limit_setting,
            **error_fields("request_lower_bound_exceeded")}
