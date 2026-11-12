"""Remedies a program can read.

For each blocker of the range preflight that has a mechanical fix, the settings that would clear it, so that a
script or a coding agent can propose the fix without parsing a sentence. A remedy is a proposal: nothing here
changes a file. Each option says what it does besides clearing the blocker: whether more is sent, more may be
spent, or files are left out of the review. A blocker that needs a decision (a credential in the change, a hidden
character, approval to use the network) has no remedy, and its hint says what to decide.

An option is offered only when it is known to clear its blocker. Where that cannot be established from what the
preflight has in hand, the option is left out and the hint stands alone.
"""

from decimal import ROUND_UP, Decimal, InvalidOperation

from .config import MAX_PACKET_BYTES

MAX_FILE_BYTES = 2_000_000  # The ceiling of max_file_bytes: above it no setting clears a file refusal.
MAX_LISTED_PATHS = 50  # A longer list is a scope question for a person, not a remedy.
_SKIP = "skip-and-report"
_REDACTED = "[redacted]"  # What a report shows in place of a name that fails screening.
_CENT = Decimal("0.01")
_BUDGETS = {"run_budget_exceeded": "max_run_usd", "daily_budget_exceeded": "daily_budget_usd",
            "monthly_budget_exceeded": "monthly_budget_usd"}
# Per route: the document a remedy edits, the blockers for a change that is too large as a whole with the setting
# that bounds it, and the blocker for a changed path outside the scope. The gate has no packet setting of its own:
# its packet limit is the larger of 2,000,000 bytes and max_request_bytes, so both of its codes name that setting.
_ROUTES = {
    "configuration": ("configuration", ("packet_limit_exceeded",), "max_packet_bytes", "scope_incomplete"),
    "gate": ("gate policy", ("gate_request_bytes_exceeded", "packet_limit_exceeded"), "max_request_bytes",
             "gate_path_not_allowed"),
}


def _option(effect: str, *changes: dict) -> dict:
    return {"effect": effect, "changes": list(changes)}


def _listed(paths: list, valid_path) -> list[str] | None:
    """Names a remedy may list, or None when one cannot be named, is not a valid entry, or there are too many."""
    if not paths or len(paths) > MAX_LISTED_PATHS or any(type(path) is not str or path == _REDACTED for path in paths):
        return None
    if valid_path is not None and not all(valid_path(path) for path in paths):
        return None
    return sorted(set(paths))


def _leave_out(rows: list[dict], setting: str) -> list[dict]:
    """Leaving files out helps only when another file stays in the review: otherwise nothing is left to send,
    and that blocker has no remedy."""
    if not any(row.get("status") == "included" for row in rows):
        return []
    return [_option("leaves_files_out", {"setting": setting, "value": _SKIP})]


def _file_limit(rows: list[dict], sizes: dict | None, fixture_roots: tuple) -> list[dict]:
    refused = [row.get("path") for row in rows
               if row.get("status") == "refused" and row.get("code") == "file_limit_exceeded"]
    # A fixture has a limit of its own, and the report does not say which limit refused a file. With fixture roots
    # in play, a file under one, or one whose name is not shown, gets no remedy: the hint names both settings.
    if fixture_roots and any(type(path) is not str or path == _REDACTED or path.startswith(tuple(fixture_roots))
                             for path in refused):
        return []
    options = _leave_out(rows, "unreviewable_paths")
    # The refusal reports the first version it met. The other version may be larger, so an increase is offered
    # only when the size of both versions of every refused file is known.
    if sizes is not None and refused and all(type(path) is str and path in sizes for path in refused):
        largest = max(sizes[path] for path in refused)
        if type(largest) is int and largest <= MAX_FILE_BYTES:
            options.append(_option("sends_more", {"setting": "max_file_bytes", "at_least": largest}))
    return options


def _outside_scope(rows: list[dict], left_out: frozenset, valid_path) -> list[dict]:
    """The configuration route: every left-out file must be one a setting can account for."""
    omitted = [row for row in rows if row.get("status") == "omitted"]
    outside = [row.get("path") for row in omitted if row.get("reason") == "outside_allowlist"]
    unreadable = [row for row in omitted if row.get("reason") in left_out]
    if not omitted or len(outside) + len(unreadable) != len(omitted):
        return []
    if unreadable and not outside and not any(row.get("status") == "included" for row in rows):
        return []  # Leaving the unreadable files out would leave nothing to review.
    changes = [{"setting": "unreviewable_paths", "value": _SKIP}] if unreadable else []
    if outside:
        names = _listed(outside, valid_path)
        if names is None:
            return []
        changes.append({"setting": "allow_paths", "add": names})
    return [_option("sends_more" if outside else "leaves_files_out", *changes)]


def _budget(blocker: dict, setting: str) -> list[dict]:
    try:
        reserve = Decimal(str(blocker.get("reserved_usd")))
        if not reserve.is_finite() or reserve <= 0:
            return []
        needed = float(reserve.quantize(_CENT, rounding=ROUND_UP))
    except (InvalidOperation, ValueError):
        return []
    return [_option("spends_more", {"setting": setting, "at_least": needed})]


def _options(blocker: dict, rows: list[dict], route: tuple, left_out: frozenset, sizes, fixture_roots,
             valid_path) -> list[dict]:
    _document, too_large, total_setting, outside = route
    code = blocker.get("code")
    if code == "file_limit_exceeded":
        return _file_limit(rows, sizes, fixture_roots)
    if code == "private_or_binary_path":
        return _leave_out(rows, "private_paths")
    if code in too_large:
        size = blocker.get("bytes")
        if type(size) is int and size <= MAX_PACKET_BYTES:
            return [_option("sends_more", {"setting": total_setting, "at_least": size})]
        return []
    if code == outside == "scope_incomplete":
        return _outside_scope(rows, left_out, valid_path)
    if code == outside:
        names = _listed([row.get("path") for row in rows if row.get("status") == "refused" and row.get("code") == code],
                        valid_path)
        return [] if names is None else [_option("sends_more", {"setting": "allow_paths", "add": names})]
    if code in _BUDGETS:
        return _budget(blocker, _BUDGETS[code])
    if code == "provider_prices_required":
        missing = blocker.get("missing")
        if isinstance(missing, list) and missing and all(type(name) is str for name in missing):
            return [_option("none", *({"setting": name, "needs_value": True} for name in missing))]
    return []


def attach_remedies(report: dict, route: str, left_out: frozenset = frozenset(), *, sizes: dict | None = None,
                    fixture_roots: tuple = (), valid_path=None) -> None:
    """Add ``remedies`` to a preflight report: one entry per blocker that has at least one option.

    ``sizes`` maps each file refused for size to the size of its larger version, or is None when that is not
    known. ``fixture_roots`` are the gate policy's fixture prefixes. ``valid_path`` says whether a path may be
    listed in the route's ``allow_paths``.
    """
    names = _ROUTES[route]
    rows = report.get("paths") or []
    found = []
    for blocker in report["blockers"]:
        options = _options(blocker, rows, names, left_out, sizes, tuple(fixture_roots), valid_path)
        if options:
            found.append({"code": blocker["code"],
                          "options": [{"document": names[0], **option} for option in options]})
    report["remedies"] = found
