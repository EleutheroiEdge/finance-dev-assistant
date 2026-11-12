"""Remedies a program can read.

For each blocker of the range preflight that has a mechanical fix, the settings that would clear it, so that a
script or a coding agent can propose the fix without parsing a sentence. A remedy is a proposal: nothing here
changes a file. Each option says what it does besides clearing the blocker: whether more is sent, more may be
spent, or files are left out of the review. A blocker that needs a decision (a credential in the change, a hidden
character, approval to use the network) has no remedy, and its hint says what to decide.
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


def _listed(paths: list) -> list[str] | None:
    """Names a remedy may list, or None when one cannot be named or there are too many."""
    if not paths or len(paths) > MAX_LISTED_PATHS or any(type(path) is not str or path == _REDACTED for path in paths):
        return None
    return sorted(set(paths))


def _file_limit(rows: list[dict]) -> list[dict]:
    sizes = [row.get("bytes") for row in rows if row.get("status") == "refused" and row.get("code") == "file_limit_exceeded"]
    options = [_option("leaves_files_out", {"setting": "unreviewable_paths", "value": _SKIP})]
    if sizes and all(type(size) is int for size in sizes) and max(sizes) <= MAX_FILE_BYTES:
        options.append(_option("sends_more", {"setting": "max_file_bytes", "at_least": max(sizes)}))
    return options


def _outside_scope(rows: list[dict], left_out: frozenset) -> list[dict]:
    """The configuration route: every left-out file must be one a setting can account for."""
    omitted = [row for row in rows if row.get("status") == "omitted"]
    outside = [row.get("path") for row in omitted if row.get("reason") == "outside_allowlist"]
    unreadable = [row for row in omitted if row.get("reason") in left_out]
    if not omitted or len(outside) + len(unreadable) != len(omitted):
        return []
    changes = [{"setting": "unreviewable_paths", "value": _SKIP}] if unreadable else []
    if outside:
        names = _listed(outside)
        if names is None:
            return []
        changes.append({"setting": "allow_paths", "add": names})
    return [_option("sends_more" if outside else "leaves_files_out", *changes)]


def _options(blocker: dict, rows: list[dict], route: tuple, left_out: frozenset) -> list[dict]:
    _document, too_large, total_setting, outside = route
    code = blocker.get("code")
    if code == "file_limit_exceeded":
        return _file_limit(rows)
    if code == "private_or_binary_path":
        return [_option("leaves_files_out", {"setting": "private_paths", "value": _SKIP})]
    if code in too_large:
        size = blocker.get("bytes")
        if type(size) is int and size <= MAX_PACKET_BYTES:
            return [_option("sends_more", {"setting": total_setting, "at_least": size})]
        return []
    if code == outside == "scope_incomplete":
        return _outside_scope(rows, left_out)
    if code == outside:
        names = _listed([row.get("path") for row in rows if row.get("status") == "refused" and row.get("code") == code])
        return [] if names is None else [_option("sends_more", {"setting": "allow_paths", "add": names})]
    if code in _BUDGETS:
        try:
            needed = float(Decimal(str(blocker.get("reserved_usd"))).quantize(_CENT, rounding=ROUND_UP))
        except (InvalidOperation, ValueError):
            return []
        return [_option("spends_more", {"setting": _BUDGETS[code], "at_least": needed})]
    if code == "provider_prices_required":
        missing = blocker.get("missing")
        if isinstance(missing, list) and missing and all(type(name) is str for name in missing):
            return [_option("none", *({"setting": name, "needs_value": True} for name in missing))]
    return []


def attach_remedies(report: dict, route: str, left_out: frozenset = frozenset()) -> None:
    """Add ``remedies`` to a preflight report: one entry per blocker that has at least one option."""
    names = _ROUTES[route]
    rows = report.get("paths") or []
    found = []
    for blocker in report["blockers"]:
        options = _options(blocker, rows, names, left_out)
        if options:
            found.append({"code": blocker["code"],
                          "options": [{"document": names[0], **option} for option in options]})
    report["remedies"] = found
