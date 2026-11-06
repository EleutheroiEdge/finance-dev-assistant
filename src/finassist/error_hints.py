"""A fixed hint for every stable error code, and the offline `explain` command.

Hints are packaged text keyed by code. They hold nothing from the run (no path,
value or content), so an error record can carry its hint beside the code.
"""

from __future__ import annotations

import argparse
import difflib
from functools import lru_cache
from importlib.resources import files
import json
import re
import unicodedata

from .errors import AssistantError
from .guides import GUIDES
from .security import canonical

AREAS = ("setup", "review", "gates", "workflows", "evidence", "state")
CODE = re.compile(r"[a-z][a-z0-9_]{0,79}")
# Printable ASCII only, so hints render the same under any terminal locale.
_TEXT = re.compile(r"[ -~]+")
_LIMITS = {"summary": 160, "fix": 300}
_DOC = re.compile(r"[a-z0-9-]+(?:/[a-z0-9-]+)*\.md")
_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})\.(?:0|[1-9][0-9]{0,3})")
_KEYS = {"summary", "fix", "see", "docs", "retired"}
_GUIDE_FOR = {source: topic for topic, (_title, source, _resource) in GUIDES.items()}


def _unique(pairs):
    table = {}
    for key, value in pairs:
        if key in table:
            raise ValueError("duplicate hint key")
        table[key] = value
    return table


def _valid(code, entry) -> bool:
    if not (isinstance(code, str) and CODE.fullmatch(code) and isinstance(entry, dict)):
        return False
    if not {"summary", "fix"} <= set(entry) <= _KEYS:
        return False
    for key, limit in _LIMITS.items():
        text = entry[key]
        if not (isinstance(text, str) and len(text) <= limit and _TEXT.fullmatch(text)):
            return False
    # A code the package no longer uses keeps its entry, marked with the release that
    # retired it, and is never reused.
    retired = entry.get("retired")
    if retired is not None and not (isinstance(retired, str) and _VERSION.fullmatch(retired)):
        return False
    see, docs = entry.get("see", []), entry.get("docs")
    return (isinstance(see, list) and len(see) <= 3 and code not in see
            and all(isinstance(other, str) and CODE.fullmatch(other) for other in see)
            and (docs is None or isinstance(docs, str) and bool(_DOC.fullmatch(docs))))


@lru_cache(maxsize=1)
def hints() -> dict[str, dict]:
    """Every packaged hint, merged across areas. A damaged table raises ValueError."""
    merged: dict[str, dict] = {}
    for area in AREAS:
        text = files("finassist").joinpath(f"resources/hints-{area}.json").read_text(encoding="utf-8")
        try:
            table = json.loads(text, object_pairs_hook=_unique)
        except RecursionError as exc:  # Deeply nested text is damage too, not a crash.
            raise ValueError("hint table nesting too deep") from exc
        if not isinstance(table, dict):
            raise ValueError("hint table is not an object")
        for code, entry in table.items():
            if not _valid(code, entry) or code in merged:
                raise ValueError("invalid or repeated hint entry")
            merged[code] = {**entry, "area": area}
    return merged


def error_fields(code: str) -> dict:
    """The `hint` field for an error record, or nothing.

    It never raises: a damaged hint table must not hide the error being reported.
    """
    try:
        entry = hints().get(code)
    except Exception:  # noqa: BLE001 - any failure here must leave the original error intact
        return {}
    return {"hint": entry["fix"]} if entry else {}


def _code_from(argument: str) -> str | None:
    """Read a code, or the code in a pasted error record. Never echoed back."""
    text = argument.strip()
    if text.startswith("{"):
        try:
            record = json.loads(text)
        except (ValueError, RecursionError):
            return None
        text = record.get("code") if isinstance(record, dict) else None
        if not isinstance(text, str):
            return None
    # Compatibility folding maps full-width letters (typed through many input
    # methods) to ASCII. Anything still not ASCII afterwards, such as a Cyrillic
    # look-alike or an invisible character, is not a code.
    text = unicodedata.normalize("NFKC", text).casefold().strip().strip("\"'`").replace("-", "_")
    return text if text.isascii() and CODE.fullmatch(text) else None


def explanation(code: str, entry: dict) -> dict:
    result = {"code": code, "area": entry["area"], "summary": entry["summary"], "fix": entry["fix"],
              "see": list(entry.get("see", []))}
    if "retired" in entry:
        result["retired"] = entry["retired"]
    if "docs" in entry:
        source = "docs/" + entry["docs"]
        result["docs"] = source
        if source in _GUIDE_FOR:
            result["guide"] = _GUIDE_FOR[source]
    return result


def _text(result: dict) -> str:
    if "codes" in result:
        return "".join(f"{row['code']}  [{row['area']}]  {row['summary']}\n" for row in result["codes"])
    lines = [f"{result['code']}  [{result['area']}]"]
    if "retired" in result:
        lines.append(f"Retired in {result['retired']}: this version no longer raises it.")
    lines += [f"What happened: {result['summary']}", f"How to fix: {result['fix']}"]
    if result["see"]:
        lines.append("Related: " + ", ".join(result["see"]))
    if "docs" in result:
        offline = f" (offline: finassist guide {result['guide']})" if "guide" in result else ""
        lines.append(f"Read more: {result['docs']}{offline}")
    return "\n".join(lines) + "\n"


def _arguments(parser) -> None:
    parser.add_argument("code", nargs="?", help="An error code, or a pasted error record")
    parser.add_argument("--list", action="store_true", help="List every code with its summary")
    parser.add_argument("--area", choices=AREAS, help="With --list, only codes from this area")
    parser.add_argument("--format", choices=("json", "text"), default="json")


def add_explain_command(commands) -> None:
    """Register explain for help listings; its arguments are parsed by explain_parser()."""
    _arguments(commands.add_parser("explain", help="Explain an error code offline: what it means and how to fix it"))


class _QuietParser(argparse.ArgumentParser):
    """argparse quotes the offending argument in its errors. explain's argument may be pasted
    text from a log, so an unreadable invocation is refused without repeating any of it."""

    def error(self, message):
        raise AssistantError("explain_arguments_invalid")


def explain_parser() -> argparse.ArgumentParser:
    parser = _QuietParser(prog="finassist explain", description="Explain an error code offline")
    _arguments(parser)
    return parser


def explain_arguments(root: argparse.ArgumentParser, argv: list[str]) -> list[str] | None:
    """explain's own arguments when argv selects explain, else None.

    The root's options come first; each is matched as argparse matches it (exact name,
    `--name=value` or a unique prefix), so the command is found without parsing the rest.
    """
    actions = root._option_string_actions  # noqa: SLF001 - argparse has no public lookup
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--" or not item.startswith("-") or item == "-":
            break
        name = item.split("=", 1)[0]
        matches = [name] if name in actions else [option for option in actions if option.startswith(name)
                                                  and name.startswith("--")]
        if len({actions[option] for option in matches}) != 1:
            return None  # Unknown or ambiguous: the root parser reports it.
        action = actions[matches[0]]
        index += 1 if action.nargs == 0 or "=" in item else 2
    if index < len(argv) and argv[index] == "--":
        index += 1
    return argv[index + 1:] if index < len(argv) and argv[index] == "explain" else None


def run_explain(args) -> int:
    if args.list:
        if args.code is not None:
            raise AssistantError("explain_code_or_list_required")
    elif not args.code:
        raise AssistantError("explain_code_or_list_required")
    elif args.area:
        raise AssistantError("explain_area_requires_list")
    try:
        table = hints()
    except (OSError, ValueError) as exc:
        raise AssistantError("error_hints_unavailable") from exc
    if args.list:
        rows = [{"code": code, "area": entry["area"], "summary": entry["summary"],
                 **({"retired": entry["retired"]} if "retired" in entry else {})}
                for code, entry in sorted(table.items()) if args.area in (None, entry["area"])]
        result = {"count": len(rows), "codes": rows}
    else:
        code = _code_from(args.code)
        if code not in table:
            close = difflib.get_close_matches(code, list(table), n=3, cutoff=0.6) if code else []
            raise AssistantError("unknown_error_code", {"suggestions": close})
        result = explanation(code, table[code])
    if args.format == "text":
        print(_text(result), end="")
    else:
        print(canonical(result).decode())
    return 0
