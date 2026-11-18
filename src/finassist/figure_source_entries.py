"""The forbidden_token_sources setting: each entry a path, read every way, or an object that declares the file's
layout. The configuration, the gate policy and the screen all judge entries here; figure_sources reads the files.
"""

from collections.abc import Mapping
from dataclasses import dataclass

from .errors import AssistantError
from .figure_sources import _DELIMITERS, DECIMAL_MARKS
from .forbidden_tokens import MAX_SOURCE_FILES

_LAYOUT_KEYS = frozenset({"path", "delimiter", "decimal_mark"})

# The figure-source reader is experimental: it has missed amounts written in shapes it does not read. Sources are
# read only beside this setting, `true`, in a configuration or a gate policy, and then only by a declared layout.
OPT_IN = "forbidden_token_sources_experimental"
EXPERIMENTAL_WARNING = ("Figure sources are opted in. The reader is experimental: it can miss amounts written in "
                        "shapes it does not read, so it is not a complete screen. List the figures you must never "
                        "send in forbidden_token_file as well.")


# One forbidden_token_sources entry, in the configuration and gate policy schemas: a path, read every way, or an
# object that declares the file's layout, where a null delimiter is one column, each line a cell. A comma that both
# separates columns and marks decimals can't be told apart without quotes, so it is not a layout.
SOURCE_ENTRY_SCHEMA = {"oneOf": [
    {"type": "string", "minLength": 1, "maxLength": 4096},
    {"type": "object", "additionalProperties": False, "required": sorted(_LAYOUT_KEYS),
     "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "delimiter": {"enum": [*_DELIMITERS, None]}, "decimal_mark": {"enum": list(DECIMAL_MARKS)}},
     "not": {"properties": {"delimiter": {"const": ","}, "decimal_mark": {"const": ","}}}},
]}


@dataclass(frozen=True)
class SourceFormat:
    """A figure source with a declared layout: it is read with this delimiter and decimal mark, and no other way."""

    path: str
    delimiter: str | None  # None: one column, each line a cell
    decimal_mark: str


def source_format(item):
    """A layout object as a SourceFormat, so a loaded configuration holds no mutable entry; anything else as it is,
    for source_entries to judge."""
    if isinstance(item, Mapping) and set(item) == _LAYOUT_KEYS:
        return SourceFormat(item["path"], item["delimiter"], item["decimal_mark"])
    return item


def check_opt_in(rules) -> None:
    """Refuse the figure sources these settings list unless they are opted in, each with a declared layout.

    Listed without `"forbidden_token_sources_experimental": true` they are refused by name, never ignored, so no one
    believes a source screens what it does not. Opted in, each declares its layout: the reading-every-way guess
    is not reachable from a configuration or a gate policy. Other damage is left to the schema and source_entries.
    """
    sources = rules.get("forbidden_token_sources") if isinstance(rules, Mapping) else None
    if not sources or not isinstance(sources, (list, tuple)):
        return
    if rules.get(OPT_IN) is not True:
        raise AssistantError("forbidden_token_sources_experimental")
    if any(isinstance(item, str) for item in sources):
        raise AssistantError("forbidden_token_source_layout_required")


def source_entries(sources) -> tuple[tuple[str, tuple[str, str] | None], ...]:
    """(path, declared (delimiter, decimal mark) or None) of each forbidden_token_sources entry, or refused.

    A path named twice is refused in either form: two layouts of one file could list different figures.
    """
    if not isinstance(sources, (list, tuple)) or len(sources) > MAX_SOURCE_FILES:
        raise AssistantError("forbidden_token_source_invalid")
    entries = []
    for item in map(source_format, sources):
        layout = None
        if isinstance(item, SourceFormat):
            layout = (item.delimiter, item.decimal_mark)
            if (not all(part is None or type(part) is str for part in layout) or layout[0] not in (*_DELIMITERS, None)
                    or layout[1] not in DECIMAL_MARKS or layout == (",", ",")):
                raise AssistantError("forbidden_token_source_invalid")
            item = item.path
        if not isinstance(item, str) or not item or len(item) > 4096:
            raise AssistantError("forbidden_token_source_invalid")
        entries.append((item, layout))
    if len({path for path, _layout in entries}) != len(entries):
        raise AssistantError("forbidden_token_source_invalid")
    return tuple(entries)
