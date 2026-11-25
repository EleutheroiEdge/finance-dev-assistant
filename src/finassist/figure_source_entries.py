"""The forbidden_token_sources setting: each entry an object that names a file and declares its whole layout.

The configuration, the gate policy and the screen all judge entries here; figure_sources reads the files, each by its
declared layout and no other way. A bare path declares nothing, so it is refused by name.
"""

from collections.abc import Mapping
from dataclasses import dataclass

from .errors import AssistantError
from .figure_sources import (DECIMAL_MARKS, DELIMITERS, GROUP_MARKS, MAX_COLUMN_NAME, MAX_COLUMN_POSITION,
                             MAX_TEXT_COLUMNS, SourceLayout, layout_valid)
from .forbidden_tokens import MAX_SOURCE_FILES

_LAYOUT_KEYS = frozenset({"path", "delimiter", "decimal_mark", "group_mark", "header", "text_columns"})

# Figure sources are not available in this release: the strict reader in figure_sources replaces one that listed
# amounts in part, and it is not released yet. A configuration or gate policy that lists sources is refused whatever
# else it sets, and no released route reads one. Only code turns it on (the reader's own tests do); no setting,
# variable or option does.
SOURCES_AVAILABLE = False
# Where sources are available, they are read only beside this setting, `true`, and then only by a declared layout.
OPT_IN = "forbidden_token_sources_experimental"
EXPERIMENTAL_WARNING = ("Figure sources are opted in, and experimental. A source lists the amounts outside the "
                        "columns you declare as text, and is refused whole when any other cell with a digit is not "
                        "one amount in the declared layout. A figure inside a declared text column is not listed, so "
                        "list the figures you must never send in forbidden_token_file as well.")


def _pair(first: str, second: str, value: str) -> dict:
    return {"properties": {first: {"const": value}, second: {"const": value}}}


# One forbidden_token_sources entry, in the configuration and gate policy schemas: an object that declares the file's
# whole layout. `group_mark` is null where the whole part is written without groups. `text_columns` lists the columns
# that hold no figures, by position from 1 or, with `header` true, by the exact name in the first row. A mark has one
# role among the digits, and a comma that both separates columns and marks decimals can't be told apart, so neither
# is a layout. A bare path is in the schema only so that it is refused by its own name,
# forbidden_token_source_layout_required.
SOURCE_ENTRY_SCHEMA = {"oneOf": [
    {"type": "string", "minLength": 1, "maxLength": 4096},
    {"type": "object", "additionalProperties": False, "required": sorted(_LAYOUT_KEYS),
     "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "delimiter": {"enum": list(DELIMITERS)}, "decimal_mark": {"enum": list(DECIMAL_MARKS)},
                    "group_mark": {"enum": list(GROUP_MARKS)}, "header": {"type": "boolean"},
                    "text_columns": {"type": "array", "maxItems": MAX_TEXT_COLUMNS, "uniqueItems": True,
                                     "items": {"oneOf": [
                                         {"type": "integer", "minimum": 1, "maximum": MAX_COLUMN_POSITION},
                                         {"type": "string", "minLength": 1, "maxLength": MAX_COLUMN_NAME}]}}},
     "not": {"anyOf": [_pair("delimiter", "decimal_mark", ","),
                       _pair("decimal_mark", "group_mark", ","), _pair("decimal_mark", "group_mark", "."),
                       {"properties": {"header": {"const": False},
                                       "text_columns": {"contains": {"type": "string"}}}}]}},
]}


@dataclass(frozen=True)
class SourceFormat:
    """A figure source with its declared layout: it is read with these marks and text columns, and no other way."""

    path: str
    delimiter: str
    decimal_mark: str
    group_mark: str | None  # None: the whole part is written without groups
    header: bool
    text_columns: tuple  # positions from 1 and, with a header, exact names

    @property
    def layout(self) -> SourceLayout:
        return SourceLayout(self.delimiter, self.decimal_mark, self.group_mark, self.header, self.text_columns)


def source_format(item):
    """A layout object as a SourceFormat, so a loaded configuration holds no mutable entry; anything else as it is,
    for source_entries to judge."""
    if isinstance(item, Mapping) and set(item) == _LAYOUT_KEYS:
        columns = item["text_columns"]
        return SourceFormat(item["path"], item["delimiter"], item["decimal_mark"], item["group_mark"], item["header"],
                            tuple(columns) if isinstance(columns, (list, tuple)) else columns)
    return item


def check_opt_in(rules) -> None:
    """Refuse any figure sources these settings list: in this release always (see check_opted_in), and where
    sources are available unless they are opted in, each with a declared layout.

    Listed without `"forbidden_token_sources_experimental": true` they are refused by name, never ignored, so no one
    believes a source screens what it does not. Opted in, each declares its layout: no reader guesses one. Other
    damage is left to the schema and source_entries.
    """
    check_opted_in(rules)
    sources = rules.get("forbidden_token_sources") if isinstance(rules, Mapping) else None
    if sources and isinstance(sources, (list, tuple)) and any(isinstance(item, str) for item in sources):
        raise AssistantError("forbidden_token_source_layout_required")


def check_opted_in(rules) -> None:
    """The first half of check_opt_in, and the settings' first check. Figure sources are not available in this
    release: any `forbidden_token_sources` in these settings, whatever its value and whatever else is set, is refused
    as `forbidden_token_sources_experimental`. A configuration's rules hold it for any value but an empty list. Where
    sources are available, a list of them without `"forbidden_token_sources_experimental": true` is refused so."""
    if not isinstance(rules, Mapping) or "forbidden_token_sources" not in rules:
        return
    sources = rules["forbidden_token_sources"]
    if not SOURCES_AVAILABLE or sources and isinstance(sources, (list, tuple)) and rules.get(OPT_IN) is not True:
        raise AssistantError("forbidden_token_sources_experimental")


def source_entries(sources) -> tuple[tuple[str, SourceLayout | None], ...]:
    """(path, declared layout) of each forbidden_token_sources entry, or refused. A bare path has no layout: it is
    kept as None for the caller to refuse by its own name, and is never read.

    A path named twice is refused: two layouts of one file could list different figures.
    """
    if not isinstance(sources, (list, tuple)) or len(sources) > MAX_SOURCE_FILES:
        raise AssistantError("forbidden_token_source_invalid")
    entries = []
    for item in map(source_format, sources):
        layout = None
        if isinstance(item, SourceFormat):
            if not isinstance(item.text_columns, tuple) or not layout_valid(item.layout):
                raise AssistantError("forbidden_token_source_invalid")
            layout, item = item.layout, item.path
        if not isinstance(item, str) or not item or len(item) > 4096:
            raise AssistantError("forbidden_token_source_invalid")
        entries.append((item, layout))
    if len({path for path, _layout in entries}) != len(entries):
        raise AssistantError("forbidden_token_source_invalid")
    return tuple(entries)
