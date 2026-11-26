"""Helpers for the figure-source tests: a declared layout, a source on disk, and whether a snapshot refuses a text.

Every figure, file and name the tests write is synthetic.
"""

from finassist.errors import AssistantError
from finassist.figure_sources import SourceLayout
from finassist.forbidden_tokens import TokenSnapshot, load_token_snapshot, screen_source, screen_text


def layout(path: str, delimiter: str = ";", decimal_mark: str = ",", group_mark: str | None = ".",
           header: bool = True, text_columns=()) -> dict:
    """One forbidden_token_sources entry; by default a semicolon export with decimal commas and grouping points."""
    return {"path": path, "delimiter": delimiter, "decimal_mark": decimal_mark, "group_mark": group_mark,
            "header": header, "text_columns": list(text_columns)}


def as_layout(entry: dict) -> SourceLayout:
    return SourceLayout(entry["delimiter"], entry["decimal_mark"], entry["group_mark"], entry["header"],
                        tuple(entry["text_columns"]))


def write_source(tmp_path, content: str | bytes, name: str = "positions.csv") -> str:
    path = tmp_path / "exports" / name
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    return str(path)


def load(*entries, parsed=None, **rules) -> TokenSnapshot:
    """The snapshot of these sources, loaded as a configuration or a gate policy loads it."""
    return load_token_snapshot({"forbidden_token_sources": list(entries), **rules}, (), parsed)


def refused(text: str, snapshot: TokenSnapshot, path: str | None = None) -> bool:
    try:
        screen_source(text, path, snapshot) if path else screen_text(text, snapshot)
    except AssistantError as exc:
        assert exc.code == "forbidden_token_present", exc.code
        return True
    return False
