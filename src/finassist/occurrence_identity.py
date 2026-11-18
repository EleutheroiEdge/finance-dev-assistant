"""Exact structural identities for credential-named YAML values that a gate policy lists as reviewed placeholders.

A gate policy may list, under `placeholder_credential_occurrences`, values a person has reviewed as public
synthetic fixtures: each entry is a path and an occurrence digest. The digest binds the path, the value's
parsed location (mapping keys and sequence indexes from the document root), the exact source text of its whole
line, of its key and of the value, its quoting style and its resolved type. An entry applies to one gate run
only when that occurrence is present exactly once in the file at base, at the merge base and at head. Then the
credential label rules do not refuse that one value, and only in those exact versions of the file. Everything
else is screened as before: known formats, account numbers, URL passwords, project patterns, hidden characters
and model output.

Only a documented subset of YAML is read: block mappings and sequences, with plain or quoted values written on
one line together with their key. A key is bound by its resolved type and value, so `true:` and `"true":` are
different places. Only text, boolean and null keys are read: a numeric, date, merge or value key, or two keys
the resolver reads as the same key (`true` and `yes`, `null` and `~`), puts the file outside the subset.
A file with an anchor, an alias, an explicit tag or directive, a complex key, or more than one document is
outside it too, and no value in it is let through. A value inside a flow collection, or a block or multi-line
scalar, is never let through. Anything that does not parse, or is too large or too deep, lets nothing through.
PyYAML reads the events; nothing is constructed and no code runs. Only the reviewed PyYAML version, installed
with the `yaml` extra, is used: without it, or with another version, nothing is let through.

A digest is not confidentiality. A value let through is ordinary reviewed source: it is in the request sent to
the configured provider. Only values reviewed as public synthetic fixtures belong in such an entry.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

DOMAIN = "finledgerpoli/placeholder-occurrence/v1"
SUPPORTED_PYYAML = "6.0.3"  # the reviewed parser: the `yaml` extra pins it, and no other version is used
MAX_OCCURRENCE_ENTRIES = 64
MAX_TEXT_CHARACTERS = 1_000_000
MAX_DEPTH = 64
MAX_EVENTS = 200_000
YAML_SUFFIXES = (".yml", ".yaml")
_QUOTED_OR_PLAIN = {None, "", "'", '"'}


class _Unsupported(Exception):
    """The text is outside the supported subset."""


def load_yaml():
    """The PyYAML module, or None when it is not installed. Tests replace this to check the absent path."""
    try:
        import yaml
    except ImportError:
        return None
    return yaml


def yaml_state():
    """(module, None) for the reviewed PyYAML, or (None, reason): yaml_unavailable or yaml_unsupported_version."""
    module = load_yaml()
    if module is None:
        return None, "yaml_unavailable"
    if getattr(module, "__version__", None) != SUPPORTED_PYYAML:
        return None, "yaml_unsupported_version"
    return module, None


_BOOLEAN = {"yes": "true", "true": "true", "on": "true", "no": "false", "false": "false", "off": "false"}


def _key_identity(tag: str, value: str) -> tuple[str, str]:
    """A key's resolved type and canonical value. Only text, boolean and null keys are in the subset."""
    if tag == "tag:yaml.org,2002:str":
        return "str", value
    if tag == "tag:yaml.org,2002:bool" and value.lower() in _BOOLEAN:
        return "bool", _BOOLEAN[value.lower()]
    if tag == "tag:yaml.org,2002:null":
        return "null", "null"
    raise _Unsupported  # a number, date, merge or value key, whose identity this reader does not settle


def is_yaml_path(path: str | None) -> bool:
    return path is not None and path.lower().endswith(YAML_SUFFIXES)


@dataclass(frozen=True)
class Occurrence:
    """One supported mapping value: its digest, the spans of its key and value, and where it sits."""

    digest: str
    key_start: int
    key_end: int
    value_start: int
    value_end: int
    location: tuple


def occurrence_digest(path: str, location: tuple, line_source: str, key_source: str, key_style: str | None,
                      value_source: str, value_style: str | None, value_type: str) -> str:
    document = {"domain": DOMAIN, "path": path, "location": [list(step) for step in location],
                "line": line_source, "key": key_source, "key_style": key_style or "plain", "value": value_source,
                "value_style": value_style or "plain", "value_type": value_type}
    data = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(data.encode("utf-8", "surrogatepass")).hexdigest()


class _Frame:
    __slots__ = ("mapping", "flow", "index", "key", "keys", "location")

    def __init__(self, mapping: bool, flow: bool, location: tuple):
        self.mapping, self.flow, self.location = mapping, flow, location
        self.index, self.key, self.keys = 0, None, set()


def yaml_occurrences(path: str, text: str) -> tuple[Occurrence, ...] | None:
    """Every supported mapping value of a YAML file, or None when the file is outside the subset or the reviewed
    PyYAML is not installed."""
    yaml, _reason = yaml_state()
    if yaml is None or not isinstance(text, str) or len(text) > MAX_TEXT_CHARACTERS or "\0" in text:
        return None
    try:
        return _walk(yaml, path, text)
    except (_Unsupported, yaml.YAMLError, RecursionError, UnicodeError, ValueError, TypeError, IndexError):
        return None


def _walk(yaml, path: str, text: str) -> tuple[Occurrence, ...]:
    resolver = yaml.SafeLoader("")  # resolves a plain value's type; reads nothing else
    stack: list[_Frame] = []
    documents, found = 0, []
    for count, event in enumerate(yaml.parse(text, Loader=yaml.SafeLoader)):
        if count > MAX_EVENTS or isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise _Unsupported
        if isinstance(event, yaml.DocumentStartEvent):
            documents += 1
            if documents > 1 or event.tags or event.version:
                raise _Unsupported
            continue
        if not isinstance(event, (yaml.ScalarEvent, yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            if isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                if not stack or stack[-1].key is not None:
                    raise _Unsupported
                stack.pop()
            continue
        if event.tag is not None:  # any explicit tag, standard or custom
            raise _Unsupported
        parent = stack[-1] if stack else None
        if parent is not None and parent.mapping and parent.key is None:
            # A key: one single-line scalar of a supported type, unique in its mapping by what the resolver reads
            # it as. A merge key would bring in other values; its resolved type is outside the subset.
            if (not isinstance(event, yaml.ScalarEvent) or event.style not in _QUOTED_OR_PLAIN
                    or event.start_mark.line != event.end_mark.line):
                raise _Unsupported
            identity = _key_identity(resolver.resolve(yaml.ScalarNode, event.value, event.implicit), event.value)
            if identity in parent.keys:
                raise _Unsupported
            parent.keys.add(identity)
            parent.key = (identity, event.start_mark.index, event.end_mark.index, event.style,
                          event.start_mark.line)
            continue
        if parent is None:
            location = ()
        elif parent.mapping:
            location = (*parent.location, ("k", *parent.key[0]))  # ("k", type, canonical value)
        else:
            location = (*parent.location, ("i", parent.index))
            parent.index += 1
        key = parent.key if parent is not None and parent.mapping else None
        if parent is not None and parent.mapping:
            parent.key = None
        if isinstance(event, yaml.ScalarEvent):
            if (key is not None and not any(frame.flow for frame in stack) and event.style in _QUOTED_OR_PLAIN
                    and key[4] == event.start_mark.line == event.end_mark.line):
                # Key and value on one line. The whole line is bound too, so re-indenting it or editing a comment
                # after it lapses an entry: the identity is conservative before it is convenient.
                value_type = resolver.resolve(yaml.ScalarNode, event.value, event.implicit)
                _key_value, key_start, key_end, key_style, _line = key
                value_start, value_end = event.start_mark.index, event.end_mark.index
                line_end = text.find("\n", value_end)
                line_source = text[text.rfind("\n", 0, key_start) + 1:len(text) if line_end < 0 else line_end]
                digest = occurrence_digest(path, location, line_source.rstrip("\r"), text[key_start:key_end],
                                           key_style, text[value_start:value_end], event.style, value_type)
                found.append(Occurrence(digest, key_start, key_end, value_start, value_end, location))
            continue
        if len(stack) >= MAX_DEPTH:
            raise _Unsupported
        stack.append(_Frame(isinstance(event, yaml.MappingStartEvent), bool(event.flow_style), location))
    if stack or documents > 1:
        raise _Unsupported
    return tuple(found)


def occurrence_for(occurrences, match) -> Occurrence | None:
    """The supported value a label match stands on: its value starts the value, and its label is the value's key."""
    start, end, separator = match.start("value"), match.end("value"), match.start("sep")
    text = match.string
    for item in occurrences:
        if (item.value_start == start and end <= item.value_end and item.key_start <= match.start() < item.key_end
                and text[item.key_end:separator].strip(" \t") == "" and text[separator] == ":"):
            return item
    return None


def text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


class OccurrenceAllowance:
    """Which reviewed occurrences a gate run lets through, in which exact file versions, and why others lapsed."""

    def __init__(self, live: dict[str, tuple[frozenset, frozenset]], notes: dict[str, tuple[dict, ...]]):
        # path -> (digests of the exact file versions checked, live occurrence digests)
        self._live = {path: (frozenset(texts), frozenset(digests)) for path, (texts, digests) in live.items()}
        self._notes = {path: tuple(dict(note) for note in notes_) for path, notes_ in notes.items()}
        state = {path: [sorted(texts), sorted(digests)] for path, (texts, digests) in self._live.items()}
        self.key = text_digest(json.dumps(state, sort_keys=True, separators=(",", ":")))
        self._spans: dict[tuple[str, str], dict] = {}

    def permitted_spans(self, path: str | None, text: str) -> dict[int, Occurrence]:
        """Value start -> occurrence, for live occurrences in this exact file version only."""
        if path not in self._live:
            return {}
        texts, digests = self._live[path]
        identity = text_digest(text)
        if identity not in texts:
            return {}
        cached = self._spans.get((path, identity))
        if cached is None:
            occurrences = yaml_occurrences(path, text) or ()
            cached = {item.value_start: item for item in occurrences if item.digest in digests}
            self._spans[(path, identity)] = cached
        return cached

    @staticmethod
    def permits(spans: dict[int, Occurrence], match) -> bool:
        """True when this label match stands on one of the permitted occurrences, as its key and value."""
        item = spans.get(match.start("value"))
        return item is not None and occurrence_for((item,), match) is not None

    def explain(self, path: str | None) -> list[dict] | None:
        """Safe metadata for each entry naming this path: entry index and per-revision status. Never a value."""
        notes = self._notes.get(path)
        return [dict(note) for note in notes] if notes else None


class DeferredAllowance:
    """An allowance that reads nothing until the screen asks about one of its listed files.

    The gate puts it in effect before its guards run. A listed file is screened only after every name, file count
    and rule-change guard has passed, so a guard that stops the run first leaves every listed file unread. The key
    for the screening cache is fixed from what defines the allowance, so asking for it reads nothing either.
    """

    permits = staticmethod(OccurrenceAllowance.permits)

    def __init__(self, paths, key: str, build):
        self._paths, self.key, self._build, self._built = frozenset(paths), key, build, None

    def _allowance(self) -> OccurrenceAllowance:
        if self._built is None:
            self._built = self._build()
        return self._built

    def permitted_spans(self, path: str | None, text: str) -> dict[int, Occurrence]:
        return self._allowance().permitted_spans(path, text) if path in self._paths else {}

    def explain(self, path: str | None) -> list[dict] | None:
        return self._allowance().explain(path) if path in self._paths else None


_ACTIVE: ContextVar[OccurrenceAllowance | DeferredAllowance | None] = ContextVar("placeholder_occurrences",
                                                                                default=None)


def active_allowance() -> OccurrenceAllowance | None:
    return _ACTIVE.get()


def occurrence_notes(path: str | None) -> dict:
    """For a local report row: the active allowance's notes on this path, or nothing."""
    allowance = _ACTIVE.get()
    notes = allowance.explain(path) if allowance is not None else None
    return {"placeholder_occurrences": notes} if notes else {}


@contextmanager
def allowance_in_effect(allowance: OccurrenceAllowance | None):
    """Let the gate's screen consult `allowance` while the block runs. None leaves today's rules in place."""
    token = _ACTIVE.set(allowance)
    try:
        yield allowance
    finally:
        _ACTIVE.reset(token)
