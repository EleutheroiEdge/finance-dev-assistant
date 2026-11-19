"""Reviewed placeholder occurrences read from a repository: a gate run's allowance, and the enrolment command.

See `occurrence_identity` for what an occurrence is and what an entry lets through.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .errors import AssistantError
from .occurrence_identity import (MAX_TEXT_CHARACTERS, OccurrenceAllowance, is_yaml_path, occurrence_for, text_digest,
                                  yaml_occurrences, yaml_state)
from .policy_ignores import ignored_paths
from .scope import read_entry, resolve
from .security import CREDENTIAL_KEY_PATTERN, FORMAT_PATTERNS, LABEL_PATTERNS, check_model_path, check_name

QUALIFICATION = ("Enrol only a value you have reviewed as a public synthetic fixture. Once let through it is "
                 "ordinary reviewed source, sent to the configured provider; a digest is not confidentiality.")


def _version(repo: Path, revision: str, path: str, config, cache: dict) -> tuple[str, str | None, Counter | None]:
    """One file version: ("read", text, digest counts), or a status naming why it could not be used."""
    key = (path, revision)
    if key not in cache:
        try:
            data, _mode = read_entry(repo, revision, path, config.file_byte_limit(path), config)
        except AssistantError:
            cache[key] = ("unreadable", None, None)
            return cache[key]
        if data is None:
            cache[key] = ("file_absent", None, None)
            return cache[key]
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            cache[key] = ("unreadable", None, None)
            return cache[key]
        found = yaml_occurrences(path, text)
        cache[key] = ("unsupported", None, None) if found is None else (
            "read", text, Counter(item.digest for item in found))
    return cache[key]


def _lapse(note: dict, **details) -> None:
    """Mark an entry as not applying, with safe metadata only."""
    note.update({"status": "lapsed", "code": "placeholder_occurrence_lapsed"}, **details)


def build_allowance(repo: Path, revisions: tuple[tuple[str, str], ...], entries: list[dict], config,
                    reviewable) -> OccurrenceAllowance:
    """Check every entry at each named revision. An entry is live only when its occurrence is present exactly
    once in every one of them. Only a path `reviewable` accepts is ever read: the caller applies the gate's name,
    privacy and committed ignore rules there, before any read."""
    cache: dict = {}
    live: dict[str, tuple[set, set]] = {}
    notes: dict[str, list[dict]] = {}
    _parser, unusable = yaml_state()
    for index, entry in enumerate(entries):
        path, wanted = entry["path"], entry["occurrence_sha256"]
        note: dict = {"entry": index}
        if unusable:
            _lapse(note, reason=unusable)  # yaml_unavailable or yaml_unsupported_version
        elif not reviewable(path):
            _lapse(note, reason="not_reviewed")  # never read
        else:
            states, texts = {}, set()
            for name, revision in revisions:
                state, text, counts = _version(repo, revision, path, config, cache)
                if state == "read":
                    count = counts.get(wanted, 0)
                    state = "present" if count == 1 else "absent" if count == 0 else "repeated"
                    texts.add(text_digest(text))
                states[name] = state
            if all(state == "present" for state in states.values()):
                note["status"] = "live"
                known_texts, digests = live.setdefault(path, (set(), set()))
                known_texts.update(texts)
                digests.add(wanted)
            else:
                _lapse(note)
            note["revisions"] = states
        notes.setdefault(path, []).append(note)
    return OccurrenceAllowance({path: (texts, digests) for path, (texts, digests) in live.items()}, notes)


def enroll(repo: Path, revision: str, path: str, line: int) -> dict:
    """The entry for the one credential-named YAML value on a line of a committed file.

    It prints the path, the commit, the line and the entry's digest: never the value, and no key or other source
    text. The path is screened as a name, and a path the commit's ignore rules exclude is never read.
    """
    commit = resolve(repo, revision)
    if not is_yaml_path(path):
        raise AssistantError("placeholder_occurrence_unsupported")
    check_model_path(path)
    check_name(path)
    if yaml_state()[0] is None:
        raise AssistantError("placeholder_occurrence_yaml_unavailable")
    if ignored_paths(repo, {commit}, [path]):
        raise AssistantError("gate_ignored_path")
    data, _mode = read_entry(repo, commit, path, MAX_TEXT_CHARACTERS)
    if data is None:
        raise AssistantError("placeholder_occurrence_not_found")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise AssistantError("non_text_blob") from exc
    occurrences = yaml_occurrences(path, text)
    if occurrences is None:
        raise AssistantError("placeholder_occurrence_unsupported")
    starts = [0] + [index + 1 for index, character in enumerate(text) if character == "\n"]
    if type(line) is not int or not 1 <= line <= len(starts):
        raise AssistantError("placeholder_occurrence_not_found")
    first = starts[line - 1]
    last = text.find("\n", first)
    last = len(text) if last < 0 else last
    if any(pattern.search(text, first, last) for pattern in FORMAT_PATTERNS):
        raise AssistantError("placeholder_occurrence_known_format")  # a known format is refused everywhere
    found = set()
    for pattern in (LABEL_PATTERNS[0], CREDENTIAL_KEY_PATTERN):
        for match in pattern.finditer(text):
            if first <= match.start() <= last:
                item = occurrence_for(occurrences, match)
                if item is None:
                    raise AssistantError("placeholder_occurrence_ambiguous")  # a match no supported value holds
                found.add(item)
    if not found:
        raise AssistantError("placeholder_occurrence_not_found")
    if len(found) > 1:
        raise AssistantError("placeholder_occurrence_ambiguous")
    item = found.pop()
    return {"path": path, "revision": commit, "line": line,
            "entry": {"path": path, "occurrence_sha256": item.digest},
            "qualification": QUALIFICATION}
