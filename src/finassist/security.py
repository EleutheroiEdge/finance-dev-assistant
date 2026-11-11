"""Fail-closed input checks. These supplement explicit scope and OS isolation."""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from copy import deepcopy
from fnmatch import fnmatchcase
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import stat
import sys
from typing import NamedTuple
import unicodedata

from .code_text import (code_text, in_block_scalar, is_expansion, is_shell, is_yaml, looks_like_nested_key,
                        yaml_block_scalars)
from .errors import AssistantError
from .platform_support import canonical_system_path
from .path_alias_data import ASCII_CONFUSABLES, DEFAULT_IGNORABLE_RANGES
from .python_annotations import credential_screening_view
from .python_source import is_python_path, python_screen

DENIED_PARTS = {
    ".finassist",
    ".git",
    ".ssh",
    ".aws",
    ".azure",
    ".env",
    ".venv",
    "node_modules",
    "credentials",
    "secrets",
    "portfolios",
    "holdings",
    "memory",
    "sessions",
    "uploads",
}
DENIED_SUFFIXES = {
    ".csv",
    ".tsv",
    ".parquet",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".xlsx",
    ".xls",
    ".pdf",
    ".png",
    ".jpg",
    ".zip",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
}
# Where tools keep a signed-in session, a registry password or a private key, by the names they
# use in a home directory. A repository that tracks one holds a credential whatever its text
# looks like, so the name alone makes the file private. An entry is a run of path components
# and matches anywhere in a path, in any case. No setting admits one. The list covers common
# tools, never every tool: docs/configuration.md repeats it, and a test keeps the two the same.
CREDENTIAL_STORES = (
    # Directories: everything under them.
    (".bluemix",), (".doppler",), (".gnupg",), (".kaggle",), (".kube",), (".ngrok2",), (".oci",),
    (".password-store",), (".pki",), (".snowsql",), (".terraform.d",),
    (".config", "configstore"), (".config", "doctl"), (".config", "gcloud"), (".config", "gh"),
    (".config", "github-copilot"), (".config", "glab-cli"), (".config", "hcloud"),
    (".config", "helm", "registry"), (".config", "netlify"), (".config", "ngrok"), (".config", "op"),
    (".config", "rclone"), (".config", "sops"), (".config", "stripe"), (".local", "share", "keyrings"),
    (".subversion", "auth"), (".wrangler", "config"),
    # One file inside a directory that may hold ordinary settings too.
    (".cargo", "credentials"), (".cargo", "credentials.toml"), (".config", "git", "credentials"),
    (".config", "hub"), (".config", "linode-cli"), (".config", "pypoetry", "auth.toml"),
    (".docker", "config.json"), (".expo", "state.json"),
    (".fly", "config.yml"), (".gem", "credentials"), (".gradle", "gradle.properties"),
    (".m2", "settings-security.xml"), (".m2", "settings.xml"),
    # Files, wherever they sit.
    (".boto",), (".databrickscfg",), (".dockercfg",), (".git-credentials",), (".htpasswd",), (".mylogin.cnf",),
    (".netrc",), (".pgpass",), (".pypirc",), (".s3cfg",), (".terraformrc",), (".vault-token",), ("_netrc",),
    ("id_dsa",), ("id_ecdsa",), ("id_ed25519",), ("id_rsa",), ("pgpass.conf",),
)
TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".txt",
    ".rst",
    ".toml",
    ".json",
    ".yaml",
    ".yml",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".html",
    ".css",
    ".sql",
    ".sh",
    ".rs",
    ".go",
    ".java",
    ".lock",
    ".in",
    ".dockerfile",
}
PUBLIC_ASSETS = {".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".ico"}
# Assignment patterns start only at a whole label-token boundary. A word
# boundary would retry the greedy prefix after every hyphen, causing quadratic
# scans. Keep unbounded prefixes so long labels cannot hide sensitive suffixes.
CREDENTIAL_KEY_PATTERN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*(?:secret|private|signing|encryption|access|client|master|auth|api)[_-]?(?:access[_-]?)?key\b[\"']?\s*(?P<sep>[=:])\s*"
    r"(?P<value>[\"'][^\"'\n]{12,}[\"']|(?![A-Za-z_][A-Za-z0-9_.]*\s*\()(?!(?-i:[A-Z][A-Za-z_]*)(?![A-Za-z0-9_./+=:@-]))(?!(?:[A-Za-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_.]))[A-Za-z0-9][A-Za-z0-9_./+=:@-]{11,})"
)

# Known secret formats and an identifier format; these read text, not syntax.
FORMAT_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
)
# Label rules for text. In parseable Python, code is checked by the AST instead
# and these rules read only comment and string text.
LABEL_PATTERNS = (
    re.compile(
        r"(?i)(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*(?:api[_-]?key|password|secret|access[_-]?token|gh[_-]?token|github[_-](?:enterprise[_-])?token)\b[\"']?\s*(?P<sep>[=:])\s*"
        r"(?P<value>[\"'][^\"'\n]{12,}[\"']|[A-Za-z0-9][A-Za-z0-9_./+=:@-]{11,})"
    ),
    CREDENTIAL_KEY_PATTERN,
    re.compile(
        r"(?i)(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*(?:account[_ -]?(?:number|id)|routing[_ -]?number)[\"']?\s*[=:]\s*[\"']?\d{6,}"
    ),
)
SECRET_PATTERNS = (*FORMAT_PATTERNS, *LABEL_PATTERNS)
# The name a refusal gives its rule in local output. Patterns for one kind of thing share a name.
_RULES = dict(zip(SECRET_PATTERNS, (
    "private_key_block", "github_token", "github_token", "aws_access_key_id", "sk_prefixed_key",
    "nine_digit_identifier", "credential_label", "credential_label", "account_label"), strict=True))
_REFERENCE_PATTERNS = tuple(pattern for pattern in LABEL_PATTERNS if "value" in pattern.groupindex)
MIN_SECRET_LENGTH = 12  # the shortest value a label rule reads as a credential
MAX_PLACEHOLDER_PATHS = 64  # entries a configuration may list as holding placeholder credentials
PLACEHOLDER_PATTERN = re.compile(r"[A-Za-z0-9_./*-]{1,512}")  # what such an entry may hold when it has a star
PLACEHOLDER_STARS = re.compile(r"\*+")
_FILE_SUFFIX = re.compile(r"\.[A-Za-z0-9*]+\Z")
_NAMED = re.compile(r"[A-Za-z0-9]")
_NAMED_LINES = 20  # line numbers a refusal names in local output


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned_image(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:[A-Za-z0-9][A-Za-z0-9._/:+-]*@)?sha256:[0-9a-f]{64}", value
    ):
        raise AssistantError("pinned_runner_image_required")
    return value


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or ":" in value
        or "\0" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise AssistantError("unsafe_path")
    return str(path)


def check_path(
    value: str,
    *,
    source_only: bool = True,
    metadata_only: bool = False,
    denied_parts=None,
    text_suffixes=None,
    fixture_roots: tuple[str, ...] = (),
) -> str:
    name = safe_relative(value)
    check_text(name)
    parts = PurePosixPath(name).parts
    fixture = is_text_fixture(name, fixture_roots)
    if fixture:
        check_fixture_private(name)
    last = _component_aliases(parts[-1])
    if _reserved_match(last, {"auth.json", "user.md", "memory.md", "session.md"}):
        raise AssistantError("private_profile_path")
    denied = set(DENIED_PARTS if denied_parts is None else denied_parts)
    if fixture:
        denied = set(denied) | DENIED_PARTS
    suffixes = TEXT_SUFFIXES if text_suffixes is None else text_suffixes
    reserved = frozenset(denied | {".git", ".finassist"})
    environment = _reserved_aliases(frozenset({".env"}))
    aliases = []  # Each component's spellings, worked out once and checked in path order.
    for index, part in enumerate(parts):
        names = last if index == len(parts) - 1 else _component_aliases(part)
        if _reserved_match(names, reserved) or any(
                _one_dot(alias).startswith(prefix) for alias in names for prefix in environment):
            raise AssistantError("private_path")
        aliases.append(names)
    if _in_credential_store(aliases):
        raise AssistantError("private_path")
    suffix = PurePosixPath(name).suffix.lower()
    if suffix in DENIED_SUFFIXES and not fixture and not (metadata_only and suffix in PUBLIC_ASSETS):
        raise AssistantError("private_or_binary_path")
    if (
        source_only
        and suffix not in suffixes
        and not fixture
        and parts[-1]
        not in {"LICENSE", "Dockerfile", "Makefile", ".gitignore", ".dockerignore", ".gitattributes"}
    ):
        raise AssistantError("unsupported_file_type")
    return name


_PRIVATE = {"data", "private", "client", "clients", "household", "households",
            "client-config", "client_config", "household-config", "household_config"}


TEXT_FIXTURE_SUFFIXES = frozenset({".csv", ".tsv", ".yaml", ".yml"})


def is_text_fixture(path: str, roots: tuple[str, ...]) -> bool:
    return PurePosixPath(path).suffix.lower() in TEXT_FIXTURE_SUFFIXES and any(
        path.startswith(root) if root.endswith("/") else path == root for root in roots
    )


def _reserved_component(part: str) -> str:
    # Refuse hidden spelling changes; never strip them into a different Git path.
    normalized = unicodedata.normalize("NFKC", part)
    for char in part + normalized:
        code = ord(char)
        if (unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}
                or code in {0x2800, 0x13441, 0x13442, 0x16FE4, 0x1BC9D}
                or any(start <= code <= end for start, end in DEFAULT_IGNORABLE_RANGES)):
            raise AssistantError("unsafe_path")
    return normalized.rstrip(" .").casefold()


def _component_aliases(part: str) -> set[str]:
    # Compare both case orders: e.g. Greek capital Nu and Cyrillic capital I
    # have different confusable mappings after folding. ASCII mappings (m/rn,
    # I/l, etc.) must also be applied to the reserved names being compared.
    folded = _reserved_component(part)
    normalized = unicodedata.normalize("NFKC", part).rstrip(" .")
    return {folded, *(
        unicodedata.normalize("NFD", value).translate(ASCII_CONFUSABLES).casefold().rstrip(" .")
        for value in (normalized, folded)
    )}


@lru_cache(maxsize=128)
def _reserved_aliases(reserved: frozenset[str]) -> frozenset[str]:
    # Cache only policy/reserved labels, never candidate paths or source text.
    return frozenset(alias for value in reserved for alias in _component_aliases(value))


@lru_cache(maxsize=128)
def _hidden_aliases(reserved: frozenset[str]) -> frozenset[str]:
    return _reserved_aliases(frozenset(name.lstrip(".") for name in reserved))


def _one_dot(alias: str) -> str:
    """A hidden spelling with its leading dots read as one: `..env.local` is `.env.local`."""
    return "." + alias.lstrip(".") if alias.startswith(".") else alias


def _reserved_match(aliases: set[str], reserved) -> bool:
    """Whether a component, given by its spellings, is one of the reserved names.

    A hidden spelling is the same name: `.secrets` is `secrets`, however many dots lead it.
    """
    names = frozenset(reserved)
    if aliases & _reserved_aliases(names):
        return True
    hidden = _hidden_aliases(names)
    return any(alias.startswith(".") and alias.lstrip(".") in hidden for alias in aliases)


def _matches_reserved(part: str, reserved) -> bool:
    return _reserved_match(_component_aliases(part), reserved)


@lru_cache(maxsize=1)
def _credential_stores() -> dict[str, tuple[tuple[frozenset[str], ...], ...]]:
    """Each store by every alias of its first component, with the aliases of the components after it."""
    index: dict[str, list] = {}
    for store in CREDENTIAL_STORES:
        rest = tuple(frozenset(_component_aliases(name)) for name in store[1:])
        for alias in _component_aliases(store[0]):
            index.setdefault(alias, []).append(rest)
    return {alias: tuple(rests) for alias, rests in index.items()}


def _in_credential_store(aliases: list[set[str]]) -> bool:
    """Whether a run of components, each given by its spellings, is a credential store."""
    stores = _credential_stores()
    for start, names in enumerate(aliases):
        for alias in names:
            for rest in stores.get(alias, ()):
                if len(rest) < len(aliases) - start and all(
                        aliases[start + 1 + offset] & wanted for offset, wanted in enumerate(rest)):
                    return True
    return False


def check_fixture_private(path: str) -> None:
    parts = PurePosixPath(path).parts
    if any(_matches_reserved(part, {"data"}) for part in parts):
        raise AssistantError("fixture_root_contains_data")
    if any(_matches_reserved(part, {"tests", "fixtures"})
           and part not in {"tests", "fixtures"} for part in parts):
        raise AssistantError("fixture_root_invalid")
    _check_model_private(path)


def _check_model_private(path: str) -> None:
    if len(path) > 512 or any(_matches_reserved(part, _PRIVATE) for part in PurePosixPath(path).parts):
        raise AssistantError("gate_private_path")
    names = _component_aliases(PurePosixPath(path).name)
    if _reserved_match(names, {"client.json", "clients.json", "household.json", "households.json",
                               "credentials.json", "credential.json", "secrets.json"}) or any(
        re.search(r"(?:household|client)[_-]?(?:config|settings|profile)", name) for name in names
    ):
        raise AssistantError("gate_private_path")


def check_model_path(path: str, *, fixture_roots: tuple[str, ...] = (), source_only: bool = True) -> str:
    """Mandatory model context path screening, including policy-owned profiles."""
    if is_text_fixture(path, fixture_roots):
        check_fixture_private(path)
    check_path(path, fixture_roots=fixture_roots, source_only=source_only)
    _check_model_private(path)
    return path



def check_private_name(path: str) -> None:
    """The gate's private directories and file names, for any caller that needs the same rule."""
    _check_model_private(path)


def local_name(name, extra_patterns: tuple[str, ...] = ()) -> str:
    """A repo-relative name for local output only, or [redacted].

    A name is redacted when it fails screening itself, or when it has a control or
    format character (such as a right-to-left override) that can make it display as
    a different name.
    """
    try:
        if not isinstance(name, str) or not name or len(name) > 512:
            raise AssistantError("unsafe_path")
        if any(unicodedata.category(character) in {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"} for character in name):
            raise AssistantError("unsafe_path")
        safe_relative(name.removesuffix("/"))
        check_text(name, extra_patterns=extra_patterns)
    except AssistantError:
        return "[redacted]"
    return name


def placeholder_pattern_names_something(pattern: str) -> bool:
    """Whether a pattern is narrower than a kind of file.

    It has to name three letters or digits besides its file suffix, and to end in a name or a
    star. So "*.py" and "*/*.yaml" are refused, which would list every file of a language, and
    "*.test.ts", "*_test.go" and "*/fixtures/*" are not. A pattern that ends in a slash fits no
    path.
    """
    return not pattern.endswith("/") and len(_NAMED.findall(_FILE_SUFFIX.sub("", pattern))) >= 3


def holds_placeholders(path: str | None, entries) -> bool:
    """True when the configuration says the credential-named values in this file are placeholders.

    An entry is a directory prefix ending in a slash, an exact path, or a pattern in which a star
    stands for any characters, slashes included.
    """
    if path is None:
        return False
    return any(fnmatchcase(path, entry) if "*" in entry else path.startswith(entry) if entry.endswith("/")
               else path == entry for entry in entries)


def check_text(text: str, *, extra_patterns: tuple[str, ...] = (), source_path: str | None = None,
               placeholders: tuple[str, ...] = ()) -> None:
    """Refuse credentials and listed patterns in text.

    File content read with its path is also asked what its own syntax says: a credential-named
    field given an expression in code, or one variable expansion in quotes, names a value kept
    elsewhere and is not refused. Anything read without a path keeps the strict text rules.

    Under a path listed in `placeholders` the credential label rules are not applied: the
    operator has said that the credential-named values there are made up. Known formats, account
    numbers and the project's own patterns are refused there as everywhere.
    """
    labels = not holds_placeholders(source_path, placeholders)
    if is_python_path(source_path) and "\0" not in text:
        screen = python_screen(text)
        if screen is not None:
            _screen_python(text, screen, extra_patterns, labels)
            return
    # Python that does not tokenize and parse is text, and so is every language code_text does not read.
    syntax = _FileSyntax(text, source_path) if source_path is not None else None
    _screen_text(text, credential_screening_view(text, source_path), extra_patterns, syntax, credential_labels=labels)


def check_context_document(document: dict, *, extra_patterns: tuple[str, ...] = (), records_key="files",
                           placeholders: tuple[str, ...] = ()) -> None:
    """Screen each record with its path, then the remaining typed envelope."""
    envelope = deepcopy(document)
    for item in envelope[records_key]:
        for side in ("before", "after"):
            if item[side] is not None:
                check_text(item[side], extra_patterns=extra_patterns, source_path=item["path"], placeholders=placeholders)
                # Already screened with its path; a JSON copy must not undo
                # the Python-aware decision with text rules.
                item[side] = ""
    envelope_text = canonical(envelope).decode()
    _screen_text(envelope_text, envelope_text, extra_patterns)
    # The model receives the complete serialized packet, so known formats and
    # custom patterns also read it intact, JSON escapes included. Label rules stay
    # path-aware above.
    intact = canonical(document).decode()
    if any(pattern.search(intact) for pattern in FORMAT_PATTERNS):
        raise AssistantError("sensitive_content")
    _screen_extra(intact, extra_patterns)


def check_output_document(
    document: dict, source_files: list[dict], *, extra_patterns: tuple[str, ...] = (), diff: bool = False,
    placeholders: tuple[str, ...] = (), supplied: tuple[str, ...] = ("before", "after")
) -> None:
    """Permit only exact credential-label quotes from screened source.

    Two kinds of quote are permitted. One is an annotation: a credential-named
    field with its type. The other is a reference: a label rule's match in
    screened source whose value is an expression or one expansion, with nothing
    after it on its line that could give the label another value. From a file
    under `placeholders`, where the label rules are not applied, every label
    match is such a quote, a quoted placeholder included.

    `supplied` names the sides that the model was sent. The other side is what
    its own patch leaves: that is screened as source, and in a file under
    `placeholders` it lends no quote, because no label rule has read it.

    A match includes its label, separator and complete candidate value; a word
    merely present elsewhere in source confers no output exception. Paths and
    source must come from the caller's validated, hash-bound request/post-images.
    Other secret patterns and custom patterns always inspect original output.
    """
    allowed: dict[str, set[str]] = {}
    references: dict[str, set[str]] = {}
    for item in source_files:
        for side in ("before", "after"):
            text = item.get(side)
            if text is None:
                continue
            check_text(text, source_path=item["path"], extra_patterns=extra_patterns, placeholders=placeholders)
            listed = holds_placeholders(item["path"], placeholders)
            # What the model's own patch wrote into a listed file was never read by a label rule,
            # so it lends nothing to repeat: neither a placeholder nor a reference.
            if side in supplied or not listed:
                for quote, rests in _reference_quotes(text, item["path"], every=listed).items():
                    references.setdefault(quote, set()).update(rests)
            view = credential_screening_view(text, item["path"])
            for match in CREDENTIAL_KEY_PATTERN.finditer(text):
                separator = text.find(":", match.start(), match.end())
                if separator < 0 or view[separator] != " ":
                    continue
                # The source view retains positions and blanks the complete
                # annotation. Keep its span, including unions/parentheses,
                # without extending into an assigned value or following token.
                end = separator
                while end < len(text) and view[end].isspace():
                    end += 1
                quote = text[match.start():end].rstrip()
                allowed.setdefault(match.group(), set()).add(quote)

    def screened(value):
        """The value with permitted references blanked, and the same with permitted annotations blanked too."""
        if isinstance(value, str):
            masked = _mask_references(value, references, diff)
            chars = list(masked)
            for match in CREDENTIAL_KEY_PATTERN.finditer(value):
                quote, start = match.group(), match.start()
                # A removed unified-diff line has one leading '-' that the
                # label regex includes. Only the validated patch caller uses
                # this context; arbitrary label prefixes stay literal data.
                if diff and (start == 0 or value[start - 1] == "\n") and quote.startswith("-"):
                    quote, start = quote[1:], start + 1
                annotations = allowed.get(quote)
                if not annotations:
                    continue
                full_ends = [start + len(full) for full in annotations if value.startswith(full, start)]
                end = max(full_ends, default=match.end())
                # A shorter label: Type quote can end here, but an unrecorded
                # union/subscript continuation is not an exact source quote.
                if value[end:].lstrip().startswith(("|", "[")) or (
                    end < len(value) and (value[end].isalnum() or value[end] in "_./+@:-")
                ):
                    continue
                separator = value.index(":", start, end)
                # Retain the label so any following '= value' still meets the
                # assignment rules. Whitespace replacement preserves offsets.
                for index in range(separator, end):
                    if chars[index] not in "\r\n":
                        chars[index] = " "
            view = "".join(chars)
            # JSON escaping can otherwise hide quoted secret values from a
            # regex. Screen original string values as well as the envelope.
            _screen_text(value, view, extra_patterns, label_text=masked)
            # A syntactically valid typed assignment in an output string must
            # not conceal a new value. The first check above retains strict
            # output screening: parsing alone never authorizes an annotation.
            _screen_text(value, credential_screening_view(view, "output.py"), extra_patterns, label_text=masked)
            return masked, view
        if isinstance(value, list):
            pairs = [screened(item) for item in value]
            return [pair[0] for pair in pairs], [pair[1] for pair in pairs]
        if isinstance(value, dict):
            pairs = {key: screened(item) for key, item in value.items()}
            return {key: pair[0] for key, pair in pairs.items()}, {key: pair[1] for key, pair in pairs.items()}
        return value, value

    masked, view = screened(document)
    # Known formats and custom patterns read the intact document; the label rules read it with
    # the permitted quotes blanked.
    _screen_text(canonical(document).decode(), canonical(view).decode(), extra_patterns,
                 label_text=canonical(masked).decode())


class _FileSyntax:
    """What a file's own syntax says about a label match. Only for file content read with its path."""

    _UNREAD = object()

    def __init__(self, text: str, path: str | None):
        self._text, self._path, self._code = text, path, self._UNREAD
        self._scalars = None  # the block scalars of a YAML file, read when first needed

    def excuses(self, match: re.Match) -> bool:
        """True when the matched value names a value kept elsewhere instead of holding one."""
        value = match.group("value")
        if value[0] in "\"'":
            return is_expansion(value[1:-1], in_shell=value[0] == '"' and is_shell(self._path))
        if value[0].isdigit():
            return False  # A number is a literal in every language.
        if is_yaml(self._path):
            if not looks_like_nested_key(self._text, match.start("sep"), match.start("value"), match.end("value")):
                return False
            if self._scalars is None:
                self._scalars = yaml_block_scalars(self._text)
            return not in_block_scalar(self._scalars, match.start("sep"))
        if self._code is self._UNREAD:
            self._code = code_text(self._text, self._path)
        code = self._code
        # In a language where a string needs quotes, an unquoted value in code is an expression.
        # It is still refused when the expression holds a literal the field would receive.
        return (code is not None and code.in_code(match.start("sep")) and code.in_code(match.start("value"))
                and code.written_as_code(match.start()) and not code.odd_slashes_before(match.start())
                and code.literal_assigned(match.start("value"), MIN_SECRET_LENGTH) is False)


# Text inside parsed Python: only a quoted expansion is a reference there.
_TEXT_IN_PYTHON = _FileSyntax("", None)


_REST_LIMIT = 200  # characters of its line kept after a reference


def _reference_quotes(text: str, path: str, *, every: bool = False) -> dict[str, set[str]]:
    """Every label match in screened source whose value is a reference, as exact text.

    The text has passed the screen. So an unquoted value in it is an expression its syntax
    excused, and a quoted one that is a single expansion names a variable. With each goes what
    follows it on its line, with and without a closing comma or semicolon: the rest of its
    expression, such as the brackets of a call. Output may repeat that too. `every` is for a
    file the operator listed as holding placeholders: there each match is kept, whatever its
    value.
    """
    quotes: dict[str, set[str]] = {}
    for pattern in _REFERENCE_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group("value")
            if (every or value[0] not in "\"'"
                    or is_expansion(value[1:-1], in_shell=value[0] == '"' and is_shell(path))):
                line_end = text.find("\n", match.end())
                rest = text[match.end():len(text) if line_end < 0 else line_end].rstrip()
                rests = quotes.setdefault(match.group(), set())
                rests.update(part for part in (rest, rest.rstrip(",;").rstrip()) if part and len(part) <= _REST_LIMIT)
    return quotes


# In prose, after the code span that held a quote, the reply is read on to the end of its clause:
# the first comma or semicolon outside the brackets opened on the way, the first closing bracket
# that nothing opened, or the end of the reply. Up to there only plain prose may stand: nothing
# that can begin a string, a comment or type arguments, and no long number. So no literal can
# follow the quote, whatever sign or word stands before it, and nothing can hide where the clause
# ends. Two things are plain though they hold a backtick: a code span too short to be a credential,
# with no escape, quote mark, dollar or brace in it, and a span that holds another quote.
# A string begins with a quote mark or a backtick, or in SQL with a dollar tag, spelled as the reader
# of source spells it. A number is counted with the point it may begin with, as it is in source.
_CLAUSE = re.compile(
    r"(?P<plain>`[^`\\\"'${}\n]{0," + str(MIN_SECRET_LENGTH - 1) + r"}`)"
    r"|(?P<end>[,;])|(?P<open>[(\[{])|(?P<close>[)\]}])"
    r"|(?P<refused>[\"'`/\\#<]|--|\$(?:[^\W\d]\w*)?\$"
    r"|(?<![A-Za-z0-9_$.])(?:\.[0-9][0-9A-Za-z_.]{" + str(MIN_SECRET_LENGTH - 2) + r",}"
    r"|[0-9][0-9A-Za-z_.]{" + str(MIN_SECRET_LENGTH - 1) + r",}))")
_CLAUSE_REACH = 4000  # characters read after a span for the end of its clause
_CLAUSE_PARTS = 400  # and the brackets and short spans read in them
_PATCH_MARK = re.compile(r"(?<=\n)[+\- ]")  # the mark that begins each further line of a patch
_LINE_BREAK = re.compile(r"\n")
_VALUE_MARK = re.compile(r"[\"'=]")
_BLANK = re.compile(r"[ \t\r]*")
# A quote that stops inside a bracket or a string it opened is not a whole expression.
_WHOLE_STRING = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\\n]|\\.)*`")
# A quote that ends with one of these is a whole operand. One that ends with an operator is not
# over, whatever follows it.
_QUOTE_END = re.compile(r"[A-Za-z0-9_$)\]}\"'!,;]")
# In code, the line after a quote that ends its line has to begin something new: a name that is no
# operator, a closing bracket, a quoted key, or the end of a fenced block. Anything else may carry
# the expression on, whatever the operator. The words are those the reader of source knows, and
# the ones Python has; a test holds the two lists together.
_BEGINS_NEW = re.compile(
    r"```|[)\]}\"']|(?!(?:in|instanceof|as|satisfies|is|else|extends|or|and|not)\b)[A-Za-z_$@]")
_COMMENT_LINE = re.compile(r"//|#|--")
_PATCH_NOTE = "\\ No newline at end of file"


class _Reply(NamedTuple):
    """One string of model output as the rules for a quote read it, worked out once for all its quotes."""

    value: str  # as written
    text: str  # with every quote of a reference blanked
    prose: str  # the same, and in a patch with the mark that begins each line blanked too
    starts: list[int]  # where each line starts
    new_after: list[bool]  # for each line: whether the next line that holds code begins something new
    marks: list[int]  # where a quote mark or an equals sign stands
    spans: dict[int, int]  # for each code span that holds a quote of a reference: where it opens, and where it closes
    diff: bool


def _read_reply(value: str, text: str, diff: bool, quotes: list) -> _Reply:
    """Read one string of output once, so that each quote in it is then judged where it stands.

    A reply can be made of quotes. Reading the rest of it again for each would take time that
    grows with the square of its length.
    """
    starts = [0, *(found.end() for found in _LINE_BREAK.finditer(text))]
    new_after, new = [True] * len(starts), True  # After the last line nothing follows.
    for index in range(len(starts) - 1, -1, -1):
        new_after[index] = new
        line = text[starts[index]:starts[index + 1] - 1 if index + 1 < len(starts) else len(text)]
        if diff and line[:1] in ("+", "-", " "):
            line = line[1:]  # the mark of a patch line
        line = line.strip(" \t\r")
        if line and _COMMENT_LINE.match(line) is None and not (diff and line == _PATCH_NOTE):
            new = _BEGINS_NEW.match(line) is not None
    prose = _PATCH_MARK.sub(" ", text) if diff else text  # the mark of a patch line is not an operator
    marks = [found.start() for found in _VALUE_MARK.finditer(text)]
    spans = {}
    for start, end, rests in quotes:
        if value[start - 1:start] == "`":
            for rest in ("", *rests):
                closes = _BLANK.match(value, end + len(rest)).end() if value.startswith(rest, end) else -1
                if closes >= 0 and value[closes:closes + 1] == "`":
                    spans[start - 1] = closes
    return _Reply(value, text, prose, starts, new_after, marks, spans, diff)


def _ends_there(reply: _Reply, start: int, end: int, rests: set[str]) -> bool:
    """Whether the expression that a permitted quote repeats is over where the quote ends.

    It may first go on exactly as it does in the source: `rests` holds what follows this
    reference on its line there.
    """
    value = reply.value
    return any(_QUOTE_END.fullmatch(value[stop - 1:stop]) and not _leaves_open(value[start:stop])
               and _is_over(reply, start, stop)
               for stop in (end + len(rest) for rest in ("", *rests) if value.startswith(rest, end)))


def _plain_to_the_end_of_its_clause(reply: _Reply, position: int) -> bool:
    """Whether only plain prose stands from `position` to the end of the clause that begins there.

    The clause ends at a comma or a semicolon outside the brackets opened on the way, at a closing
    bracket that nothing opened, and with the reply. Brackets can be counted because nothing that
    could hold one as text is let through: see `_CLAUSE`. A code span that holds another quote of
    a reference is stepped over: if that quote is not permitted either, the label rules refuse
    it. Short code spans with only space between them are one string, as strings that stand side
    by side are in source, and count together. No end in reach is unclear, and unclear is refused.
    """
    prose, depth = reply.prose, 0
    limit = min(len(prose), position + _CLAUSE_REACH)
    together, last = 0, -1  # the length of the short spans that stand side by side, and where the last one ended
    for _part in range(_CLAUSE_PARTS):
        part = _CLAUSE.search(prose, position, limit)
        if part is None:
            return limit == len(prose)  # The reply ends here, and nothing was joined to the quote.
        kind, position = part.lastgroup, part.end()
        if kind == "plain":
            beside = last >= 0 and not prose[last:part.start()].strip()
            together, last = (together if beside else 0) + len(part.group()) - 2, part.end()
            if together >= MIN_SECRET_LENGTH:
                return False
        if kind == "end" and not depth:
            return True
        if kind == "open":
            depth += 1
        elif kind == "close":
            if not depth:
                return True
            depth -= 1
        elif kind == "refused":
            closes = reply.spans.get(part.start())
            if closes is None:
                return False
            position = closes + 1
    return False


def _leaves_open(quote: str) -> bool:
    """Whether a quote stops inside a bracket or a string that it opened.

    Then its expression goes on over the next lines, as the arguments of a call do, and what
    stands there is not looked at here.
    """
    code = _WHOLE_STRING.sub("", quote)
    depth = 0
    for character in code:
        if character in "([{":
            depth += 1
        elif character in ")]}" and depth:
            depth -= 1
    return depth > 0 or any(mark in code for mark in "\"'`")


def _is_over(reply: _Reply, start: int, end: int) -> bool:
    """Whether nothing from `end` on can give the label that starts at `start` another value.

    A quote is over in two shapes. In prose it is a code span: a backtick just before the label
    and one just after the quote, with only plain prose after it to the end of its clause. In
    code it ends its line, or a comma or a semicolon does, and the next line of code begins
    something new. Anything else after the quote could hold a literal, in quote marks, in
    backticks or as a number.
    """
    text = reply.text
    line = bisect_right(reply.starts, end) - 1
    line_end = reply.starts[line + 1] - 1 if line + 1 < len(reply.starts) else len(text)
    mark = bisect_left(reply.marks, end)
    if mark < len(reply.marks) and reply.marks[mark] < line_end:
        return False  # a quote mark or an equals sign after the quote on its line
    first = _BLANK.match(text, end, line_end).end()  # where the first thing after the quote on its line is
    if first < line_end and text[first] == "`":
        # The code span has ended. Only plain prose may follow it, to the end of its clause.
        return text[start - 1:start] == "`" and _plain_to_the_end_of_its_clause(reply, first + 1)
    if first < line_end:
        return text[first] in ",;" and _BLANK.match(text, first + 1, line_end).end() == line_end
    return reply.new_after[line]  # The quote ends its line: what begins the next line that holds code?


def _mask_references(value: str, references: dict[str, set[str]], diff: bool) -> str:
    """Blank each exact quote of a screened reference in model output.

    A quote is permitted only when its expression ends where it does: see `_ends_there`. A quote
    that fails this stays as it is, and the label rules then refuse it.
    """
    if not references:
        return value
    quotes = []
    for pattern in _REFERENCE_PATTERNS:
        for match in pattern.finditer(value):
            quote, start = match.group(), match.start()
            # A removed line of a unified diff starts with '-', which the label pattern takes in.
            if diff and (start == 0 or value[start - 1] == "\n") and quote.startswith("-"):
                quote, start = quote[1:], start + 1
            if quote in references:
                quotes.append((start, match.end(), references[quote]))
    if not quotes:
        return value

    def blanked(spans) -> str:
        chars = list(value)
        for start, end, _rests in spans:
            for index in range(start, end):
                if chars[index] not in "\r\n":
                    chars[index] = " "
        return "".join(chars)

    without = blanked(quotes)
    reply = _read_reply(value, without, diff, quotes)
    permitted = [quote for quote in quotes if _ends_there(reply, *quote)]
    return without if len(permitted) == len(quotes) else blanked(permitted)


def _hits(pattern: re.Pattern, text: str, syntax, first_line: int = 1) -> list[int]:
    """The lines of the matches the file's syntax does not excuse: at most one more than a refusal names."""
    lines = []
    excusable = syntax is not None and "value" in pattern.groupindex
    for match in pattern.finditer(text):
        if excusable and syntax.excuses(match):
            continue
        lines.append(first_line + text.count("\n", 0, match.start()))
        if len(lines) > _NAMED_LINES:
            break
    return lines


def _sensitive(rule: str, lines: list[int] | None = None) -> AssistantError:
    """The refusal. The rule and the lines are for local output only, and it never holds a value."""
    error = AssistantError("sensitive_content")
    error.local_details["rule"] = rule
    if lines is not None:
        error.local_details["lines"] = sorted(set(lines))[:_NAMED_LINES]
        if len(lines) > _NAMED_LINES:
            error.local_details["more_lines"] = True
    return error


def refusal_location(error: AssistantError) -> dict:
    """The rule, the lines and the version of a content refusal, for a report that stays on this machine."""
    return {key: error.local_details[key] for key in ("rule", "version", "lines", "more_lines")
            if key in error.local_details}


def _screen_text(text: str, credential_text: str, extra_patterns: tuple[str, ...], syntax: _FileSyntax | None = None,
                 *, label_text: str | None = None, credential_labels: bool = True) -> None:
    """Refuse a credential in text.

    Known formats read `text`. The label rules read `label_text` when the caller gives one, and
    the key rule reads only `credential_text`, where annotations are blanked. With
    `credential_labels` off, the two credential label rules are not applied.
    """
    if "\0" in text:
        raise AssistantError("binary_input")
    labels = text if label_text is None else label_text

    def views(*candidates):
        return dict.fromkeys(candidates)  # the same text is read once

    for pattern in SECRET_PATTERNS:
        if not credential_labels and pattern in _REFERENCE_PATTERNS:
            continue
        if pattern is CREDENTIAL_KEY_PATTERN:
            searched = views(credential_text)
        elif pattern in FORMAT_PATTERNS:
            searched = views(text, credential_text)
        else:
            # Both views: this catches typed assignments without losing sensitive content in annotations.
            searched = views(labels, credential_text)
        for view in searched:
            lines = _hits(pattern, view, syntax)
            if lines:
                # Line numbers mean something only for a file's own content.
                raise _sensitive(_RULES[pattern], lines if syntax is not None else None)
    _screen_extra(text, extra_patterns)


def _screen_python(text: str, screen, extra_patterns: tuple[str, ...], credential_labels: bool = True) -> None:
    """Parsed Python: formats on raw text, the AST for code, label rules for text."""
    for pattern in FORMAT_PATTERNS:
        lines = _hits(pattern, text, None)
        if lines:
            raise _sensitive(_RULES[pattern], lines)
    hits = [(line, "account_label" if kind == "account" else "credential_label") for line, kind in screen.credential_hits
            if credential_labels or kind == "account"]
    rules = LABEL_PATTERNS if credential_labels else tuple(p for p in LABEL_PATTERNS if p not in _REFERENCE_PATTERNS)
    for segment, first_line in zip(screen.text_segments, screen.segment_lines, strict=True):
        if len(hits) > _NAMED_LINES:
            break
        for pattern in rules:
            hits += [(line, _RULES[pattern]) for line in _hits(pattern, segment, _TEXT_IN_PYTHON, first_line)]
    if hits:
        rule = min(hits)[1]
        raise _sensitive(rule, [line for line, name in hits if name == rule])
    _screen_extra(text, extra_patterns)


def _screen_extra(text: str, extra_patterns: tuple[str, ...]) -> None:
    try:
        if any(re.search(p, text, re.IGNORECASE) for p in extra_patterns):
            raise AssistantError("project_content_blocked")
    except re.error as exc:
        raise AssistantError("invalid_content_pattern") from exc


def regular_path(path: Path) -> Path:
    """Reject symlink ancestors before resolving, including not-yet-created files."""
    path = Path(path).expanduser().absolute()
    # Inspect raw ancestors before collapsing .., including older Python builds
    # without Path.is_junction(). Only fixed, verified Darwin OS aliases qualify.
    for item in (path, *path.parents):
        try:
            attributes = getattr(item.lstat(), "st_file_attributes", 0)
        except FileNotFoundError:
            attributes = 0
        if (item.is_symlink() or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT) and canonical_system_path(
            item
        ) == item:
            raise AssistantError("linked_path")
        if item.is_symlink():
            if not (
                sys.platform == "darwin"
                and len(item.parts) == 2
                and item.name in {"var", "tmp", "etc"}
                and canonical_system_path(item) != item
            ):
                raise AssistantError("linked_path")
        elif attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise AssistantError("linked_path")
    return canonical_system_path(path)


def write_private(path: Path, data: bytes, *, replace: bool = False) -> None:
    path = regular_path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and not replace:
        raise AssistantError("output_exists")
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            readonly_mode = None
            if sys.platform == "win32" and path.exists() and not path.stat().st_mode & stat.S_IWRITE:
                readonly_mode = path.stat().st_mode
                path.chmod(readonly_mode | stat.S_IWRITE)
            try:
                Path(name).replace(path)
            finally:
                if readonly_mode is not None and path.exists():
                    path.chmod(readonly_mode)
        else:
            # An exclusive hard-link prevents silently overwriting concurrent output.
            try:
                path.hardlink_to(Path(name))
            except FileExistsError as exc:
                raise AssistantError("output_exists") from exc
    finally:
        Path(name).unlink(missing_ok=True)
