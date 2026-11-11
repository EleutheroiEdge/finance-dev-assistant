"""Fail-closed input checks. These supplement explicit scope and OS isolation."""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import stat
import sys
import unicodedata

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
    r"(?i)(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*(?:secret|private|signing|encryption|access|client|master|auth|api)[_-]?(?:access[_-]?)?key\b[\"']?\s*[=:]\s*"
    r"(?:[\"'][^\"'\n]{12,}[\"']|(?![A-Za-z_][A-Za-z0-9_.]*\s*\()(?!(?-i:[A-Z][A-Za-z_]*)(?![A-Za-z0-9_./+=:@-]))(?!(?:[A-Za-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_.]))[A-Za-z0-9][A-Za-z0-9_./+=:@-]{11,})"
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
        r"(?i)(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*(?:api[_-]?key|password|secret|access[_-]?token|gh[_-]?token|github[_-](?:enterprise[_-])?token)\b[\"']?\s*[=:]\s*"
        r"(?:[\"'][^\"'\n]{12,}[\"']|[A-Za-z0-9][A-Za-z0-9_./+=:@-]{11,})"
    ),
    CREDENTIAL_KEY_PATTERN,
    re.compile(
        r"(?i)(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*(?:account[_ -]?(?:number|id)|routing[_ -]?number)[\"']?\s*[=:]\s*[\"']?\d{6,}"
    ),
)
SECRET_PATTERNS = (*FORMAT_PATTERNS, *LABEL_PATTERNS)


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
                alias.startswith(prefix) for alias in names for prefix in environment):
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


def check_text(text: str, *, extra_patterns: tuple[str, ...] = (), source_path: str | None = None) -> None:
    if is_python_path(source_path) and "\0" not in text:
        screen = python_screen(text)
        if screen is not None:
            _screen_python(text, screen, extra_patterns)
            return
    # Text, and Python that does not tokenize and parse, keeps the strict text rules.
    _screen_text(text, credential_screening_view(text, source_path), extra_patterns)


def check_context_document(document: dict, *, extra_patterns: tuple[str, ...] = (), records_key="files") -> None:
    """Screen each record with its path, then the remaining typed envelope."""
    envelope = deepcopy(document)
    for item in envelope[records_key]:
        for side in ("before", "after"):
            if item[side] is not None:
                check_text(item[side], extra_patterns=extra_patterns, source_path=item["path"])
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
    document: dict, source_files: list[dict], *, extra_patterns: tuple[str, ...] = (), diff: bool = False
) -> None:
    """Permit only exact credential-label quotes from screened annotations.

    A match includes its label, separator and complete candidate value; a word
    merely present elsewhere in source confers no output exception. Paths and
    source must come from the caller's validated, hash-bound request/post-images.
    Other secret patterns and custom patterns always inspect original output.
    """
    allowed: dict[str, set[str]] = {}
    for item in source_files:
        for side in ("before", "after"):
            text = item.get(side)
            if text is None:
                continue
            check_text(text, source_path=item["path"], extra_patterns=extra_patterns)
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

    def screening_view(value):
        if isinstance(value, str):
            chars = list(value)
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
            _screen_text(value, view, extra_patterns)
            # A syntactically valid typed assignment in an output string must
            # not conceal a new value. The first check above retains strict
            # output screening: parsing alone never authorizes an annotation.
            _screen_text(value, credential_screening_view(view, "output.py"), extra_patterns)
            return view
        if isinstance(value, list):
            return [screening_view(item) for item in value]
        if isinstance(value, dict):
            return {key: screening_view(item) for key, item in value.items()}
        return value

    _screen_text(canonical(document).decode(), canonical(screening_view(document)).decode(), extra_patterns)


def _screen_text(text: str, credential_text: str, extra_patterns: tuple[str, ...]) -> None:
    if "\0" in text:
        raise AssistantError("binary_input")
    for pattern in SECRET_PATTERNS:
        if pattern is CREDENTIAL_KEY_PATTERN:
            matched = pattern.search(credential_text)
        else:
            # Searching both views catches typed assignments without losing
            # literal secret signatures or sensitive content in annotations.
            matched = pattern.search(text) or pattern.search(credential_text)
        if matched:
            raise AssistantError("sensitive_content")
    _screen_extra(text, extra_patterns)


def _screen_python(text: str, screen, extra_patterns: tuple[str, ...]) -> None:
    """Parsed Python: formats on raw text, the AST for code, label rules for text."""
    if any(pattern.search(text) for pattern in FORMAT_PATTERNS):
        raise AssistantError("sensitive_content")
    if screen.credential_literal or any(
        pattern.search(segment) for segment in screen.text_segments for pattern in LABEL_PATTERNS
    ):
        raise AssistantError("sensitive_content")
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
