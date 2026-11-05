"""Read Python source the way Python itself does, for screening only.

Numbers come from the standard tokenizer and AST, and credential literals from
the standard AST, so no regex has to guess Python's syntax. Neither result
replaces source or request bytes, and neither proves that a file holds no
private data.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import io
from pathlib import PurePosixPath
import re
import sys
import tokenize
import warnings

PYTHON_SUFFIXES = frozenset({".py", ".pyi"})
# Comment and string text is still screened with the ordinary text rules.
_TEXT_TOKENS = frozenset({"STRING", "COMMENT", "FSTRING_MIDDLE", "TSTRING_MIDDLE"})
_ENVIRONMENT_READERS = frozenset({"getenv", "getenvb"})

# The credential vocabulary is the one the text rules use. As there, the name
# must end with the credential word; any other characters may come before it,
# including non-ASCII letters. Only a bounded tail is searched.
_SECRET_SUFFIX = re.compile(
    r"(?:api[_-]?key|password|secret|access[_-]?token|gh[_-]?token|github[_-](?:enterprise[_-])?token"
    r"|(?:secret|private|signing|encryption|access|client|master|auth|api)[_-]?(?:access[_-]?)?key)\Z",
    re.IGNORECASE)
_ACCOUNT_SUFFIX = re.compile(r"(?:account[_ -]?(?:number|id)|routing[_ -]?number)\Z", re.IGNORECASE)
_SUFFIX_WINDOW = 48
_MIN_SECRET_LENGTH = 12
_MIN_ACCOUNT_VALUE = 100_000  # at least six digits
# The deny list accepts up to 128 input digits with an exponent of up to 128,
# so a listed value can have up to 256 digits. Beyond these bounds a value can
# never equal a listed figure, and an integer is never converted to decimal.
MAX_FIGURE_DIGITS = 260
_MAX_INTEGER_BITS = 870  # 2**870 > 10**261


def is_python_path(path: str | None) -> bool:
    return path is not None and PurePosixPath(path).suffix.lower() in PYTHON_SUFFIXES


def _normalized(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def python_tokens(text: str) -> list[tokenize.TokenInfo] | None:
    """Return the complete token stream, or None when Python cannot tokenize the text."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(_normalized(text)).readline))
    except (tokenize.TokenError, SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    # Older tokenizers report an unterminated string or a stray character as an
    # error token and carry on. A partial stream must never pass as complete.
    if any(token.type == tokenize.ERRORTOKEN and token.string.strip() for token in tokens):
        return None
    return tokens


def python_tree(text: str) -> ast.AST | None:
    """Parse with warnings suppressed (they can echo source), or return None."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(_normalized(text))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def text_segments(tokens: list[tokenize.TokenInfo]) -> list[str]:
    """Comment and string token text, which the text rules screen as text."""
    return [token.string for token in tokens if tokenize.tok_name.get(token.type) in _TEXT_TOKENS]


def hidden_fstring_fields(tokens: list[tokenize.TokenInfo]) -> bool:
    """True when this Python tokenizes f-string fields as part of one STRING token.

    Before Python 3.12 the tokenizer yields no NUMBER token inside an f-string
    replacement field, so only the AST can read those numbers.
    """
    if sys.version_info >= (3, 12):
        return False
    for token in tokens:
        if token.type == tokenize.STRING and "{" in token.string:
            prefix = re.match(r"[A-Za-z]*", token.string).group().lower()
            if "f" in prefix:
                return True
    return False


def _plain_decimal(number: Decimal) -> str | None:
    """Plain decimal text of an exact value within the figure bounds, or None."""
    if not number.is_finite() or not -(MAX_FIGURE_DIGITS + 1) <= number.adjusted() <= MAX_FIGURE_DIGITS:
        return None
    # Bounded: the exponent is within the figure bounds and the coefficient is
    # the literal's own digits.
    plain = format(number, "f")
    if "." in plain:
        plain = plain.rstrip("0").rstrip(".")
    if len(plain.replace(".", "").lstrip("0")) > MAX_FIGURE_DIGITS:
        return None
    return plain or "0"


def _plain_integer(value: int) -> str | None:
    value = abs(value)
    return None if value.bit_length() > _MAX_INTEGER_BITS else str(value)


def number_text(token: str) -> str | None:
    """Plain decimal text of a numeric literal's exact value, or None if it cannot be a listed figure."""
    value = token.replace("_", "").lower()
    if value.endswith("j"):
        value = value[:-1]
    if not value:
        return None
    try:
        if value.startswith(("0x", "0o", "0b")):
            return _plain_integer(int(value, 0))
        return _plain_decimal(Decimal(value))
    except (ValueError, InvalidOperation):
        return None


class _SourceIndex:
    """Single-line source spans by AST position, without re-splitting the file per node."""

    def __init__(self, source: str):
        self._lines = _normalized(source).split("\n")  # the text python_tree parsed
        self._encoded: dict[int, bytes] = {}

    def segment(self, node: ast.AST) -> str | None:
        # A numeric literal is one token, so it never spans lines.
        if getattr(node, "end_lineno", None) != node.lineno or node.end_col_offset is None:
            return None
        row = node.lineno - 1
        if not 0 <= row < len(self._lines):
            return None
        data = self._encoded.get(row)
        if data is None:
            data = self._encoded[row] = self._lines[row].encode("utf-8")
        try:  # AST columns count UTF-8 bytes
            return data[node.col_offset:node.end_col_offset].decode("utf-8")
        except UnicodeDecodeError:
            return None


_UNAVAILABLE = object()


def _spelled_number(node: ast.Constant, index: _SourceIndex):
    """Exact text of a numeric constant from its source spelling.

    Returns the plain text, None when the exact value is outside the figure bounds
    (so it can never be listed), or _UNAVAILABLE when no spelling checks out.
    """
    segment = index.segment(node)
    if not segment:
        return _UNAVAILABLE
    actual = node.value.imag if isinstance(node.value, complex) and node.value.real == 0 else node.value
    spelled = segment.replace("_", "").lower().rstrip("j")
    # The spelling must be the literal this node was parsed from. Integers compare
    # exactly; floats compare after Python's own rounding of the spelled value.
    try:
        if isinstance(actual, int):
            matches = int(spelled, 0) == actual
        else:
            matches = float(Decimal(spelled)) == float(actual)
    except (ValueError, InvalidOperation, OverflowError):
        return _UNAVAILABLE
    return number_text(segment) if matches else _UNAVAILABLE


def fstring_constant_texts(tree: ast.AST, source: str) -> list[str]:
    """Plain decimal text of numeric constants inside f-string fields.

    Only needed before Python 3.12, where those numbers are not NUMBER tokens;
    every other numeric constant is a NUMBER token already.
    """
    index = _SourceIndex(source)
    seen, texts = set(), []
    for joined in ast.walk(tree):
        if not isinstance(joined, ast.JoinedStr):
            continue
        for node in ast.walk(joined):
            if (id(node) in seen or not isinstance(node, ast.Constant) or isinstance(node.value, bool)
                    or not isinstance(node.value, (int, float, complex))):
                continue
            seen.add(id(node))
            spelled = _spelled_number(node, index)
            if spelled is not _UNAVAILABLE:
                if spelled is not None:  # None: exact value outside the bounds, never listed
                    texts.append(spelled)
                continue
            # No checked spelling: integers stay exact, floats use their
            # shortest round-trip text.
            value = node.value
            for part in ([value.real, value.imag] if isinstance(value, complex) else [value]):
                if isinstance(part, int):
                    text = _plain_integer(part)
                else:
                    text = _plain_decimal(Decimal(repr(part))) if part == part else None
                if text is not None:
                    texts.append(text)
    return texts


@dataclass(frozen=True)
class PythonScreen:
    """What the screen needs from one parsed Python file; never serialized."""

    text_segments: tuple[str, ...]
    credential_literal: bool


def python_screen(text: str) -> PythonScreen | None:
    """Tokenize and parse once, or return None so the caller screens strictly."""
    normalized = _normalized(text)
    tokens = python_tokens(normalized)
    tree = python_tree(normalized) if tokens is not None else None
    if tree is None:
        return None
    return PythonScreen(tuple(text_segments(tokens)), credential_literal_present(tree, normalized))


def _label_kind(name: str) -> str | None:
    tail = name[-_SUFFIX_WINDOW:]
    if _ACCOUNT_SUFFIX.search(tail):
        return "account"
    if _SECRET_SUFFIX.search(tail):
        return "secret"
    return None


def _environment_lookup(func: ast.AST) -> bool:
    if isinstance(func, ast.Name):
        return func.id in _ENVIRONMENT_READERS
    if isinstance(func, ast.Attribute):
        if func.attr in _ENVIRONMENT_READERS:
            return True
        owner = func.value
        owner_name = owner.id if isinstance(owner, ast.Name) else owner.attr if isinstance(owner, ast.Attribute) else ""
        return func.attr in {"get", "setdefault"} and owner_name in {"environ", "environb"}
    return False


def _value_node(node: ast.AST) -> ast.AST | None:
    """The literal node assigned, unwrapping a literal getenv/environ fallback or default=."""
    if isinstance(node, (ast.Constant, ast.JoinedStr)):
        return node
    if isinstance(node, ast.Call):
        # A literal fallback in os.getenv(NAME, "...") or Field(default="...") is
        # still a hardcoded value for the credential-named target.
        for keyword in node.keywords:
            if keyword.arg == "default":
                return keyword.value
        if _environment_lookup(node.func) and len(node.args) >= 2:
            return node.args[1]
    return None


def _value_text(node: ast.AST | None, index: _SourceIndex) -> str | None:
    """Text of a literal value. Numbers keep their source spelling, never str(int)."""
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            return value.decode("latin-1")
        if isinstance(value, (int, float, complex)) and not isinstance(value, bool):
            # One token on one line: read from the per-file index, not the whole file.
            return index.segment(node)
        return None
    if isinstance(node, ast.JoinedStr) and all(isinstance(part, ast.Constant) for part in node.values):
        return "".join(str(part.value) for part in node.values)
    return None


def _target_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if (isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant)
            and isinstance(target.slice.value, str)):
        return target.slice.value
    return None


def _target_pairs(target: ast.AST, value: ast.AST):
    if isinstance(target, (ast.Tuple, ast.List)):
        if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts):
            for item, item_value in zip(target.elts, value.elts, strict=True):
                yield from _target_pairs(item, item_value)
        return
    name = _target_name(target)
    if name is not None:
        yield name, value


def _labelled_values(tree: ast.AST):
    """Yield (name, value node) pairs; annotations are never inspected."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                yield from _target_pairs(target, node.value)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            yield from _target_pairs(node.target, node.value)
        elif isinstance(node, ast.keyword) and node.arg is not None:
            yield node.arg, node.value
        elif isinstance(node, ast.arguments):
            positional = [*node.posonlyargs, *node.args]
            for arg, default in zip(positional[len(positional) - len(node.defaults):], node.defaults, strict=True):
                yield arg.arg, default
            for arg, default in zip(node.kwonlyargs, node.kw_defaults, strict=True):
                if default is not None:
                    yield arg.arg, default
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    yield key.value, value


def _is_account_value(node: ast.AST, index: _SourceIndex) -> bool:
    if (isinstance(node, ast.Constant) and isinstance(node.value, int)
            and not isinstance(node.value, bool)):
        # Magnitude, not spelling: 123_456_789 and 0x1E240 both count, and no
        # decimal conversion of a huge integer or source lookup is needed.
        return abs(node.value) >= _MIN_ACCOUNT_VALUE
    text = _value_text(node, index)
    return text is not None and re.match(r"\d{6,}", text.replace("_", "")) is not None


def credential_literal_present(tree: ast.AST, source: str) -> bool:
    """True when a credential-named target is given a literal value."""
    index = _SourceIndex(source)
    for name, node in _labelled_values(tree):
        kind = _label_kind(name)
        if kind is None:
            continue
        value = _value_node(node)
        if value is None:
            continue
        if kind == "account":
            if _is_account_value(value, index):
                return True
            continue
        text = _value_text(value, index)
        if text is not None and len(text) >= _MIN_SECRET_LENGTH:
            return True
    return False
