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

# The credential vocabulary is the one the text rules already use. A name must
# consist of label characters and end with the credential word, as the text
# rules require. Only the bounded tail is searched, so long names stay linear.
_SECRET_CHARS = re.compile(r"[A-Za-z0-9_-]+\Z")
_SECRET_SUFFIX = re.compile(
    r"(?:api[_-]?key|password|secret|access[_-]?token|gh[_-]?token|github[_-](?:enterprise[_-])?token"
    r"|(?:secret|private|signing|encryption|access|client|master|auth|api)[_-]?(?:access[_-]?)?key)\Z",
    re.IGNORECASE)
_ACCOUNT_CHARS = re.compile(r"[A-Za-z0-9_ -]+\Z")
_ACCOUNT_SUFFIX = re.compile(r"(?:account[_ -]?(?:number|id)|routing[_ -]?number)\Z", re.IGNORECASE)
_SUFFIX_WINDOW = 48
_MIN_SECRET_LENGTH = 12
# Listed figures have at most 128 digits. 2**430 has 130 digits, so a larger
# integer can never equal a listed figure and is never converted to decimal.
_MAX_INTEGER_BITS = 430


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
    """Plain decimal text of an exact value with at most 128 digits, or None."""
    if not number.is_finite() or not -129 <= number.adjusted() <= 128:
        return None
    # Bounded: the exponent is within 128 and the coefficient is the literal's own.
    plain = format(number, "f")
    if "." in plain:
        plain = plain.rstrip("0").rstrip(".")
    if len(plain.replace(".", "").lstrip("0")) > 128:
        return None
    return plain or "0"


def _plain_integer(value: int) -> str | None:
    value = abs(value)
    return None if value.bit_length() > _MAX_INTEGER_BITS else str(value)


def number_text(token: str) -> str | None:
    """Plain decimal text of a NUMBER token's exact value, or None if it cannot be a listed figure."""
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


def constant_number_texts(tree: ast.AST) -> list[str]:
    """Plain decimal text of every numeric constant, including those inside f-strings."""
    texts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or isinstance(node.value, bool):
            continue
        value = node.value
        parts = [value.real, value.imag] if isinstance(value, complex) else [value]
        for part in parts:
            if isinstance(part, int):
                text = _plain_integer(part)
            elif isinstance(part, float):
                text = _plain_decimal(Decimal(repr(part))) if part == part else None
            else:
                text = None
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
    if _ACCOUNT_CHARS.match(name) and _ACCOUNT_SUFFIX.search(tail):
        return "account"
    if _SECRET_CHARS.match(name) and _SECRET_SUFFIX.search(tail):
        return "secret"
    return None


def _value_text(node: ast.AST | None, source: str) -> str | None:
    """Text of a literal value. Numbers keep their source spelling, never str(int)."""
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            return value.decode("latin-1")
        if isinstance(value, (int, float, complex)) and not isinstance(value, bool):
            return ast.get_source_segment(source, node)
        return None
    if isinstance(node, ast.JoinedStr) and all(isinstance(part, ast.Constant) for part in node.values):
        return "".join(str(part.value) for part in node.values)
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


def _value_literal(node: ast.AST, source: str) -> str | None:
    literal = _value_text(node, source)
    if literal is not None or not isinstance(node, ast.Call):
        return literal
    # A literal fallback in os.getenv(NAME, "...") or Field(default="...") is
    # still a hardcoded value for the credential-named target.
    for keyword in node.keywords:
        if keyword.arg == "default":
            return _value_text(keyword.value, source)
    if _environment_lookup(node.func) and len(node.args) >= 2:
        return _value_text(node.args[1], source)
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


def credential_literal_present(tree: ast.AST, source: str) -> bool:
    """True when a credential-named target is given a literal value."""
    for name, node in _labelled_values(tree):
        kind = _label_kind(name)
        if kind is None:
            continue
        text = _value_literal(node, source)
        if text is None:
            continue
        if kind == "secret" and len(text) >= _MIN_SECRET_LENGTH:
            return True
        if kind == "account" and re.match(r"\d{6,}", text):
            return True
    return False
