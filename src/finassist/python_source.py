"""Read Python source the way Python itself does, for screening only.

Numbers come from the standard tokenizer and credential literals from the
standard AST, so no regex has to guess Python's syntax. Neither result replaces
source or request bytes, and neither proves that a file holds no private data.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import io
from pathlib import PurePosixPath
import re
import tokenize
import warnings

PYTHON_SUFFIXES = frozenset({".py", ".pyi"})
# Comment and string text is still screened with the ordinary text rules.
_TEXT_TOKENS = frozenset({"STRING", "COMMENT", "FSTRING_MIDDLE", "TSTRING_MIDDLE"})
_ENVIRONMENT_READERS = frozenset({"getenv", "getenvb"})

# The credential vocabulary is the one the text rules already use. A name must
# end with the credential word, as the text rules require for a label.
_SECRET_LABELS = (
    re.compile(r"[A-Za-z0-9_-]*(?:api[_-]?key|password|secret|access[_-]?token|gh[_-]?token"
               r"|github[_-](?:enterprise[_-])?token)", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9_-]*(?:secret|private|signing|encryption|access|client|master|auth|api)"
               r"[_-]?(?:access[_-]?)?key", re.IGNORECASE),
)
_ACCOUNT_LABEL = re.compile(r"[A-Za-z0-9_ -]*(?:account[_ -]?(?:number|id)|routing[_ -]?number)",
                            re.IGNORECASE)
_MIN_SECRET_LENGTH = 12
_MAX_LABEL_LENGTH = 256


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


def text_segments(tokens: list[tokenize.TokenInfo]) -> list[str]:
    """Comment and string token text, which the text rules screen as text."""
    return [token.string for token in tokens if tokenize.tok_name.get(token.type) in _TEXT_TOKENS]


def number_text(token: str) -> str | None:
    """Plain decimal text of a NUMBER token's exact value, or None if out of bounds."""
    value = token.replace("_", "").lower()
    if value.endswith("j"):
        value = value[:-1]
    if not value or len(value) > 300:
        return None
    try:
        if value.startswith(("0x", "0o", "0b")):
            whole = int(value, 0)
            if whole.bit_length() > 430:  # more than 128 decimal digits
                return None
            number = Decimal(whole)
        else:
            number = Decimal(value)
    except (ValueError, InvalidOperation):
        return None
    # Listed figures have at most 128 digits; never expand a huge exponent.
    if not number.is_finite() or len(number.as_tuple().digits) > 128 or not -129 <= number.adjusted() <= 128:
        return None
    return format(number, "f")


@dataclass(frozen=True)
class PythonScreen:
    """What the screen needs from one parsed Python file; never serialized."""

    text_segments: tuple[str, ...]
    credential_literal: bool


def python_screen(text: str) -> PythonScreen | None:
    """Tokenize and parse once, or return None so the caller screens strictly."""
    normalized = _normalized(text)
    tokens = python_tokens(normalized)
    if tokens is None:
        return None
    try:
        with warnings.catch_warnings():
            # Invalid escapes can warn and echo the source line; never let them.
            warnings.simplefilter("ignore")
            tree = ast.parse(normalized)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    return PythonScreen(tuple(text_segments(tokens)), credential_literal_present(tree))


def _label_kind(name: str) -> str | None:
    if not name or len(name) > _MAX_LABEL_LENGTH:
        return None
    if _ACCOUNT_LABEL.fullmatch(name):
        return "account"
    if any(label.fullmatch(name) for label in _SECRET_LABELS):
        return "secret"
    return None


def _plain_literal(node: ast.AST | None) -> str | int | None:
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, bytes):
            return value.decode("latin-1")
        if isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool)):
            return value
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


def _value_literal(node: ast.AST) -> str | int | None:
    literal = _plain_literal(node)
    if literal is not None or not isinstance(node, ast.Call):
        return literal
    # A literal fallback in os.getenv(NAME, "...") or Field(default="...") is
    # still a hardcoded value for the credential-named target.
    for keyword in node.keywords:
        if keyword.arg == "default":
            return _plain_literal(keyword.value)
    if _environment_lookup(node.func) and len(node.args) >= 2:
        return _plain_literal(node.args[1])
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


def credential_literal_present(tree: ast.AST) -> bool:
    """True when a credential-named target is given a literal value."""
    for name, node in _labelled_values(tree):
        kind = _label_kind(name)
        if kind is None:
            continue
        literal = _value_literal(node)
        if literal is None:
            continue
        text = str(literal)
        if kind == "secret" and len(text) >= _MIN_SECRET_LENGTH:
            return True
        if kind == "account" and re.match(r"\d{6,}", text):
            return True
    return False
