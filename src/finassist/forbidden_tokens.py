"""Bounded decimal normalization for confidential-number screening.

This module does not load policy, authorize a request or dispatch a provider.
"""

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
import unicodedata

from .errors import AssistantError
from .security import regular_path

_CURRENCIES = "$€£¥"
_GROUP_SEPARATORS = "   "
_DECIMAL = re.compile(r"(?P<integer>[0-9]+|[0-9]{1,3}(?:,[0-9]{3})+)"
                      r"(?:\.(?P<fraction>[0-9]+))?(?:[eE](?P<exponent>[+-]?[0-9]{1,3}))?")


def normalize_numeric_token(value: str) -> str:
    """Return a dot-decimal canonical value, without floating-point rounding.

    Only explicit dot decimals, comma/space thousands groups, underscores between
    digits, Unicode decimal digits, one currency prefix, signs, parentheses and bounded
    decimal exponents are supported. Invalid input has a non-disclosing error.
    """
    if not isinstance(value, str) or not value or len(value) > 256:
        raise AssistantError("forbidden_token_invalid")
    value = value.strip(" ")
    value = "".join(str(unicodedata.decimal(c)) if c.isdecimal() else c for c in value)
    value = re.sub(r"(?<=[0-9])_(?=[0-9])", "", value)
    negative = value.startswith("(") and value.endswith(")")
    if negative:
        value = value[1:-1]
    if value[:1] in _CURRENCIES and value:
        value = value[1:]
    if value.startswith(("+", "-")):
        if negative:
            raise AssistantError("forbidden_token_invalid")
        negative = value.startswith("-")
        value = value[1:]
        if value[:1] in _CURRENCIES and value:
            value = value[1:]
    # Grouping must use one separator throughout, with exactly three digits
    # after each separator. Whitespace never changes a decimal's magnitude.
    used = [c for c in _GROUP_SEPARATORS if c in value]
    if used:
        if len(used) != 1 or "," in value:
            raise AssistantError("forbidden_token_invalid")
        value = value.replace(used[0], ",")
    match = _DECIMAL.fullmatch(value)
    if match is None:
        raise AssistantError("forbidden_token_invalid")
    integer = match["integer"].replace(",", "")
    fraction = match["fraction"] or ""
    exponent = int(match["exponent"] or "0")
    if len(integer) + len(fraction) > 128 or abs(exponent) > 128:
        raise AssistantError("forbidden_token_invalid")
    digits = integer + fraction
    point = len(integer) + exponent
    if point <= 0:
        result = "0." + "0" * (-point) + digits
    elif point >= len(digits):
        result = digits + "0" * (point - len(digits))
    else:
        result = digits[:point] + "." + digits[point:]
    whole, _, fractional = result.partition(".")
    whole = whole.lstrip("0") or "0"
    fractional = fractional.rstrip("0")
    result = whole + ("." + fractional if fractional else "")
    return ("-" if negative and result != "0" else "") + result


MAX_TOKEN_BYTES = 131_072
MAX_TOKENS = 1024


@dataclass(frozen=True)
class TokenSnapshot:
    """Private ephemeral deny set; never serialize into packets or reports."""

    hashes: frozenset[str] = field(repr=False)
    file_path: Path | None = field(default=None, repr=False)
    line_count: int = 0
    file_digest: str | None = field(default=None, repr=False)


def _read_token_file(value: str, excluded_roots: tuple[Path, ...]) -> tuple[bytes, Path]:
    """Read a bounded regular non-linked external file, with identity checks."""
    descriptor = None
    try:
        candidate = Path(value)
        if not candidate.is_absolute() or ".git" in candidate.parts:
            raise ValueError
        path = regular_path(candidate)
        if any(path.is_relative_to(root.resolve()) for root in excluded_roots):
            raise ValueError
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_TOKEN_BYTES:
            raise ValueError
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_BINARY", 0))
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ValueError
        chunks, size = [], 0
        while size <= MAX_TOKEN_BYTES:
            chunk = os.read(descriptor, min(8192, MAX_TOKEN_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        current = regular_path(candidate).stat()
        def identity(st):
            return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        def metadata(st):
            return (*identity(st), st.st_ctime_ns, st.st_nlink)
        # Windows stat/fstat can expose different ctime semantics. Compare
        # ctime within each API, and cross-check the shared object identity.
        if (size > MAX_TOKEN_BYTES or metadata(opened) != metadata(after)
                or metadata(before) != metadata(current) or identity(after) != identity(current)):
            raise ValueError
        return b"".join(chunks), path
    except (OSError, ValueError, AssistantError):
        raise AssistantError("forbidden_token_file_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def load_token_snapshot(rules: dict, excluded_roots: tuple[Path, ...]) -> TokenSnapshot:
    """Union optional literal and normalized-hash declarations without logging."""
    configured = rules.get("forbidden_token_hashes", [])
    if (not isinstance(configured, list) or len(configured) > MAX_TOKENS
            or any(not isinstance(h, str) or re.fullmatch(r"[0-9a-f]{64}", h) is None for h in configured)):
        raise AssistantError("forbidden_token_hashes_invalid")
    hashes = set(configured)
    path, count, fingerprint = None, 0, None
    if "forbidden_token_file" in rules:
        value = rules["forbidden_token_file"]
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise AssistantError("forbidden_token_file_invalid")
        raw, path = _read_token_file(value, excluded_roots)
        try:
            lines = raw.decode("utf-8").replace("\r\n", "\n").split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            if not lines or len(lines) > MAX_TOKENS:
                raise ValueError
            for line in lines:
                normalized = normalize_numeric_token(line)
                hashes.add(hashlib.sha256(normalized.encode("utf-8")).hexdigest())
        except (UnicodeError, ValueError, AssistantError):
            raise AssistantError("forbidden_token_file_invalid") from None
        count = len(lines)
        fingerprint = hashlib.sha256(raw).hexdigest()
    return TokenSnapshot(frozenset(hashes), path, count, fingerprint)


# Broad passes cover grouping and exponents. The plain pass also finds a
# literal beside punctuation/numeric CSV cells when a broad candidate is invalid.
_PLAIN = re.compile(r"(?<!\d)\d+(?:\.\d+)?(?!\d)")
_NUMBER = re.compile(r"(?<![\d.])(?:\()?[-+]?[$€£¥]?[-+]?\d+(?:[,._ \u00a0\u202f]\d+)*(?:[eE][-+]?\d+)?(?:\))?(?!\d)")
_UNGROUPED = re.compile(r"(?<![\d.,])(?:\()?[-+]?[$€£¥]?[-+]?\d+(?:[,._]\d+)*(?:[eE][-+]?\d+)?(?:\))?(?![\d,])")


# A preceding/following separate number must not swallow a space-grouped value.
# Match valid space/underscore groups directly as well as broad candidates.
_SPACED = re.compile(r"(?<![\d.,])(?:\()?[-+]?[$€£¥]?[-+]?\d{1,3}"
                     r"(?P<group>[ _\u00a0\u202f])\d{3}(?:(?P=group)\d{3})*"
                     r"(?:\.\d+)?(?:[eE][-+]?\d+)?(?:\))?(?!\d|[,.]\d)")


_DIGIT_SEPARATED = re.compile(
    r"(?<![\d.])(?:\()?[-+]?[$€£¥]?[-+]?\d[\d_]*"
    r"(?:\.[\d_]+)?(?:[eE][-+]?[\d_]+)?(?:\))?(?!\d)"
)


def screen_text(text: str, snapshot: TokenSnapshot) -> None:
    """Check content only; callers must select typed content, not filenames."""
    if not snapshot.hashes:
        return
    for pattern in (_NUMBER, _UNGROUPED, _SPACED, _DIGIT_SEPARATED, _PLAIN):
        for match in pattern.finditer(text):
            try:
                number = normalize_numeric_token(match.group())
            except AssistantError:
                continue
            magnitude = number.lstrip("-")
            # Hash-only policies can list either sign. Compare both without
            # recovering or retaining any configured plaintext value.
            forms = {number, magnitude, "-" + magnitude} if magnitude != "0" else {"0"}
            if any(hashlib.sha256(form.encode("utf-8")).hexdigest() in snapshot.hashes
                   for form in forms):
                raise AssistantError("forbidden_token_present")


def screen_packet(packet: dict, system: str, snapshot: TokenSnapshot) -> None:
    """Select content after the caller validates the packet's strict schema."""
    screen_text(system, snapshot)
    for item in packet["files"]:
        for side in ("before", "after"):
            if item[side] is not None:
                screen_text(item[side], snapshot)


@dataclass(frozen=True)
class TokenGuard:
    """Ephemeral screening state, excluded from Config and serialized identity."""

    rules: dict = field(repr=False)
    roots: tuple[Path, ...] = field(repr=False)
    snapshot: TokenSnapshot = field(repr=False)

    def recheck(self, packet: dict, system: str) -> None:
        current = load_token_snapshot(self.rules, self.roots)
        # Even a semantically equivalent rewrite invalidates a prior snapshot.
        if current != self.snapshot:
            raise AssistantError("forbidden_token_configuration_changed")
        screen_packet(packet, system, current)


def token_file_audit(snapshot: TokenSnapshot) -> dict | None:
    """Only non-content metadata may enter the private budget audit."""
    if snapshot.file_path is None:
        return None
    path = str(snapshot.file_path)
    try:
        screen_text(path, snapshot)
    except AssistantError:
        path = "[redacted]"
    return {"event": "forbidden_token_file_screened", "file_path": path,
            "line_count": snapshot.line_count}
