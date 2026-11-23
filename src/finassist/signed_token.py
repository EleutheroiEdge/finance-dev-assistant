"""The signed web token rule of the credential screen: a format found by decoding, not by its first characters.

It sits beside the label and format rules in `security.FORMAT_PATTERNS` and has their interface (`search`,
`finditer`, `groupindex`), so every screen reads it the same way.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys


class SignedToken:
    """A signed web token by its structure: three base64url parts, the first decoding to a JSON object that names
    its algorithm and the second to JSON. The JSON may be spaced or empty, as RFC 7519 allows, so the encoded text
    is decoded, not matched by its first characters. Each part is bounded, so the work stays linear.

    What cannot be settled within those bounds is refused as a token, never passed: JSON nested deeper than
    _DEPTH is not decoded at all, and numbers stay text, so a long one cannot fail in conversion. The
    outcome is the same on every Python, whatever its recursion and integer limits."""

    # A part that decodes to JSON begins with "{" or with white space before it: base64url e, I, C or D.
    _CANDIDATE = re.compile(r"(?<![0-9A-Za-z_-])(?=([eICD][0-9A-Za-z_-]{3,2047})\.([eICD][0-9A-Za-z_-]{1,16383})"
                            r"\.([0-9A-Za-z_-]{16,1024})(?![0-9A-Za-z_-]))")
    groupindex: dict = {}
    _DEPTH = 64  # tokens in use nest a few levels; deeper is not decoded
    _UNSETTLED = object()

    def finditer(self, text: str, pos: int = 0, endpos: int = sys.maxsize):
        for match in self._CANDIDATE.finditer(text, pos, endpos):
            if self._is_token(match.group(1), match.group(2)):
                yield match

    def search(self, text: str, pos: int = 0, endpos: int = sys.maxsize):
        return next(self.finditer(text, pos, endpos), None)

    @classmethod
    def _is_token(cls, header: str, payload: str) -> bool:
        head = cls._decoded(header)
        if head is cls._UNSETTLED:
            return True
        if not (isinstance(head, dict) and isinstance(head.get("alg"), str)):
            return False
        body = cls._decoded(payload)
        return body is cls._UNSETTLED or isinstance(body, dict)

    @classmethod
    def _decoded(cls, part: str):
        """The part's JSON value, None when it is not JSON, or _UNSETTLED when that is not decided here."""
        try:
            text = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):  # not base64url, or not the UTF-8 that JSON is
            return None
        if text.count("[") + text.count("{") > cls._DEPTH and _nesting(text) > cls._DEPTH:
            return cls._UNSETTLED
        try:
            return json.loads(text, parse_int=str, parse_float=str, parse_constant=str)
        except json.JSONDecodeError:
            return None
        except (RecursionError, ValueError):  # not expected within the bounds; refused if it happens
            return cls._UNSETTLED


def _nesting(text: str) -> int:
    """The deepest nesting of brackets in JSON text, outside its strings."""
    depth = deepest = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "]}":
            depth -= 1
    return deepest


SIGNED_TOKEN = SignedToken()
