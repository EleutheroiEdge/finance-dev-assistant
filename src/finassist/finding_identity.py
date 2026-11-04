"""Request-bound finding identities shared by gate reports and history output.

A digest binds bytes and position, not the truth or completeness of a claim.
"""

import re

from .errors import AssistantError
from .security import canonical, digest

_FIELDS = frozenset({"severity", "file", "line", "claim", "evidence_status"})
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


def finding_identifier(request_sha256: str, index: int, finding: dict) -> str:
    """Hash the exact request, zero-based position and public finding projection.

    Preserve the history f-<sha256> convention and positional disambiguation.
    The optional supplied id is excluded; consumers must compare it with this
    derived identity after validating their full report envelope.
    """
    if (not isinstance(request_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", request_sha256) is None
            or type(index) is not int or not 0 <= index < 50
            or not isinstance(finding, dict)
            or set(finding) not in (_FIELDS, _FIELDS | {"id"})):
        raise AssistantError("finding_identity_invalid")
    if (not isinstance(finding["severity"], str) or finding["severity"] not in _SEVERITIES
            or not isinstance(finding["file"], str) or not 1 <= len(finding["file"]) <= 512
            or type(finding["line"]) is not int or finding["line"] < 1
            or not isinstance(finding["claim"], str) or not 1 <= len(finding["claim"]) <= 2000
            or finding["evidence_status"] != "source-reference-validated-not-reproduced"):
        raise AssistantError("finding_identity_invalid")
    public = {key: finding[key] for key in _FIELDS}
    try:
        raw = canonical({"request_sha256": request_sha256, "index": index, "finding": public})
    except (UnicodeError, ValueError, TypeError):
        raise AssistantError("finding_identity_invalid") from None
    return "f-" + digest(raw)
