from contextlib import contextmanager
import re

_DETAIL_KEY = re.compile(r"[a-z][a-z0-9_]{0,40}")


def _bounded(value) -> bool:
    if isinstance(value, (bool, int, float)) or value is None:
        return True
    if isinstance(value, str):
        return len(value) <= 256
    return isinstance(value, (list, tuple)) and len(value) <= 64 and all(
        isinstance(item, (bool, int, float, str)) and (not isinstance(item, str) or len(item) <= 256)
        for item in value)


class AssistantError(Exception):
    """Public errors contain a fixed code, never payload or credential values.

    Optional public details hold bounded, non-secret facts only, such as an
    option name and its allowed range. They never hold paths, contents or values.
    Local details may name repository paths for the person at this machine only.
    """

    def __init__(self, code: str, details: dict | None = None):
        self.code = code
        # Producers still choose only non-secret facts; this keeps the shape bounded
        # and stops a detail from replacing the reserved code or status keys.
        self.public_details = {
            key: list(value) if isinstance(value, tuple) else value
            for key, value in (details or {}).items()
            if isinstance(key, str) and _DETAIL_KEY.fullmatch(key) and key not in {"code", "status", "hint"}
            and _bounded(value)
        }
        # Facts for the person at this machine only, such as repository path names. The CLI
        # prints them under "local" for commands that name paths locally; they are never
        # audited, sent to a provider, or written to a packet or report.
        self.local_details: dict = {}
        super().__init__(code)


# Commands whose errors may name repository paths on this machine's stderr, under "local".
# gate run and ci gate never do (their logs are often published); doctor --policy names
# paths in its own local report instead.
LOCAL_NAMING_COMMANDS = frozenset({"plan", "watch"})


def error_record(exc: AssistantError, command: str | None, fields: dict) -> dict:
    """The stderr record for a caught error: code, public details, hint, and local details where allowed."""
    record = {"status": "error", "code": exc.code, **exc.public_details, **fields}
    if getattr(exc, "local_details", None) and command in LOCAL_NAMING_COMMANDS:
        record["local"] = exc.local_details
    return record


@contextmanager
def local_details(**details):
    """Attach the non-empty details to an AssistantError raised inside, for local output only."""
    try:
        yield
    except AssistantError as exc:
        for key, value in details.items():
            if value:
                exc.local_details.setdefault(key, value)
        raise


def network_not_approved(allow_network: bool, approved: bool) -> AssistantError:
    """Name which of the two required network permissions is missing."""
    return AssistantError("network_not_approved",
                          {"allow_network": bool(allow_network), "allow_network_flag": bool(approved)})


def prices_required(prices: dict) -> AssistantError:
    """List every price field that must be set above zero."""
    return AssistantError("provider_prices_required", {"missing": sorted(k for k, v in prices.items() if v <= 0)})


class OperationOutcomeUnknown(AssistantError):
    """A mutation may have completed; retain the open audit run for reconciliation."""
