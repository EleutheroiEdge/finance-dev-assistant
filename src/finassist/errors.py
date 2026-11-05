class AssistantError(Exception):
    """Public errors contain a fixed code, never payload or credential values.

    Optional public details hold bounded, non-secret facts only, such as an
    option name and its allowed range. They never hold paths, contents or values.
    """

    def __init__(self, code: str, details: dict | None = None):
        self.code = code
        self.public_details = dict(details) if details else {}
        super().__init__(code)


def network_not_approved(allow_network: bool, approved: bool) -> AssistantError:
    """Name which of the two required network permissions is missing."""
    return AssistantError("network_not_approved",
                          {"allow_network": bool(allow_network), "allow_network_flag": bool(approved)})


def prices_required(prices: dict) -> AssistantError:
    """List every price field that must be set above zero."""
    return AssistantError("provider_prices_required", {"missing": sorted(k for k, v in prices.items() if v <= 0)})


class OperationOutcomeUnknown(AssistantError):
    """A mutation may have completed; retain the open audit run for reconciliation."""
