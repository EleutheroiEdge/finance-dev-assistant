class AssistantError(Exception):
    """Public errors contain a fixed code, never payload or credential values."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class OperationOutcomeUnknown(AssistantError):
    """A mutation may have completed; retain the open audit run for reconciliation."""
