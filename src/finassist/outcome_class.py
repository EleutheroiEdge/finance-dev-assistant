"""What a gate report's verdict means for the change: pass, fail, incomplete, refused or not_applicable.

Verdicts and exit codes stay as they are; adopters wire those into required checks. `outcome_class` names which kind
of stop a BLOCKED report is:
- `refused`: every reason is a rule that stopped this change on purpose, a content or privacy screen, an edit to a
  governance file, a size, count or budget limit, the fork rule, or nothing left to review. A person decides, or the
  change or the policy changes;
- `incomplete`: anything else. The review did not run to a result: a provider failure, an invalid or empty reply, an
  outcome or spend not reconciled, a setup problem. Rerun once it is fixed.
A reason not listed here is `incomplete`, so a new code can never read as a pass and never claims that a rule
stopped the change. A report with a refused reason beside an incomplete one is `incomplete`.
"""

from __future__ import annotations

CLASSES = ("pass", "fail", "incomplete", "refused", "not_applicable")

# Rule stops on the change itself. Each is an error code that has a hint (tests/test_outcome_class.py checks that).
REFUSED = frozenset({
    # content and privacy screens
    "sensitive_content", "hidden_characters", "project_content_blocked", "forbidden_token_present",
    "gate_key_in_source_context", "private_path", "private_or_binary_path", "private_profile_path",
    "gate_private_path", "review_scope_entirely_withheld", "gate_denied_path", "gate_path_not_allowed",
    "gate_ignored_path", "unsafe_path",
    # governance files the change edits, and the fork rule
    "gate_policy_change_requires_review", "gate_ignore_change_requires_review", "gate_profile_change_requires_review",
    "gate_fixture_marker_change_requires_review", "gate_fork_not_allowed",
    # limits and budgets
    "packet_limit_exceeded", "gate_request_bytes_exceeded", "gate_file_count_exceeded", "file_limit_exceeded",
    "packet_file_count_limit", "unsupported_file_type", "non_text_blob", "run_budget_exceeded",
    "daily_budget_exceeded", "monthly_budget_exceeded",
    # nothing left to review
    "empty_model_context", "empty_review_scope",
})


# The checks-only gate's rule stops: its pinned base policy stopped the change on purpose.
CI_REFUSED = frozenset({"ci_guarded_change_requires_review", "ci_check_budget_exceeded", "ci_model_review_required",
                        "ci_changes_absent", "ci_coverage_incomplete"})
# The reasons a run of checks that finished but did not pass reports.
CI_CHECK_FAILED = frozenset({"workflow_check_failed", "ci_checks_incomplete"})
# What ended a failed check, from its receipt. Only `nonzero_exit` means the check ran and said no.
CAUSES = ("nonzero_exit", "killed", "timed_out", "output_limit_exceeded", "unknown")


def check_cause(receipt) -> str:
    """Why a failed check failed, from its receipt; anything unreadable is `unknown`."""
    if not isinstance(receipt, dict):
        return "unknown"
    if receipt.get("timed_out") is True:
        return "timed_out"
    if receipt.get("output_limit_exceeded") is True:
        return "output_limit_exceeded"
    code = receipt.get("exit_code")
    if type(code) is int and code < 0:
        return "killed"
    if type(code) is int and code > 0:
        return "nonzero_exit"
    return "unknown"


def ci_outcome_class(status: str, reasons: list[str], causes: list[str]) -> str:
    """The class of a checks-only report. A failed run is `fail` only when every failed check exited nonzero; a
    timed-out, killed or overflowing check, or one whose cause is unknown, did not run to a result."""
    if status == "passed":
        return "pass"
    if status != "blocked":
        return "incomplete"
    if reasons and all(reason in CI_REFUSED for reason in reasons):
        return "refused"
    if reasons and set(reasons) <= CI_CHECK_FAILED and causes and all(cause == "nonzero_exit" for cause in causes):
        return "fail"
    return "incomplete"


def model_outcome_class(verdict: str, reasons: list[str], phase: str | None = None) -> str:
    """The class of a model-gate report from its verdict, reasons and, for BLOCKED, the phase that stopped it.

    `phase` is "reply" when the stop came while validating the model's reply. The output screens raise the same
    codes as the input screens, but there they mean the reply was unusable, so the review did not run to a result.
    """
    if verdict == "PASS":
        return "pass"
    if verdict == "FAIL":
        return "fail"
    if verdict == "NOT_APPLICABLE":
        return "not_applicable"
    if phase == "reply":
        return "incomplete"
    return "refused" if reasons and all(reason in REFUSED for reason in reasons) else "incomplete"
