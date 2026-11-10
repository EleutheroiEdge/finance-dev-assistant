"""Bound built-in scanning on adversarial synthetic tokens without dropping suffixes."""
import subprocess
import sys

import pytest

from finassist.errors import AssistantError
from finassist.security import check_text


@pytest.mark.parametrize("label", [
    "api_key", "secret_key", "aws_secret_access_key", "password", "secret", "access_token", "gh_token", "github_enterprise_token",
    "account_number", "routing_number",
])
@pytest.mark.parametrize("prefix", ["", "a-" * 3000, "prefix_", "-", "X-Custom-"])
def test_long_and_prefixed_sensitive_assignments_remain_detected(label, prefix):
    value = "123456789" if "number" in label else "x" * 24
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text(prefix + label + ' = "' + value + '"')


@pytest.mark.alone
def test_policy_sized_hyphenated_tokens_scan_in_bounded_time():
    # Time only scans inside the child; imports/startup are outside the2s bound.
    # A10s subprocess timeout prevents a regression hanging the whole test runner.
    code = """
from time import perf_counter
from finassist.security import check_text
from finassist.errors import AssistantError
start = perf_counter()
for token in ("a-", "a_", "password-", "account-number-"):
    text = (token * (128000 // len(token)))[:128000]
    check_text(text)
    for label, value in (("api_key", "x" * 24), ("access_key", "x" * 24), ("account_number", "123456789")):
        try:
            check_text(text + label + ' = "' + value + '"')
        except AssistantError as exc:
            assert exc.code == "sensitive_content"
        else:
            raise AssertionError("suffix assignment was missed")
for token in ("key=", "key:", "access_key=", "access_key:"):
    text = (token * (128000 // len(token) + 1))[:128000] + "("
    try:
        check_text(text)
    except AssistantError as exc:
        assert exc.code == "sensitive_content"
print(perf_counter() - start)
"""
    completed = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                               check=True, timeout=10)
    assert float(completed.stdout.strip()) < 2.0


@pytest.mark.parametrize("expression", ["os.environ.get(placeholder)", "resolve_credential ()"])
def test_generic_key_reference_call_is_not_a_literal_assignment(expression):
    check_text("key = " + expression)


@pytest.mark.parametrize("label", ["access_key", "secret_key", "aws_secret_access_key"])
def test_unquoted_key_suffix_literal_remains_detected(label):
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text(label + "=" + "synthetic-" + "x" * 20)


@pytest.mark.parametrize("text", [
    "key = record.transaction_id", "partition_key = event.account_id",
    'idempotency_key = request.headers["Idempotency-Key"]',
    'account_id: int = Field(foreign_key="portfolio_account.id")',
    'primary_key = "transaction_id"', 'cache_key = "portfolio-snapshot-v2"',
    '{"key": "ledger.balance.label"}', "signing_key: CryptographicKeyMaterial",
    "encryption_key = config.key_material", "access_key = resolve_credential()",
])
def test_ordinary_finance_keys_and_credential_references_pass(text):
    check_text(text)


@pytest.mark.parametrize("suffix", [" (rotated monthly)", "(", ""])
def test_non_identifier_credential_literals_remain_screened(suffix):
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text("aws_secret_access_key=" + "synthetic/" + "x" * 20 + suffix)


def test_lowercase_unquoted_secret_literal_remains_screened():
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text("secret_" + "key=" + "x" * 24)
