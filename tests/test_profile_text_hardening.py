"""Unambiguous policy instruction lines, using synthetic policy blobs only."""
import pytest

from finassist.errors import AssistantError
from finassist.model_policy import load_model_policy
from test_gate_profiles import profile_case
from test_model_gate import change_policy, run
from test_model_policy import model_policy

pytest_plugins = ("test_model_gate", "test_model_policy")


@pytest.mark.parametrize("line,reason", [
    ('Check rounding.\n', 'gate_profile_line_invalid'),
    ('Check\rrounding.', 'gate_policy_invalid'),
    ('Check\nrounding.', 'gate_policy_invalid'),
    ('Check\u2028rounding.', 'gate_profile_line_invalid'),
    ('Check\u2029rounding.', 'gate_profile_line_invalid'),
    ('Check\x85rounding.', 'gate_profile_line_invalid'),
    ('Check\x0brounding.', 'gate_profile_line_invalid'),
    ('Check\x0crounding.', 'gate_profile_line_invalid'),
    ('Check\x1crounding.', 'gate_profile_line_invalid'),
    ('Check\x1drounding.', 'gate_profile_line_invalid'),
    ('Check\x1erounding.', 'gate_profile_line_invalid'),
    ('Check\trounding.', 'gate_profile_line_invalid'),
    ('Check\x7frounding.', 'gate_profile_line_invalid'),
    ('Check\u200brounding.', 'gate_profile_line_invalid'),
    ('Check\u202erounding.', 'gate_profile_line_invalid'),
    ('\ufeff', 'gate_profile_line_invalid'),
    ('\u200b', 'gate_profile_line_invalid'),
    ('\u200d', 'gate_profile_line_invalid'),
    (' \ufeff ', 'gate_profile_line_invalid'),
    (' \u200b ', 'gate_profile_line_invalid'),
    ('   ', 'gate_profile_line_invalid'),
])
def test_inline_profile_rejects_hidden_lines_and_controls(policy_case, line, reason):
    document = model_policy()
    document["model_review"]["profile_text"] = [line]
    repo, base, pin = policy_case(document)
    with pytest.raises(AssistantError, match="^" + reason + "$"):
        load_model_policy(repo, base, "gate-policy.json", pin)


@pytest.mark.parametrize("line", ["\ufeff", "\u200b", "\u200d", " \ufeff "])
def test_file_profile_rejects_invisible_instruction_lines(gate_case, line):
    profile_case(gate_case, raw=(line + "\n").encode())
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_profile_line_invalid"] and not calls


def test_visible_unicode_instructions_are_preserved_exactly(gate_case):
    line = "Check café costs — reconcile ¥ amounts and Δ totals."
    change_policy(gate_case, profile_text=[line])
    policy = load_model_policy(gate_case["repo"], gate_case["base"], "gate-policy.json", gate_case["pin"])
    assert policy.config.profiles["finance-saas"] == [line]
    report, calls = run(gate_case)
    assert report["verdict"] == "PASS" and len(calls) == 1


def test_inline_text_counts_toward_policy_blob_cap(policy_case):
    document = model_policy()
    document["model_review"]["profile_text"] = ["x" * 2000] * 64
    repo, base, pin = policy_case(document)
    with pytest.raises(AssistantError, match="^file_limit_exceeded$"):
        load_model_policy(repo, base, "gate-policy.json", pin)
