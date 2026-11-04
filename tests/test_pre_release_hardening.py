"""Synthetic boundary regressions for the five pre-release review follow-ups."""
from dataclasses import replace
from pathlib import Path

import pytest

from finassist.errors import AssistantError
from finassist.model_policy import _profile_lines
from finassist.policy_fixtures import PolicyFixtureConfig, fixture_settings
from finassist.security import check_model_path
from test_ci_gate import base_policy, gate
from test_gate_profiles import profile_case
from test_model_gate import change_policy, run
from test_policy_text_fixtures import candidate

pytest_plugins = ("test_model_gate", "test_model_policy", "test_ci_gate")


@pytest.mark.parametrize("codepoint", [
    0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D,
    0x180F, 0x2800, 0x3164, 0xFFA0, 0xFE00, 0xFE0F, 0xE0100, 0xE01EF,
    0xE000, 0xF0000, 0x0378, 0xD800, 0xDFFF, 0x00A0, 0x2007, 0x202F,
])
def test_invisible_profile_characters_fail_with_line_error(codepoint):
    with pytest.raises(AssistantError, match="^gate_profile_line_invalid$"):
        _profile_lines(["Check" + chr(codepoint) + "rounding."])


@pytest.mark.parametrize("line", ["Check \ufe00\ufe01 rounding.", "Check \U000e0100 rounding.", "Check \ud800 rounding."])
def test_hidden_inline_text_never_reaches_fake_provider(gate_case, line):
    change_policy(gate_case, profile_text=[line])
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_profile_line_invalid"] and not calls


@pytest.mark.parametrize("separator", ["\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029", "\r", "\t"])
def test_file_profiles_preserve_physical_lines_before_validation(gate_case, separator):
    profile_case(gate_case, raw=("Check rounding." + separator + "Trace totals.\n").encode())
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_profile_line_invalid"] and not calls


def test_control_only_file_lines_are_not_silently_discarded(gate_case):
    profile_case(gate_case, raw=b"Check rounding.\n\t\n")
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_profile_line_invalid"] and not calls


def test_visible_combining_text_and_crlf_remain_supported(gate_case):
    profile_case(gate_case, raw="Check cafe\u0301 costs and Δ totals.\r\n \r\nTrace ¥ amounts.\r\n".encode())
    report, calls = run(gate_case)
    assert report["verdict"] == "PASS" and len(calls) == 1


@pytest.mark.parametrize("separator", ["\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029", "\r\n"])
def test_marker_first_line_is_lf_exact(gate_case, separator):
    candidate(gate_case, "synthetic/.finledgerpoli-synthetic", ("synthetic: true" + separator + "junk\n").encode())
    change_policy(gate_case, fixture_roots=["synthetic/"])
    report, calls = run(gate_case)
    assert report["reasons"] == ["fixture_root_unqualified"] and not calls


@pytest.mark.parametrize("folder", ["data", "client", "private"])
def test_fixture_policy_keeps_ordinary_v1_snapshot_paths(ci_case, tmp_path, dispatch, monkeypatch, folder):
    import finassist.workflow_execution as execution
    name = folder + "/algorithm.py"
    candidate(ci_case, name, b"# Synthetic source, not private records.\n")
    def options(policy):
        policy.update(fixture_roots=["tests/fixtures/"], guard_paths=[])
        policy["config"]["allow_paths"] = [*policy["config"]["allow_paths"], folder + "/"]
    base_policy(ci_case, options)
    candidate(ci_case, "tests/fixtures/prices.csv")
    ci_case["context"] = replace(ci_case["context"], head_sha=ci_case["head"])
    original = execution.run_recipe
    seen = []
    def inspect(config, recipe, snapshot, **kwargs):
        seen.append((snapshot / name).read_bytes())
        return original(config, recipe, snapshot, **kwargs)
    monkeypatch.setattr(execution, "run_recipe", inspect)
    assert gate(ci_case, tmp_path)["status"] == "passed"
    assert dispatch == ["unit", "cash"] and len(seen) == 2


@pytest.mark.parametrize("part,reason", [
    ("data.", "fixture_root_contains_data"), ("data ", "fixture_root_contains_data"),
    ("ＤＡＴＡ", "fixture_root_contains_data"), ("ｄａｔａ．", "fixture_root_contains_data"),
    ("client.", "gate_private_path"), ("ｃｌｉｅｎｔ", "gate_private_path"),
    ("household ", "gate_private_path"), ("ｈｏｕｓｅｈｏｌｄ", "gate_private_path"),
    ("private.", "gate_private_path"), ("ｐｒｉｖａｔｅ", "gate_private_path"),
    ("tests.", "fixture_root_invalid"), ("ｔｅｓｔｓ", "fixture_root_invalid"),
    ("fixtures ", "fixture_root_invalid"), ("ｆｉｘｔｕｒｅｓ", "fixture_root_invalid"),
])
def test_reserved_aliases_refused_in_roots_and_fixture_candidates(part, reason):
    root = "tests/" + part + "/"
    with pytest.raises(AssistantError, match="^" + reason + "$"):
        fixture_settings(Path("."), "0" * 40, {"fixture_roots": [root]})
    with pytest.raises(AssistantError, match="^" + reason + "$"):
        PolicyFixtureConfig(fixture_roots=("tests/",)).check_path(root + "one.csv")


def test_model_paths_still_refuse_private_components_without_fixture_opt_in():
    for name in ("data/logic.py", "ｄａｔａ/logic.py", "client./logic.py", "private /logic.py"):
        with pytest.raises(AssistantError, match="^gate_private_path$"):
            check_model_path(name)
