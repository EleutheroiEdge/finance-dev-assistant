"""Synthetic regressions for issue47 items12–14; provider IO is always fake."""
from pathlib import Path

import pytest

from conftest import command
from finassist.errors import AssistantError
from finassist.model_policy import _profile_lines
from finassist.policy_fixtures import PolicyFixtureConfig, fixture_settings
from finassist.security import DENIED_PARTS, check_model_path, check_path
from test_gate_profiles import profile_case
from test_model_gate import change_policy, run

pytest_plugins = ("test_model_gate", "test_model_policy")


@pytest.mark.parametrize("codepoint", [0x13441, 0x13442, 0x16FE4, 0x1BC9D])
@pytest.mark.parametrize("file_profile", [False, True])
def test_blank_profile_fillers_never_dispatch_or_reserve(gate_case, codepoint, file_profile):
    line = "Check" + chr(codepoint) + "rounding."
    if file_profile:
        profile_case(gate_case, raw=(line + "\n").encode())
    else:
        change_policy(gate_case, profile_text=[line])
    report, calls = run(gate_case)
    assert report["reasons"] == ["gate_profile_line_invalid"] and not calls
    assert not (gate_case["state"] / "audit.sqlite").exists()


@pytest.mark.parametrize("part,reason", [
    ("dat\u0430", "fixture_root_contains_data"),
    ("cl\u0456ent", "gate_private_path"),
    ("clie\u039dt", "gate_private_path"),
    ("CL\u0406ENT", "gate_private_path"),
    ("\u0441redentials", "private_path"),
    ("\u0455ecrets", "private_path"),
    ("h\u03bfldings", "private_path"),
])
def test_cross_script_reserved_paths_refuse_roots_and_candidates(part, reason):
    root = "tests/" + part + "/"
    with pytest.raises(AssistantError, match="^" + reason + "$"):
        fixture_settings(Path("."), "0" * 40, {"fixture_roots": [root]})
    with pytest.raises(AssistantError, match="^" + reason + "$"):
        PolicyFixtureConfig(fixture_roots=("tests/",)).check_path(root + "one.csv")


@pytest.mark.parametrize("codepoint", [0x200B, 0x034F, 0x115F, 0xFE0F, 0xE0001, 0x13441])
def test_hidden_path_components_refuse_source_roots_and_fixtures(codepoint):
    part = "da" + chr(codepoint) + "ta"
    for operation in (
        lambda: check_model_path(part + "/logic.py"),
        lambda: check_path("src/" + part + "/logic.py"),
        lambda: fixture_settings(Path("."), "0" * 40, {"fixture_roots": [part + "/"]}),
        lambda: PolicyFixtureConfig(fixture_roots=("tests/",)).check_path("tests/" + part + "/one.csv"),
    ):
        with pytest.raises(AssistantError, match="^unsafe_path$"):
            operation()


@pytest.mark.parametrize("part", sorted(DENIED_PARTS))
@pytest.mark.parametrize("tail", [".", " .", " "])
def test_denied_components_keep_ntfs_aliases_private(part, tail):
    with pytest.raises(AssistantError, match="^private_path$"):
        check_path(part + tail + "/logic.py", source_only=False)


@pytest.mark.parametrize("name,reason", [
    ("auth.json.", "private_profile_path"), ("AUTH.JSON ", "private_profile_path"),
    ("memory.md .", "private_profile_path"), ("client.json.", "gate_private_path"),
    ("credentials.json ", "gate_private_path"), ("cl\u0456ent.json", "gate_private_path"),
])
def test_private_filenames_use_reserved_alias_comparison(name, reason):
    with pytest.raises(AssistantError, match="^" + reason + "$"):
        check_model_path("src/" + name, source_only=False)


@pytest.mark.parametrize("name", ["src/dat\u0430/logic.py", "src/da\u200bta/logic.py"])
def test_alias_candidates_never_dispatch_or_reserve(gate_case, name):
    target = gate_case["repo"] / name
    target.parent.mkdir(parents=True)
    target.write_text("# Synthetic public source.\n", encoding="utf-8")
    command(gate_case["repo"], "add", "--", name)
    command(gate_case["repo"], "commit", "-m", "Synthetic aliased candidate")
    gate_case["head"] = command(gate_case["repo"], "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
    assert not (gate_case["state"] / "audit.sqlite").exists()


@pytest.mark.parametrize("root", ["Tests/fixtures/", "src/App.Tests/Fixtures/"])
def test_case_aliases_do_not_qualify_fixture_roots(root):
    with pytest.raises(AssistantError, match="^fixture_root_invalid$"):
        fixture_settings(Path("."), "0" * 40, {"fixture_roots": [root]})


@pytest.mark.parametrize("text", ["Check \u2764\ufe0f totals.", "Check 1\ufe0f\u20e3 totals.", "Check \U0001f469\u200d\U0001f4bb totals."])
def test_selector_and_joiner_emoji_sequences_are_refused(text):
    with pytest.raises(AssistantError, match="^gate_profile_line_invalid$"):
        _profile_lines([text])


def test_visible_unicode_and_custom_source_denylist_remain_supported():
    for name in ("src/caf\u00e9/\u5206\u6790.py", "src/cafe\u0301.py", "src/\U0001f600.py"):
        assert check_model_path(name) == name
    assert _profile_lines(["Check cafe\u0301, Δ and \U0001f600 totals; keycap 1\u20e3."])
    assert check_path("holdings/logic.py", denied_parts=set()) == "holdings/logic.py"
    with pytest.raises(AssistantError, match="^private_path$"):
        check_path("Custom ./logic.py", denied_parts={"CUSTOM"})
