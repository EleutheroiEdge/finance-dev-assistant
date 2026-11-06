"""#69 batch 2: version floors on development builds, surfaced Action output codes, bundle JSON codes.

All inputs are synthetic.
"""

import json

import pytest

from finassist import github_actions
from finassist.config import load_config
from finassist.config_compat import ConfigCompatibilityError, check_min_version, installed_order
from finassist.errors import AssistantError
from finassist.workflow_packs import read_bundle


@pytest.mark.parametrize("installed, meets", [
    ("0.8.0", True), ("0.8.1", True), ("0.8.0.post1", True), ("0.8.0+local.7", True),
    ("0.9.0.dev3", True), ("0.9.0rc1+g1234567", True), ("1.0.0", True),
    ("0.8.0.dev1", False), ("0.8.0rc1", False), ("0.8.0a2", False), ("0.7.9", False), ("0.7.10.post2", False),
])
def test_a_development_or_local_build_is_compared_by_its_release(monkeypatch, installed, meets):
    monkeypatch.setattr("finassist.config_compat.installed_version", lambda: installed)
    if meets:
        check_min_version("0.8.0")
        assert load_config(content=b'{"min_version":"0.8.0"}').provider == "offline"
    else:
        with pytest.raises(ConfigCompatibilityError) as error:
            check_min_version("0.8.0")
        # The configuration is valid: the code says to upgrade, never that min_version is malformed.
        assert error.value.code == "minimum_version_required"
        assert error.value.public_details["installed_version"] == installed


@pytest.mark.parametrize("installed", ["", "unknown", "v0.8.0", "08.0.0", "0.8"])
def test_an_installed_version_without_a_release_never_meets_a_floor(monkeypatch, installed):
    monkeypatch.setattr("finassist.config_compat.installed_version", lambda: installed)
    assert installed_order(installed) is None
    with pytest.raises(ConfigCompatibilityError, match="minimum_version_required"):
        check_min_version("0.1.0")


def test_the_floor_itself_must_still_be_plain_release_digits():
    with pytest.raises(AssistantError, match="invalid_min_version"):
        load_config(content=b'{"min_version":"0.8.0.dev1"}')


@pytest.mark.parametrize("code", ["ci_output_path_invalid", "ci_report_invalid"])
def test_action_output_codes_reach_the_caller(monkeypatch, capsys, code):
    def refuse(environment):
        raise AssistantError(code)

    monkeypatch.setattr(github_actions, "_run_github_action", refuse)
    assert github_actions.run_github_action({}) == 2
    assert json.loads(capsys.readouterr().out) == {"status": "error", "code": code}


def test_other_action_failures_keep_the_generic_code(monkeypatch, capsys):
    def refuse(environment):
        raise AssistantError("ci_state_unresolved")

    monkeypatch.setattr(github_actions, "_run_github_action", refuse)
    assert github_actions.run_github_action({}) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "ci_action_output_unavailable"


@pytest.mark.parametrize("content", [b'{"schema_version": 1, "schema_version": 1}', b'{"limit": NaN}'])
def test_a_bundle_with_duplicate_keys_or_nan_reports_a_bundle_code(tmp_path, content):
    path = tmp_path / "bundle.json"
    path.write_bytes(content)
    with pytest.raises(AssistantError) as error:
        read_bundle(path)
    assert error.value.code == "workflow_bundle_invalid"
