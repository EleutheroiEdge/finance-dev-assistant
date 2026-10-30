"""Version floors and explicit migrations never rewrite configuration during load."""

from dataclasses import asdict
import json
from pathlib import Path

import pytest

from finassist.cli import main
from finassist.config import Config, load_config
from finassist.config_compat import (
    ConfigCompatibilityError, DeprecatedOption, apply_config_migration,
    preview_config_migration, unknown_option, OPTION_INTRODUCED,
)
from finassist.errors import AssistantError
from finassist.health import doctor_report


def test_version_floor_precedes_unknown_fields_profiles_and_option_validation(tmp_path, monkeypatch):
    monkeypatch.setattr("finassist.config_compat.installed_version", lambda: "0.5.0")
    path = tmp_path / "config.json"
    original = b'{"min_version":"0.6.0","future_option":true,"provider":42,"profile_files":["missing.json"]}\n'
    path.write_bytes(original)
    with pytest.raises(ConfigCompatibilityError) as error:
        load_config(path)
    assert error.value.code == "minimum_version_required"
    assert error.value.public_details["required_version"] == "0.6.0"
    assert path.read_bytes() == original
    assert "future_option" not in str(error.value.public_details)


def test_min_floor_is_optional_and_cli_error_has_safe_upgrade_hint(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("finassist.config_compat.installed_version", lambda: "0.5.0")
    assert load_config(content=b'{"min_version":"0.4.0"}').provider == "offline"
    assert Config().min_version == "" and not Config().allow_network
    path = tmp_path / "config.json"
    path.write_text('{"min_version":"0.6.0","private_value":"DO-NOT-ECHO"}', encoding="utf-8")
    assert main(["--config", str(path), "doctor"]) == 2
    output = capsys.readouterr()
    data = json.loads(output.err)
    assert data["code"] == "minimum_version_required" and "Upgrade" in data["upgrade_hint"]
    assert "DO-NOT-ECHO" not in output.err + output.out


@pytest.mark.parametrize("value", [True, None, 0.5, "0.5", "v0.5.0", "0.5.0\n", "01.0.0", "../0.5.0"])
def test_invalid_floor_is_rejected(value):
    with pytest.raises(AssistantError, match="invalid_min_version"):
        load_config(content=json.dumps({"min_version": value}).encode())


def test_unknown_key_names_upgrade_hint_and_known_introduction(monkeypatch):
    with pytest.raises(ConfigCompatibilityError) as error:
        load_config(content=b'{"future_switch":"DO-NOT-ECHO"}')
    assert error.value.code == "unknown_config_option"
    assert error.value.public_details["option"] == "future_switch"
    assert "Upgrade" in error.value.public_details["upgrade_hint"]
    assert "DO-NOT-ECHO" not in str(error.value.public_details)
    monkeypatch.setitem(OPTION_INTRODUCED, "future_switch", "0.6.0")
    assert unknown_option("future_switch").public_details["introduced_in"] == "0.6.0"
    assert unknown_option("unsafe\nname").public_details["option"] == "(redacted)"


@pytest.fixture
def synthetic_rename(monkeypatch):
    from finassist.config_compat import DEPRECATED_OPTIONS

    monkeypatch.setitem(DEPRECATED_OPTIONS, "old_profile", DeprecatedOption("profile", "0.5.0", "0.7.0"))


def test_deprecated_alias_warns_and_does_not_change_file_or_semantic_document(tmp_path, synthetic_rename):
    path = tmp_path / "config.json"
    before = b'{\n  "old_profile": "general"\n}\n'
    path.write_bytes(before)
    with pytest.warns(FutureWarning, match="old_profile.*profile"):
        config = load_config(path)
    assert config.profile == "general" and path.read_bytes() == before
    assert "old_profile" not in asdict(config)
    assert doctor_report(config)["deprecated_config_options"] == [
        {"option": "old_profile", "replacement": "profile", "remove_after": "0.7.0"},
    ]


def test_explicit_migration_shows_diff_and_keeps_exact_original_bytes(tmp_path, synthetic_rename):
    path = tmp_path / "config.json"
    before = b'{\r\n  "old_profile" : "general"\r\n}\r\n'
    path.write_bytes(before)
    plan = preview_config_migration(path)
    assert plan.report()["changed"] and '"profile"' in plan.diff
    assert path.read_bytes() == before and len(list(tmp_path.iterdir())) == 1
    result = apply_config_migration(plan)
    assert result["written"]
    assert json.loads(path.read_bytes()) == {"profile": "general"}
    assert Path(result["backup"]).read_bytes() == before


def test_no_op_preserves_whitespace_and_creates_no_backup(tmp_path):
    path = tmp_path / "config.json"
    before = b'{ "profile" : "general" }\r\n'
    path.write_bytes(before)
    plan = preview_config_migration(path)
    assert not plan.report()["changed"] and not plan.diff
    assert not apply_config_migration(plan)["written"]
    assert path.read_bytes() == before and len(list(tmp_path.iterdir())) == 1


def test_stale_plan_and_alias_conflict_are_refused(tmp_path, synthetic_rename):
    path = tmp_path / "config.json"
    path.write_text('{"old_profile":"general"}', encoding="utf-8")
    plan = preview_config_migration(path)
    path.write_text('{"profile":"finance-saas"}', encoding="utf-8")
    with pytest.raises(AssistantError, match="config_changed_during_migration"):
        apply_config_migration(plan)
    assert len(list(tmp_path.iterdir())) == 1
    with pytest.raises(AssistantError, match="deprecated_option_conflict"):
        load_config(content=b'{"old_profile":"general","profile":"general"}')


def test_short_rename_window_and_duplicate_json_are_refused(monkeypatch):
    from finassist.config_compat import DEPRECATED_OPTIONS

    monkeypatch.setitem(DEPRECATED_OPTIONS, "old_profile", DeprecatedOption("profile", "0.5.0", "0.6.0"))
    with pytest.raises(AssistantError, match="invalid_deprecation_window"):
        load_config(content=b'{"old_profile":"general"}')
    with pytest.raises(AssistantError, match="config_duplicate_key"):
        load_config(content=b'{"profile":"general","profile":"finance-saas"}')


def test_cli_migrate_dry_run_has_no_writes_then_apply_has_exact_backup(tmp_path, synthetic_rename, capsys):
    path = tmp_path / "config.json"
    before = b'{ "old_profile" : "general" }\r\n'
    path.write_bytes(before)
    args = ["--audit-dir", str(tmp_path / "private-audit"), "config", "migrate", "--path", str(path)]
    assert main(args + ["--dry-run"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["changed"] and not report["written"] and report["diff"]
    assert path.read_bytes() == before and len(list(tmp_path.iterdir())) == 1
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["written"] and Path(report["backup"]).read_bytes() == before
    assert (tmp_path / "private-audit/audit.sqlite").exists()


@pytest.mark.parametrize("raw", [b'{"unfinished":', b'\xff'])
def test_migration_library_has_fixed_errors_for_malformed_input(tmp_path, raw):
    path = tmp_path / "config.json"
    path.write_bytes(raw)
    with pytest.raises(AssistantError, match="invalid_config"):
        preview_config_migration(path)
    assert path.read_bytes() == raw


def test_cli_refuses_ambiguous_config_paths(tmp_path, capsys):
    assert main(["--config", str(tmp_path / "first.json"), "config", "migrate", "--path", str(tmp_path / "second.json")]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "config_migration_path_ambiguous"
    assert list(tmp_path.iterdir()) == []
