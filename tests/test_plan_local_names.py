"""plan names the paths it refuses, for the person at this machine only, and reports settings with no effect."""

from dataclasses import replace
import json

import pytest

from conftest import command
from finassist import scope
from finassist.cli import main
from finassist.errors import LOCAL_NAMING_COMMANDS
from finassist.config import Config, save_config
from finassist.errors import AssistantError
from finassist.scope import build_packet

FIXTURES = {f"tests/fixtures/prices/p{index:02}.csv": "date,close\n2026-01-02,100.00\n" for index in range(3)}
DATA = {"data/legacy_master.csv": "id,name\n1,Synthetic Security\n"}


@pytest.fixture
def csv_range(repository):
    """A synthetic range that changes code, three price fixtures and a data file."""
    repo, base, _head = repository
    for name, text in {**FIXTURES, **DATA}.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
    (repo / "src/cash.py").write_text("def balance(opening, deposits):\n    return opening + deposits + 0\n",
                                      encoding="utf-8", newline="\n")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic range with CSV files")
    return repo, base, command(repo, "rev-parse", "HEAD")


@pytest.fixture
def reads(monkeypatch):
    seen = []
    real = scope.read_entry

    def spy(repo, sha, path, *args, **kwargs):
        seen.append(path)
        return real(repo, sha, path, *args, **kwargs)

    monkeypatch.setattr(scope, "read_entry", spy)
    return seen


def plan(capsys, tmp_path, repo, base, head, config=None):
    path = tmp_path / "finassist.json"
    save_config(path, config or Config())
    code = main(["--config", str(path), "--audit-dir", str(tmp_path / "audit"), "plan", "--repo", str(repo),
                 "--base", base, "--head", head, "--output", str(tmp_path / "plan.json")])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_plan_names_every_refused_path_locally_before_reading_any_file(csv_range, tmp_path, capsys, reads):
    repo, base, head = csv_range
    code, _out, err = plan(capsys, tmp_path, repo, base, head)
    record = json.loads(err)
    assert code == 2 and record["status"] == "error"
    assert record["refused_count"] == 4
    groups = {group["code"]: group for group in record["local"]["refused_paths"]}
    assert sum(group["count"] for group in groups.values()) == 4
    named = sorted(name for group in groups.values() for name in group["paths"])
    assert named == sorted([*FIXTURES, *DATA])
    assert record["code"] in groups  # The first refusal's code leads the record.
    assert reads == []  # No file was read: names are checked first.
    assert not (tmp_path / "plan.json").exists()


def test_public_fields_and_the_audit_log_never_hold_a_refused_name(csv_range, tmp_path, capsys):
    repo, base, head = csv_range
    _code, _out, err = plan(capsys, tmp_path, repo, base, head)
    record = json.loads(err)
    public = json.dumps({key: value for key, value in record.items() if key != "local"})
    assert not any(part in public for part in ("p00", "p01", "p02", "legacy_master", "fixtures/prices"))
    stored = b"".join(path.read_bytes() for path in (tmp_path / "audit").rglob("*") if path.is_file())
    assert stored  # The run was audited...
    assert b"p00" not in stored and b"legacy_master" not in stored  # ...without any name.


def test_a_name_that_fails_screening_is_redacted(csv_range, tmp_path, capsys):
    repo, base, head = csv_range
    config = replace(Config(), extra_sensitive_patterns=("legacy_master",))
    _code, _out, err = plan(capsys, tmp_path, repo, base, head, config)
    record = json.loads(err)
    named = [name for group in record["local"]["refused_paths"] for name in group["paths"]]
    assert "[redacted]" in named and not any("legacy_master" in name for name in named)


def test_a_read_refusal_names_its_file_locally(repository, tmp_path, capsys):
    repo, base, head = repository
    _code, _out, err = plan(capsys, tmp_path, repo, base, head, replace(Config(), max_file_bytes=10))
    record = json.loads(err)
    assert record["code"] == "file_limit_exceeded" and record["local"] == {"path": "src/cash.py"}
    assert "cash" not in json.dumps({key: value for key, value in record.items() if key != "local"})


def test_many_refusals_keep_twenty_names_per_code(repository, tmp_path):
    repo, base, _head = repository
    for index in range(25):
        name = repo / f"tests/fixtures/many/f{index:02}.csv"
        name.parent.mkdir(parents=True, exist_ok=True)
        name.write_text("a,b\n1,2\n", encoding="utf-8", newline="\n")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic range with many CSV files")
    with pytest.raises(AssistantError) as caught:
        build_packet(repo, base, command(repo, "rev-parse", "HEAD"), Config())
    (group,) = caught.value.local_details["refused_paths"]
    assert group["count"] == 25 and len(group["paths"]) == 20
    assert caught.value.public_details["refused_count"] == 25


def test_plan_summary_reports_settings_with_no_effect(repository, tmp_path, capsys):
    repo, base, head = repository
    config = replace(Config(), text_suffixes=(*Config().text_suffixes, ".csv"))
    code, out, _err = plan(capsys, tmp_path, repo, base, head, config)
    summary = json.loads(out.splitlines()[-1])
    assert code == 0
    assert [(item["code"], item["suffix"]) for item in summary["config_warnings"]] == [
        ("text_suffix_always_denied", ".csv")]


def test_a_refusal_carries_the_settings_that_explain_it(csv_range, tmp_path, capsys):
    repo, base, head = csv_range
    config = replace(Config(), text_suffixes=(*Config().text_suffixes, ".csv"))
    _code, _out, err = plan(capsys, tmp_path, repo, base, head, config)
    warnings = json.loads(err)["local"]["config_warnings"]
    assert {"code": "text_suffix_always_denied", "suffix": ".csv"}.items() <= warnings[0].items()


def test_a_clean_plan_adds_no_warnings(repository, tmp_path, capsys):
    repo, base, head = repository
    code, out, _err = plan(capsys, tmp_path, repo, base, head)
    assert code == 0 and "config_warnings" not in json.loads(out.splitlines()[-1])


def test_only_local_commands_print_local_names():
    assert LOCAL_NAMING_COMMANDS == {"plan", "watch"}


def test_skip_and_report_still_withholds_instead_of_refusing(csv_range, tmp_path, capsys):
    repo, base, head = csv_range
    code, out, _err = plan(capsys, tmp_path, repo, base, head, replace(Config(), private_paths="skip-and-report"))
    summary = json.loads(out.splitlines()[-1])
    assert code == 0 and sorted(summary["withheld_paths"]) == sorted([*FIXTURES, *DATA])
