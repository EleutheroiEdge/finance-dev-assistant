"""Figure sources are not available in this release, and cannot be turned on.

The strict reader that reads them is not released yet, so a configuration that sets `forbidden_token_sources` to
anything but an empty list, and a gate policy that holds the key at all, is refused as
`forbidden_token_sources_experimental` on every route, whatever else it sets, before any file is opened. Only code
turns the reader on, as its own tests do. Synthetic only."""

from dataclasses import replace
import json
from pathlib import Path
import re

import pytest

from conftest import command
from figure_source_cases import layout
from test_model_gate import gate_case, run, change_policy  # noqa: F401 - fixtures
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration

import finassist.figure_source_entries as figure_source_entries
import finassist.figure_sources as figure_sources
import finassist.forbidden_tokens as forbidden_tokens
from finassist.cli import main
from finassist.config import Config, config_hash, load_config
from finassist.config_preflight import config_preflight
from finassist.error_hints import error_fields, hints
from finassist.errors import AssistantError
from finassist.figure_source_entries import OPT_IN, SourceFormat
from finassist.figure_sources import SOURCE_RULE
from finassist.forbidden_tokens import TokenGuard
from finassist.model_policy import check_draft
from finassist.scope import config_token_guard
from finassist.security import canonical, digest

CODE = "forbidden_token_sources_experimental"
PACKAGE = Path(__file__).resolve().parents[1] / "src" / "finassist"
# A well-formed source: were it read, it would list its amount.
SOURCE = b"Name;Amount\nSYN-1;98.765,43\n"


@pytest.fixture
def source(tmp_path, monkeypatch):
    """A source on disk that any read would reach: reading it, or any source, fails the test."""
    path = tmp_path / "exports" / "positions.csv"
    path.parent.mkdir()
    path.write_bytes(SOURCE)

    def never(*_args, **_kwargs):
        raise AssertionError("a figure source was read")

    snapshot = forbidden_tokens.load_token_snapshot

    def snapshot_without_sources(rules, *args, **kwargs):
        if "forbidden_token_sources" in rules:
            never()
        return snapshot(rules, *args, **kwargs)

    monkeypatch.setattr(forbidden_tokens, "load_token_snapshot", snapshot_without_sources)
    monkeypatch.setattr(figure_sources, "read_source", never)
    monkeypatch.setattr(figure_sources, "source_amounts", never)
    return str(path)


def _shapes(path):
    """name: (forbidden_token_sources, the opt-in or None for none)"""
    declared = layout(path, text_columns=["Name"])
    return {
        "layouts-opted-in": ([declared], True),
        "layouts": ([declared], None),
        "layouts-opted-out": ([declared], False),
        "bare-path-opted-in": ([path], True),
        "bare-path": ([path], None),
        "one-object-opted-in": (declared, True),
        "true-opted-in": (True, True),
        "number-opted-in": (123, True),
        "empty-list-opted-in": ([], True),
    }


SHAPES = sorted(_shapes("/synthetic/positions.csv"))


def _settings(source, name):
    sources, opted = _shapes(source)[name]
    return {"forbidden_token_sources": sources, **({} if opted is None else {OPT_IN: opted})}


def _in_code(value):
    if isinstance(value, list):
        return tuple(SourceFormat(**{**item, "text_columns": tuple(item["text_columns"])})
                     if isinstance(item, dict) else item for item in value)
    return value


def test_the_shipped_switch_is_off_and_only_code_reads_it():
    assert figure_source_entries.SOURCES_AVAILABLE is False
    # No setting, variable or option reads it: the name appears only where it is defined and where it is consulted.
    named = {path.name: path.read_text(encoding="utf-8") for path in PACKAGE.rglob("*.py")
             if "SOURCES_AVAILABLE" in path.read_text(encoding="utf-8")}
    assert set(named) == {"figure_source_entries.py", "onboarding.py"}
    entries = named["figure_source_entries.py"]
    assert re.findall(r"^SOURCES_AVAILABLE\b.*$", entries, re.M) == ["SOURCES_AVAILABLE = False"]
    assert entries.count("SOURCES_AVAILABLE") == 2 and "environ" not in entries and "getenv" not in entries
    assert named["onboarding.py"].count("SOURCES_AVAILABLE") == 1
    for path in PACKAGE.rglob("*.py"):  # nor in any other spelling, as a setting or option name would be
        text = path.read_text(encoding="utf-8")
        assert text.lower().count("sources_available") == text.count("SOURCES_AVAILABLE")
    for path in PACKAGE.rglob("*.json"):
        assert "sources_available" not in path.read_text(encoding="utf-8").lower()


@pytest.mark.parametrize("name", [name for name in SHAPES if not name.startswith("empty-list")])
def test_a_configuration_listing_sources_is_refused_on_every_route(name, source, tmp_path, repository, capsys):
    settings = _settings(source, name)
    with pytest.raises(AssistantError, match=f"^{CODE}$"):
        load_config(content=json.dumps(settings).encode())
    in_code = {"forbidden_token_sources": _in_code(settings["forbidden_token_sources"])}
    if OPT_IN in settings:
        in_code[OPT_IN] = settings[OPT_IN]
    with pytest.raises(AssistantError, match=f"^{CODE}$"):
        Config(**in_code).validate()
    unvalidated = replace(Config(), **in_code)
    with pytest.raises(AssistantError, match=f"^{CODE}$"):
        config_token_guard(unvalidated, tmp_path)
    repo, base, head = repository
    report = config_preflight(repo, base, head, unvalidated)
    assert report["status"] == "blocked" and [item["code"] for item in report["blockers"]][:1] == [CODE]
    path = tmp_path / "finassist.json"
    path.write_text(json.dumps(settings), encoding="utf-8")
    assert main(["--config", str(path), "doctor"]) == 2
    record = json.loads(capsys.readouterr().err)
    assert record["code"] == CODE and "forbidden_token_file" in record["hint"]


def test_an_empty_list_in_a_configuration_is_the_default(source):
    assert config_hash(load_config(content=b'{"forbidden_token_sources": []}')) == config_hash(Config())
    assert config_hash(Config(forbidden_token_sources=[]).validate()) == config_hash(Config())
    assert "forbidden_token_sources" not in load_config(content=b'{"forbidden_token_sources": []}').forbidden_token_rules


@pytest.mark.parametrize("value", [False, 0, "", {}, None], ids=["false", "zero", "empty-text", "empty-object", "null"])
def test_any_other_value_in_a_configuration_is_refused_by_the_same_name(value):
    with pytest.raises(AssistantError, match=f"^{CODE}$"):
        load_config(content=json.dumps({"forbidden_token_sources": value}).encode())
    with pytest.raises(AssistantError, match=f"^{CODE}$"):
        Config(forbidden_token_sources=value).validate()


@pytest.mark.parametrize("name", SHAPES)
def test_the_guard_itself_refuses_every_shape(name, source):
    with pytest.raises(AssistantError, match=f"^{CODE}$"):
        TokenGuard.load(_settings(source, name), ())


@pytest.mark.parametrize("name", SHAPES)
def test_a_gate_policy_holding_the_key_is_refused_on_every_route(name, source, gate_case, tmp_path, capsys):  # noqa: F811
    settings = {**_settings(source, name), "forbidden_token_source_rule": SOURCE_RULE}
    document = model_policy()
    document["model_review"].update(settings)
    with pytest.raises(AssistantError, match=f"^{CODE}$"):
        check_draft(document)
    policy = tmp_path / "policy.json"
    policy.write_bytes(canonical(document))
    main(["doctor", "--policy-file", str(policy), "--repo", str(gate_case["repo"]), "--base", gate_case["base"],
          "--head", gate_case["head"], "--policy-sha256", digest(canonical(document))])
    report = json.loads(capsys.readouterr().out)
    first = report["blockers"][0]
    assert (first["code"], first["field"]) == (CODE, "/model_review/forbidden_token_sources")
    assert "does not offer it" in first["hint"] and "forbidden_token_file" in first["hint"]
    # The setting's value is not judged further: the one refusal names it.
    assert not [item for item in report["blockers"] if item["field"].startswith("/model_review/forbidden_token_sources")
                and item["code"] != CODE]
    change_policy(gate_case, **{OPT_IN: None, **settings})
    report, calls = run(gate_case)
    assert not calls and report["reasons"] == [CODE] and report["spend"]["reserved_usd"] is None


def test_the_refusal_says_not_available_and_what_to_do_instead():
    hint = error_fields(CODE)["hint"]
    assert "does not offer it" in hint and "even with forbidden_token_sources_experimental set to true" in hint
    assert "forbidden_token_file" in hint and "forbidden_token_hashes" in hint
    assert "not available in this release and cannot be turned on" in hints()[CODE]["summary"]


def test_init_detect_proposes_no_figure_source(tmp_path, capsys):
    repo = tmp_path / "repository"
    repo.mkdir()
    command(repo, "init", "-q", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    (repo / "src").mkdir()
    (repo / "src/app.py").write_text("def total(a, b):\n    return a + b\n", encoding="utf-8")
    (repo / "tests/fixtures").mkdir(parents=True)
    (repo / "tests/fixtures/positions.csv").write_text("Name;Amount\nSYN-1;12.345,67\n", encoding="utf-8")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic layout")
    assert main(["--audit-dir", str(tmp_path / "audit"), "init", "--detect", "--repo", str(repo)]) == 0
    proposal = json.loads(capsys.readouterr().out)
    drafted = canonical({"config": proposal["config"], "policy": proposal["gate_policy_draft"]}).decode()
    assert "forbidden_token" not in drafted
