"""Public schema, CLI stream and documented boundary regressions."""

import argparse
from dataclasses import asdict, fields
import json
from pathlib import Path
import re

import jsonschema
import pytest

from finassist.cli import main, parser
from finassist.config import Config, load_config
from finassist.config_schema import configuration_schema, schema_text
from finassist.errors import AssistantError
from finassist.integrations import export_kit

ROOT = Path(__file__).resolve().parent.parent
CONFIG_EXAMPLES = ["offline", "dashboard", "anthropic", "compatible", "google", "openai", "ollama", "fork-config"]


def test_schema_is_generated_from_every_config_field_and_shipped_in_sync():
    text = schema_text()
    assert (ROOT / "schemas/finassist.schema.json").read_text(encoding="utf-8") == text
    assert (ROOT / "src/finassist/resources/finassist.schema.json").read_text(encoding="utf-8") == text
    schema = configuration_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    assert set(schema["properties"]) == {item.name for item in fields(Config)} | {"$schema"}
    defaults = json.loads(json.dumps(asdict(Config())))
    jsonschema.validate(defaults, schema)
    for name, value in defaults.items():
        assert schema["properties"][name]["default"] == value


@pytest.mark.parametrize("name", CONFIG_EXAMPLES)
def test_examples_have_working_editor_reference_and_remain_cli_loadable(name):
    path = ROOT / "examples" / (name + ".json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert (path.parent / data["$schema"]).resolve() == ROOT / "schemas/finassist.schema.json"
    jsonschema.validate(data, configuration_schema())
    load_config(path)


@pytest.mark.parametrize("data", [{"max_file_bytes": True}, {"daily_budget_usd": -1}, {"unknown": 1}, {"provider": "google"}, {"readiness_max_age_seconds": 2_000_001}, {"recipes": {"unit": []}}])
def test_schema_rejects_structural_and_basic_policy_errors(data):
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, configuration_schema())


def test_editor_hint_never_fetches_and_cannot_override_runtime_policy(tmp_path, monkeypatch):
    import urllib.request

    def refuse(*args, **kwargs):
        pytest.fail("config loading must not fetch the schema hint")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"$schema": "https://schema.example.invalid/config.json"}), encoding="utf-8", newline="\n")
    assert load_config(path) == Config()
    path.write_text(json.dumps({"$schema": "../schema.json", "allow_paths": ["../outside/"]}), encoding="utf-8", newline="\n")
    with pytest.raises(AssistantError):
        load_config(path)
    path.write_text('{"$schema": {}}', encoding="utf-8", newline="\n")
    with pytest.raises(AssistantError, match="invalid_schema_hint"):
        load_config(path)


def test_exported_examples_resolve_the_packaged_schema(tmp_path):
    destination = tmp_path / "kit"
    export_kit(destination)
    example = destination / "examples/fork-config.json"
    data = json.loads(example.read_text(encoding="utf-8"))
    schema_path = (example.parent / data["$schema"]).resolve()
    assert schema_path == destination / "schemas/finassist.schema.json"
    jsonschema.validate(data, json.loads(schema_path.read_text(encoding="utf-8")))
    load_config(example)


def test_documented_commands_track_parser_and_real_exit_streams(capsys, tmp_path):
    commands = next(action.choices for action in parser()._actions if isinstance(action, argparse._SubParsersAction))
    documentation = (ROOT / "docs/cli-contracts.md").read_text(encoding="utf-8")
    assert set(re.findall(r"^\| `([a-z-]+)` \|", documentation, re.MULTILINE)) == set(commands)
    assert main(["demo"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"
    bad = tmp_path / "invalid.json"
    bad.write_text("{}", encoding="utf-8", newline="\n")
    assert main(["finance-check", "--kind", "cash", "--input", str(bad)]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error == {"status": "error", "code": "invalid_input", "kind": "TypeError"}
    with pytest.raises(SystemExit) as usage:
        main(["not-a-command"])
    assert usage.value.code == 2 and "usage:" in capsys.readouterr().err


def test_threat_model_test_evidence_paths_exist():
    documentation = (ROOT / "docs/threat-model.md").read_text(encoding="utf-8")
    references = re.findall(r"`((?:tests|scripts|dashboard)/[^`]+\.(?:py|tsx|ts))`", documentation)
    assert len(references) >= 12
    assert all((ROOT / path).is_file() for path in references)
