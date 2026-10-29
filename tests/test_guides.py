"""Offline guide discovery works without a checkout, config or operational state."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from finassist.cli import main
from finassist.integrations import export_kit

ROOT = Path(__file__).resolve().parent.parent


def test_guides_are_offline_read_only_and_ignore_broken_config(tmp_path, monkeypatch, capsys):
    import socket

    def refuse(*args, **kwargs):
        pytest.fail("guides must not access the network or load operational configuration")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr("finassist.cli.load_config", refuse)
    monkeypatch.setattr("finassist.cli.command_audit", refuse)
    monkeypatch.chdir(tmp_path)
    assert main(["--config", "missing.json", "guide"]) == 0
    topics = json.loads(capsys.readouterr().out)["topics"]
    assert {row["topic"] for row in topics} >= {"agents", "configuration", "cli-contracts", "threat-model"}
    for row in topics:
        assert main(["guide", row["topic"]]) == 0
        text = capsys.readouterr().out
        assert text.startswith("# ") and "finledgerpoli" in text
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("topic", ["../SECURITY.md", "unknown", "configuration.md"])
def test_unknown_guide_cannot_read_arbitrary_paths(topic, capsys):
    assert main(["guide", topic]) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert json.loads(result.err) == {"status": "error", "code": "unknown_guide"}


def test_exported_guides_match_offline_guides(tmp_path, capsys):
    from finassist.guides import GUIDES

    destination = tmp_path / "kit"
    export_kit(destination)
    for topic, (title, source, _resource) in GUIDES.items():
        assert title
        assert main(["guide", topic]) == 0
        text = capsys.readouterr().out
        assert text == (ROOT / source).read_text(encoding="utf-8")
        assert text == (destination / source).read_text(encoding="utf-8")


def test_guide_stdout_is_utf8_lf_even_with_legacy_console_encoding(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "finassist", "guide", "agents"],
        cwd=tmp_path, capture_output=True, check=True, shell=False,
        env={**os.environ, "PYTHONIOENCODING": "ascii"},
    )
    assert result.stdout == (ROOT / "docs/agents.md").read_bytes()
    assert b"\r\n" not in result.stdout and result.stderr == b""
