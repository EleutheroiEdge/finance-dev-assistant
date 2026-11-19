"""JSON nested past the decoder's recursion limit is refused as invalid input on every route that reads it.

Python 3.13 decodes about 5,000 levels and 3.11 under 1,100, so each case nests well past both; the refusal must be a structured one, never a traceback.
"""

import http.client
import json

import pytest

from finassist.cli import main
from finassist.errors import AssistantError
from finassist.patching import rollback_patch
from test_dashboard import dashboard  # noqa: F401  (the fixture)
from test_init_detect import _proposal, _repo

DEPTH = 100_000


def _deep_array(depth: int = DEPTH) -> str:
    return "[" * depth + "]" * depth


def test_a_command_input_too_deep_to_decode_is_invalid_input(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    deep = tmp_path / "deep.json"
    deep.write_text('{"a": ' + _deep_array() + "}", encoding="utf-8", newline="\n")
    assert main(["finance-check", "--kind", "cash", "--input", str(deep)]) == 2
    error = json.loads(capsys.readouterr().err)
    assert (error["code"], error["kind"]) == ("invalid_input", "RecursionError")


def test_detection_warns_about_a_package_manifest_too_deep_to_decode(tmp_path, capsys):
    # 23,000 levels stay within the 48,000 bytes detection reads from one file.
    manifest = '{"scripts": ' + _deep_array(23_000) + "}"
    repo = _repo(tmp_path, {"src/app.py": "X = 1\n", "package.json": manifest})
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    assert {"code": "detect_file_unreadable", "path": "package.json"} in proposal["warnings"]


def test_the_dashboard_refuses_a_body_too_deep_to_decode(dashboard):  # noqa: F811
    state, server, _ = dashboard
    before = state.config_path.read_bytes()
    body = _deep_array(32_000).encode()  # within the 65,536-byte body limit
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=20)
    try:
        connection.request("POST", "/api/config/preview", body=body, headers={
            "Content-Type": "application/json", "X-Finassist-Token": state.token, "Origin": server.origin})
        response = connection.getresponse()
        assert (response.status, json.loads(response.read())) == (400, {"code": "invalid_request"})
    finally:
        connection.close()
    assert state.config_path.read_bytes() == before


def test_a_saved_patch_too_deep_to_decode_is_an_unavailable_backup(tmp_path):
    patches = tmp_path / ".finassist" / "patches"
    patches.mkdir(parents=True)
    name = "a" * 64
    (patches / (name + ".json")).write_text('{"before": ' + _deep_array() + "}", encoding="utf-8")
    (patches / (name + ".receipt.json")).write_text("{}", encoding="utf-8")
    with pytest.raises(AssistantError) as refused:
        rollback_patch(tmp_path, name)
    assert refused.value.code == "patch_backup_unavailable"
