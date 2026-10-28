from dataclasses import replace
import os

import pytest

from finassist.config import Config, load_config, save_config
from finassist.errors import AssistantError
from finassist.scope import build_packet, triage, verify_packet
from finassist.security import canonical, check_path, check_text, digest, regular_path, write_private
from finassist.workspace import export_snapshot
from conftest import command, synthetic_symlink


@pytest.mark.parametrize(
    "value", ["../src/file.py", "/etc/passwd", "src/../file.py", "src//file.py", "a\\b.py", "a:stream.py"]
)
def test_path_traversal_rejected(value):
    with pytest.raises(AssistantError):
        check_path(value)


@pytest.mark.parametrize(
    "value",
    [
        ".env",
        "config/.env.example",
        "data/holdings/example.json",
        "src/credentials/settings.json",
        "tests/example.xlsx",
    ],
)
def test_private_paths_are_not_source(value):
    with pytest.raises(AssistantError):
        check_path(value)


def test_renamed_sensitive_payload_is_rejected():
    text = "access_" + 'token = "' + "x" * 30 + '"'
    with pytest.raises(AssistantError, match="sensitive_content"):
        check_text(text)
    with pytest.raises(AssistantError, match="sensitive_content"):
        check_text("account_" + "number = " + "123456789")


def test_project_patterns_and_invalid_regex():
    with pytest.raises(AssistantError, match="project_content_blocked"):
        check_text("fictional client marker", extra_patterns=("client marker",))
    with pytest.raises(AssistantError, match="invalid_content_pattern"):
        check_text("text", extra_patterns=("[",))


def test_ancestor_link_rejected_even_for_missing_leaf(tmp_path):
    (tmp_path / "real").mkdir()
    synthetic_symlink(tmp_path / "linked", tmp_path / "real", target_is_directory=True)
    with pytest.raises(AssistantError, match="linked_path"):
        regular_path(tmp_path / "linked/missing/file.json")


def test_exclusive_outputs_never_overwrite(tmp_path):
    path = tmp_path / "report.json"
    write_private(path, b"first")
    with pytest.raises(AssistantError, match="output_exists"):
        write_private(path, b"second")
    assert path.read_bytes() == b"first"
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0


def test_scope_hashes_both_sides_and_ignores_uncommitted_changes(repository):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    (repo / "src/cash.py").write_text("uncommitted and not reviewed", encoding="utf-8", newline="\n")
    verify_packet(packet)
    assert "+ deposits" in packet["files"][0]["before"]
    assert "- deposits" in packet["files"][0]["after"]
    assert packet["head"] == head
    assert triage(packet)["risks"] == ["financial-correctness"]
    packet["files"][0]["after"] += "tamper"
    with pytest.raises(AssistantError, match="packet_integrity_failed"):
        verify_packet(packet)


def test_merge_base_does_not_invent_upstream_deletions(repository):
    repo, base, head = repository
    command(repo, "switch", "main")
    (repo / "docs").mkdir()
    (repo / "docs/upstream.md").write_text("Upstream-only addition", encoding="utf-8", newline="\n")
    command(repo, "add", "docs/upstream.md")
    command(repo, "commit", "-m", "Upstream addition")
    packet = build_packet(repo, "main", head, Config())
    assert packet["merge_base"] == base
    assert packet["changed_paths"] == ["src/cash.py"]


def test_coverage_omissions_are_explicit(repository):
    repo, base, head = repository
    packet = build_packet(repo, base, head, replace(Config(), allow_paths=("docs/",)))
    assert packet["omitted"] == [{"path": "src/cash.py", "reason": "outside_allowlist"}]
    assert not triage(packet, replace(Config(), allow_paths=("docs/",)))["coverage_complete"]


def test_git_symlink_is_never_followed(repository):
    repo, base, _ = repository
    synthetic_symlink(repo / "src/linked.py", "unavailable-target")
    command(repo, "add", "src/linked.py")
    command(repo, "commit", "-m", "Synthetic link")
    with pytest.raises(AssistantError, match="linked_or_special_git_object"):
        build_packet(repo, base, "HEAD", Config())


def test_size_limit_fails_closed(repository):
    repo, base, head = repository
    with pytest.raises(AssistantError, match="file_limit_exceeded"):
        build_packet(repo, base, head, replace(Config(), max_file_bytes=5))
    with pytest.raises(AssistantError, match="packet_limit_exceeded"):
        build_packet(repo, base, head, replace(Config(), max_packet_bytes=10))


def test_resealed_packet_cannot_hide_coverage(repository):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    packet["files"] = []
    packet["packet_hash"] = digest(canonical({k: v for k, v in packet.items() if k != "packet_hash"}))
    with pytest.raises(AssistantError, match="packet_coverage_invalid"):
        verify_packet(packet)


def test_snapshot_is_committed_screened_code(repository, tmp_path):
    repo, _, head = repository
    destination = tmp_path / "snapshot"
    result = export_snapshot(repo, head, destination, Config())
    assert result["head"] == head and len(result["files"]) == 1
    assert not (destination / ".git").exists()
    assert "- deposits" in (destination / "src/cash.py").read_text(encoding="utf-8")


def test_config_is_explicit_and_keys_do_not_choose_provider(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    assert load_config().provider == "offline"
    path = tmp_path / "config.json"
    save_config(path, Config())
    assert load_config(path) == Config()
    path.write_text(canonical({"unknown_field": True}).decode(), encoding="utf-8", newline="\n")
    with pytest.raises(AssistantError, match="unknown_config_option"):
        load_config(path)


@pytest.mark.parametrize(
    "config",
    [
        replace(Config(), provider="unknown"),
        replace(Config(), timeout_seconds=True),
        replace(Config(), max_run_usd=float("nan")),
        replace(Config(), provider="openai", model="selected", endpoint="http://api.openai.com/v1/responses"),
        replace(Config(), provider="openai", model="selected", endpoint="https://unknown.example/v1"),
        replace(
            Config(), provider="openai", model="selected", endpoint="https://name:password@api.openai.com/v1"
        ),
    ],
)
def test_invalid_configuration_rejected(config):
    with pytest.raises(AssistantError):
        config.validate()
