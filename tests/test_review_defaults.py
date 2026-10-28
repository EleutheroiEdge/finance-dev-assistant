"""Synthetic regressions for the configurable-defaults review."""

from dataclasses import replace
import json
import os
from pathlib import Path

import httpx
import pytest

from conftest import command
from finassist.cli import main
from finassist.config import Config, load_config, save_config
from finassist.errors import AssistantError
from finassist.github_audit import inspect_github
from finassist.patching import apply_patch_artifact, rollback_patch
from finassist.proposal import propose
from finassist.readiness import verify_gate
from finassist.scope import build_packet, verify_packet
from finassist.security import DENIED_PARTS, canonical, digest, check_text
from finassist.workspace import export_snapshot
from test_providers_review import envelope, model_config


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8", newline="\n")


@pytest.mark.parametrize(
    "name",
    [
        "../outside.json",
        "/outside.json",
        "~/profile.json",
        "C:/profile.json",
        "a/../profile.json",
        "secrets/profile.json",
        "profile.txt",
    ],
)
def test_profile_reference_paths_fail_before_loading(name):
    with pytest.raises(AssistantError):
        replace(Config(), profile_files=(name,)).validate()


def test_profile_sources_require_regular_nonempty_unique_files(tmp_path, monkeypatch):
    path, source = tmp_path / "config.json", tmp_path / "profile.json"
    write_json(path, {"profile_files": ["profile.json"]})
    write_json(source, {})
    with pytest.raises(AssistantError, match="duplicate_or_invalid_profile_file"):
        load_config(path)
    source.unlink()
    source.mkdir()
    with pytest.raises(AssistantError, match="profile_file_not_regular"):
        load_config(path)
    source.rmdir()
    if hasattr(os, "mkfifo"):
        os.mkfifo(source)
        original = Path.read_text

        def read_text(self, *args, **kwargs):
            assert self != source, "FIFO must be rejected before opening"
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", read_text)
        with pytest.raises(AssistantError, match="profile_file_not_regular"):
            load_config(path)


def test_symlink_traversal_is_rejected_before_collapsing_segments(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    write_json(tmp_path / "profile.json", {"custom": ["Synthetic checklist"]})
    write_json(tmp_path / "config.json", {"profile_files": ["link/../profile.json"]})
    with pytest.raises(AssistantError):
        load_config(tmp_path / "config.json")


def test_saved_profile_references_do_not_resurrect_deleted_definitions(tmp_path):
    write_json(tmp_path / "profile.json", {"custom": ["Synthetic checklist"]})
    write_json(tmp_path / "config.json", {"profile_files": ["profile.json"]})
    loaded = load_config(tmp_path / "config.json")
    save_config(tmp_path / "saved.json", loaded)
    write_json(tmp_path / "profile.json", {"other": ["Replacement checklist"]})
    assert "custom" not in load_config(tmp_path / "saved.json").profiles


def test_programmatic_profile_references_cannot_be_silently_ignored():
    with pytest.raises(AssistantError, match="profile_files_require_load_config"):
        replace(Config(), profile_files=("profile.json",)).validate()


def test_init_materializes_profiles_when_copying_configuration(tmp_path):
    write_json(tmp_path / "profile.json", {"custom": ["Synthetic checklist"]})
    path = tmp_path / "config.json"
    write_json(path, {"profile": "custom", "profile_files": ["profile.json"]})
    target = tmp_path / "copy/config.json"
    assert (
        main(["--config", str(path), "--audit-dir", str(tmp_path / "state"), "init", "--output", str(target)])
        == 0
    )
    loaded = load_config(target)
    assert loaded.profile == "custom" and loaded.profile_files == ()
    assert loaded.profiles["custom"] == ["Synthetic checklist"]


@pytest.mark.parametrize("host", ["127.0.0.1", "2130706433", "localhost", "::1"])
def test_github_host_rejects_ip_literals_and_single_labels(host):
    with pytest.raises(AssistantError, match="invalid_github_host"):
        replace(Config(), github_host=host).validate()


def test_public_github_tokens_never_reach_other_cloud_tenants(monkeypatch):
    monkeypatch.delenv("GH_ENTERPRISE_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_ENTERPRISE_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", "synthetic-public")
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-public")

    def run(argv, **kwargs):
        assert "GH_TOKEN" not in kwargs["env"] and "GITHUB_TOKEN" not in kwargs["env"]
        raise OSError("stop after inspecting the environment")

    monkeypatch.setattr("finassist.github_audit.shutil.which", lambda _: "gh")
    monkeypatch.setattr("finassist.github_audit.subprocess.run", run)
    with pytest.raises(AssistantError, match="github_metadata_unavailable"):
        inspect_github(
            "example/repository",
            "main",
            replace(Config(), github_host="tenant.ghe.com", allow_network=True),
            network_approved=True,
        )


@pytest.mark.parametrize("policy", ["profile", "allow_paths", "patterns"])
def test_packets_must_obey_the_active_policy(repository, policy):
    repo, base, _ = repository
    packet = build_packet(repo, base, "HEAD", Config())
    config = {
        "profile": replace(Config(), profile="general"),
        "allow_paths": replace(Config(), allow_paths=("tests/",)),
        "patterns": replace(Config(), extra_sensitive_patterns=("deposits",)),
    }[policy]
    with pytest.raises(AssistantError):
        verify_packet(packet, config)


def test_snapshot_omits_the_same_public_assets_as_plan(repository, tmp_path):
    repo, base, _ = repository
    (repo / "src/chart.png").write_bytes(b"synthetic image")
    command(repo, "add", "src/chart.png")
    command(repo, "commit", "-m", "Synthetic image")
    assert build_packet(repo, base, "HEAD", Config())["omitted"]
    snapshot = export_snapshot(repo, "HEAD", tmp_path / "snapshot", Config())
    assert "src/chart.png" not in {row["path"] for row in snapshot["files"]}


def test_rollback_honors_active_scope_before_any_write(repository):
    repo, _, head = repository
    target = repo / "src/cash.py"
    before = target.read_bytes()
    target.write_bytes(before.replace(b"opening - deposits", b"opening + deposits"))
    patch = command(repo, "diff") + "\n"
    target.write_bytes(before)
    artifact = {"head": head, "patch": patch, "summary": "Synthetic fix"}
    approved = digest(canonical(artifact))
    apply_patch_artifact(repo, artifact, approved, Config())
    changed = target.read_bytes()
    with pytest.raises(AssistantError):
        rollback_patch(repo, approved, replace(Config(), allow_paths=("tests/",)))
    assert target.read_bytes() == changed


@pytest.mark.parametrize("name", ["gh_token", "github_enterprise_token"])
def test_github_credential_assignments_are_screened(name):
    with pytest.raises(AssistantError, match="sensitive_content"):
        check_text(name + "=" + "fictional-value-for-screening")


@pytest.mark.parametrize("operation", ["plan", "watch", "scan"])
def test_cli_operations_propagate_custom_policy(repository, tmp_path, capsys, operation):
    repo, _, _ = repository
    target = repo / "src/portfolios/model.cs"
    target.parent.mkdir()
    target.write_text("class Model {}\n", encoding="utf-8", newline="\n")
    base = command(repo, "rev-parse", "HEAD")
    command(repo, "add", "src/portfolios/model.cs")
    command(repo, "commit", "-m", "Synthetic custom scope")
    config = replace(
        Config(),
        denied_parts=tuple(sorted(DENIED_PARTS - {"portfolios"})),
        text_suffixes=(*Config().text_suffixes, ".cs"),
    )
    path = tmp_path / "config.json"
    save_config(path, config)
    argv = ["--config", str(path), "--audit-dir", str(tmp_path / "state"), operation, "--repo", str(repo)]
    argv += ["--base", base] if operation != "scan" else []
    argv += ["--iterations", "1"] if operation == "watch" else []
    argv += ["--output", str(tmp_path / "packet.json")] if operation == "plan" else []
    assert main(argv) == 0
    assert '"private_path"' not in capsys.readouterr().out


def test_propose_uses_active_config_and_custom_profile(repository, tmp_path, monkeypatch):
    repo, base, head = repository
    config = replace(
        model_config(),
        profile="custom",
        profiles={**Config().profiles, "custom": ["Check synthetic invariant."]},
    )
    packet = build_packet(repo, base, head, config)
    before = (repo / "src/cash.py").read_bytes()
    (repo / "src/cash.py").write_bytes(before.replace(b"opening - deposits", b"opening + deposits"))
    patch = command(repo, "diff") + "\n"
    (repo / "src/cash.py").write_bytes(before)
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")

    def reply(request):
        assert "Check synthetic invariant." in json.loads(request.content)["instructions"]
        return httpx.Response(
            200, json=envelope(json.dumps({"head": head, "patch": patch, "summary": "Synthetic fix"}))
        )

    result = propose(
        packet,
        config,
        tmp_path / "audit.db",
        network_approved=True,
        approved_packet_hash=packet["packet_hash"],
        transport=httpx.MockTransport(reply),
    )
    assert result["artifact"]["patch"] == patch


def test_readiness_rejects_source_blocked_by_active_policy(repository, tmp_path):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    with pytest.raises(AssistantError, match="project_content_blocked"):
        verify_gate(
            packet,
            {},
            [],
            replace(Config(), extra_sensitive_patterns=("deposits",)),
            head,
            tmp_path / "audit.db",
        )


def test_packet_scope_identity_changes_even_when_all_files_still_fit(repository):
    repo, base, head = repository
    packet = build_packet(repo, base, head, Config())
    with pytest.raises(AssistantError, match="packet_allow_paths_mismatch"):
        verify_packet(packet, replace(Config(), allow_paths=(*Config().allow_paths, "other/")))


def test_duplicate_json_profile_names_are_not_silently_overwritten(tmp_path):
    (tmp_path / "profile.json").write_text(
        '{"custom":["First"],"custom":["Second"]}', encoding="utf-8", newline="\n"
    )
    write_json(tmp_path / "config.json", {"profile_files": ["profile.json"]})
    with pytest.raises(AssistantError, match="duplicate_or_invalid_profile_file"):
        load_config(tmp_path / "config.json")


def test_exported_configuration_examples_exist(tmp_path):
    import re
    from finassist.integrations import export_kit

    target = tmp_path / "kit"
    export_kit(target)
    guide = target / "docs/configuration.md"
    for link in re.findall(r"\]\((\.\./examples/[^)]+)\)", guide.read_text(encoding="utf-8")):
        assert (guide.parent / link).is_file()
