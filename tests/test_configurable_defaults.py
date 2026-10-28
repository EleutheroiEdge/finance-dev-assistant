from dataclasses import asdict, replace
import json
from pathlib import Path
import subprocess

import httpx
import pytest

from conftest import command
from finassist.config import Config, load_config, save_config
from finassist.errors import AssistantError
from finassist.evaluation import evaluate
from finassist.github_audit import inspect_github
from finassist.patching import apply_patch_artifact, rollback_patch
from finassist.review import review_packet, validate_review
from finassist.scope import build_packet, triage, verify_packet
from finassist.security import DENIED_PARTS, TEXT_SUFFIXES, canonical, digest
from finassist.workspace import export_snapshot
from test_providers_review import model_config, envelope


@pytest.mark.parametrize("suffix", [".py", ".tf", ".cs"])
def test_fork_path_policy_reaches_plan_review_snapshot_patch_and_rollback(repository, tmp_path, suffix):
    repo, _, _ = repository
    path = repo / ("src/portfolios/model" + suffix)
    path.parent.mkdir()
    path.write_text("value = 1\n", encoding="utf-8", newline="\n")
    command(repo, "add", "src/portfolios")
    command(repo, "commit", "-m", "Synthetic fork baseline")
    base = command(repo, "rev-parse", "HEAD")
    path.write_text("value = 2\n", encoding="utf-8", newline="\n")
    command(repo, "add", "src/portfolios")
    command(repo, "commit", "-m", "Synthetic fork candidate")
    config = replace(
        Config(),
        denied_parts=tuple(sorted(DENIED_PARTS - {"portfolios"})),
        text_suffixes=tuple(sorted(TEXT_SUFFIXES | {".tf", ".cs"})),
    )
    with pytest.raises(AssistantError, match="private_path"):
        build_packet(repo, base, "HEAD", Config())
    packet = build_packet(repo, base, "HEAD", config)
    verify_packet(packet, config)
    assert triage(packet, config)["coverage_complete"]
    assert review_packet(packet, config, tmp_path / "audit.db")["status"] == "offline-analysis"
    validate_review(
        {
            "head": packet["head"],
            "summary": "Synthetic",
            "findings": [],
            "reviewed_paths": [path.relative_to(repo).as_posix()],
        },
        packet,
        config=config,
    )
    manifest = export_snapshot(repo, "HEAD", tmp_path / "snapshot", config)
    assert any(row["path"] == path.relative_to(repo).as_posix() for row in manifest["files"])
    path.write_text("value = 3\n", encoding="utf-8", newline="\n")
    patch = command(repo, "diff") + "\n"
    path.write_text("value = 2\n", encoding="utf-8", newline="\n")
    artifact = {"head": packet["head"], "patch": patch, "summary": "Synthetic change"}
    approved = digest(canonical(artifact))
    apply_patch_artifact(repo, artifact, approved, config)
    assert path.read_text(encoding="utf-8") == "value = 3\n"
    rollback_patch(repo, approved)
    assert path.read_text(encoding="utf-8") == "value = 2\n"
    suite = {
        "version": 1,
        "cases": [
            {
                "id": "fork",
                "path": path.relative_to(repo).as_posix(),
                "before": "value = 1\n",
                "after": "value = 2\n",
                "expected_defect": False,
            }
        ],
    }
    assert len(evaluate(suite, config, tmp_path / "eval")["cases"]) == 1


def test_profile_files_are_relative_data_and_content_bound(tmp_path, monkeypatch, repository):
    source = tmp_path / "profiles/custom.json"
    source.parent.mkdir()
    source.write_text(
        json.dumps({"custom": ["Inspect synthetic invariant Ω."]}), encoding="utf-8", newline="\n"
    )
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"profile": "custom", "profile_files": ["profiles/custom.json"]}),
        encoding="utf-8",
        newline="\n",
    )
    monkeypatch.chdir(repository[0])
    config = load_config(path)
    assert "Inspect synthetic invariant Ω." in config.instructions()
    assert "cannot execute tools" in config.instructions()
    before = digest(canonical(asdict(config)))
    save_config(tmp_path / "saved.json", config)
    source.write_text(
        json.dumps({"custom": ["Inspect a changed invariant."]}), encoding="utf-8", newline="\n"
    )
    loaded = load_config(tmp_path / "saved.json")
    assert digest(canonical(asdict(loaded))) != before
    assert "changed invariant" in loaded.instructions()


def test_model_uses_loaded_custom_checklist(repository, tmp_path, monkeypatch):
    repo, base, _ = repository
    config = replace(
        model_config(), profile="custom", profiles={**Config().profiles, "custom": ["Check synthetic Ω."]}
    )
    packet = build_packet(repo, base, "HEAD", config)
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")

    def reply(request):
        assert "Check synthetic Ω." in json.loads(request.content)["instructions"]
        return httpx.Response(
            200,
            json=envelope(
                json.dumps(
                    {
                        "head": packet["head"],
                        "summary": "Synthetic",
                        "reviewed_paths": ["src/cash.py"],
                        "findings": [],
                    }
                )
            ),
        )

    result = review_packet(
        packet,
        config,
        tmp_path / "audit.db",
        network_approved=True,
        approved_packet_hash=packet["packet_hash"],
        transport=httpx.MockTransport(reply),
    )
    assert result["config_hash"] == digest(canonical(asdict(config)))


def test_enterprise_metadata_goes_only_to_configured_host(monkeypatch):
    hosts = []
    enterprise_value = "fictional-enterprise"
    monkeypatch.setenv("GH_TOKEN", "fictional-public")
    monkeypatch.setenv("GH_ENTERPRISE_TOKEN", enterprise_value)

    def get(argv, **kwargs):
        hosts.append(argv[-1])
        assert argv[-2:] == ["--hostname", "git.example.com"]
        assert kwargs["env"]["GH_ENTERPRISE_TOKEN"] == enterprise_value
        assert "GH_TOKEN" not in kwargs["env"]
        endpoint = argv[2]
        if endpoint.endswith("/protection"):
            return subprocess.CompletedProcess(argv, 1, json.dumps({"status": "404"}), "")
        value = (
            []
            if "/rules/" in endpoint
            else (
                {"name": "main", "protected": False, "commit": {"sha": "a" * 40}}
                if "/branches/" in endpoint
                else {"full_name": "example/repository"}
            )
        )
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    monkeypatch.setattr("finassist.github_audit.shutil.which", lambda _: "gh")
    monkeypatch.setattr("finassist.github_audit.subprocess.run", get)
    report = inspect_github(
        "example/repository",
        "main",
        replace(Config(), allow_network=True, github_host="git.example.com"),
        network_approved=True,
    )
    assert hosts == ["git.example.com"] * 5 and report["host"] == "git.example.com"


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("denied_parts", ["../data"], "invalid_denied_parts"),
        ("denied_parts", [], "required_denied_parts_missing"),
        ("text_suffixes", ["cs"], "invalid_text_suffixes"),
        ("text_suffixes", [".cs", ".cs"], "invalid_text_suffixes"),
        ("github_host", "https://git.example.com", "invalid_github_host"),
        ("github_host", "--hostname=other", "invalid_github_host"),
        ("github_host", "git..example.com", "invalid_github_host"),
        ("profiles", {"general": []}, "invalid_profile_checklist"),
        ("profile", "missing", "unknown_profile"),
        ("profile_files", [None], "invalid_profile_files"),
    ],
)
def test_invalid_configuration_has_specific_errors(field, value, code):
    with pytest.raises(AssistantError, match=code):
        replace(Config(), **{field: value}).validate()


def test_profile_file_failures_are_bounded_and_do_not_execute(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"profile_files": ["missing.json"]}), encoding="utf-8", newline="\n")
    with pytest.raises(AssistantError, match="profile_file_unavailable"):
        load_config(path)
    source = tmp_path / "profile.json"
    source.write_text("[]", encoding="utf-8", newline="\n")
    path.write_text(json.dumps({"profile_files": ["profile.json"]}), encoding="utf-8", newline="\n")
    with pytest.raises(AssistantError, match="duplicate_or_invalid_profile_file"):
        load_config(path)
    source.write_text(json.dumps({"custom": ["Bounded data"]}), encoding="utf-8", newline="\n")
    path.write_text(
        json.dumps({"profile_files": ["profile.json", "profile.json"]}), encoding="utf-8", newline="\n"
    )
    with pytest.raises(AssistantError, match="duplicate_or_invalid_profile_file"):
        load_config(path)


def test_configuration_example_round_trips():
    config = load_config(Path(__file__).parents[1] / "examples/fork-config.json")
    assert (
        "portfolios" not in config.denied_parts
        and ".tf" in config.text_suffixes
        and ".cs" in config.text_suffixes
    )
    assert config.profile == "engineering" and config.github_host == "git.example.com"
