import ast
from dataclasses import replace
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
import tempfile

import pytest
import yaml

from conftest import command
from finassist.config import Config, load_config
from finassist.errors import AssistantError
from finassist.ledger import Ledger
from finassist.patching import apply_patch_artifact
from finassist.platform_support import clean_environment, find_tool, read_utf8, private_state_protection
from finassist.runner import run_bounded, run_recipe
from finassist.scope import build_packet
from finassist.security import canonical, digest


def test_utf8_crlf_config_and_source_hashes(repository, tmp_path):
    config_path = tmp_path / "configuration.json"
    config_path.write_bytes(b'{\r\n"profile": "general"\r\n}\r\n')
    assert load_config(config_path).profile == "general"
    path = tmp_path / "example.txt"
    path.write_bytes("Ω\r\nnext\r\n".encode("utf-8"))
    assert read_utf8(path) == "Ω\nnext\n"
    repo, base, _ = repository
    (repo / "src/unicode.py").write_bytes("value = 'Ω'\r\n".encode("utf-8"))
    command(repo, "add", "src/unicode.py")
    command(repo, "commit", "-m", "Synthetic UTF-8 and CRLF source")
    packet = build_packet(repo, base, "HEAD", Config())
    entry = next(file for file in packet["files"] if file["path"] == "src/unicode.py")
    assert entry["after_hash"] == digest("value = 'Ω'\r\n".encode("utf-8"))


@pytest.mark.parametrize("tool", ["git", "gh", "docker", "podman"])
def test_tool_discovery_is_native_and_batch_shims_are_refused(monkeypatch, tool):
    monkeypatch.setattr("finassist.platform_support.shutil.which", lambda _: f"tools/{tool}.exe")
    assert find_tool(tool).endswith(".exe")
    monkeypatch.setattr("finassist.platform_support.shutil.which", lambda _: f"tools/{tool}.cmd")
    with pytest.raises(AssistantError, match="batch_tool_not_supported"):
        find_tool(tool)
    monkeypatch.setattr("finassist.platform_support.shutil.which", lambda _: None)
    with pytest.raises(AssistantError, match=tool + "_executable_missing"):
        find_tool(tool)


def test_unicode_space_paths_run_without_shell_and_without_provider_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    root = tmp_path / "space Ω"
    root.mkdir()
    script = root / "synthetic script.py"
    script.write_text("print('Ω')\n", encoding="utf-8", newline="\n")
    env = clean_environment()
    assert "OPENAI_API_KEY" not in env
    result = run_bounded([sys.executable, str(script)], cwd=root, env=env, timeout=5)
    assert result["passed"] and result["output"].strip() == "Ω"


def test_git_symlink_objects_are_rejected_without_native_symlink_privilege(repository, tmp_path):
    repo, base, _ = repository
    target = tmp_path / "target.txt"
    target.write_text("unavailable-target", encoding="utf-8", newline="\n")
    blob = command(repo, "hash-object", "-w", str(target))
    command(repo, "update-index", "--add", "--cacheinfo", "120000," + blob + ",src/link.py")
    command(repo, "commit", "-m", "Synthetic Git link object")
    with pytest.raises(AssistantError, match="linked_or_special_git_object"):
        build_packet(repo, base, "HEAD", Config())


def test_unrepresentable_mode_change_is_refused_without_mutation(repository, monkeypatch):
    repo, _, head = repository
    patch = "diff --git a/src/cash.py b/src/cash.py\nold mode 100644\nnew mode 100755\n"
    artifact = {"head": head, "patch": patch, "summary": "Synthetic mode change"}
    before = (repo / "src/cash.py").read_bytes()
    monkeypatch.setattr("finassist.patching.executable_modes_supported", lambda: False)
    with pytest.raises(AssistantError, match="executable_mode_change_not_supported"):
        apply_patch_artifact(repo, artifact, digest(canonical(artifact)), Config())
    assert (repo / "src/cash.py").read_bytes() == before


def test_sqlite_handles_close_before_unicode_temp_cleanup():
    with tempfile.TemporaryDirectory(prefix="finassist-platform-") as directory:
        root = Path(directory)
        path = root / "space Ω" / "audit.sqlite"
        with Ledger(path) as ledger:
            ledger.append({"event": "synthetic"})
            assert ledger.verify() == 1
        with Ledger(path) as reopened:
            assert reopened.verify() == 1
        source = root / "readonly.py"
        source.write_text("synthetic\n", encoding="utf-8", newline="\n")
        source.chmod(0o444)
    assert not root.exists()
    assert ("ACL" in private_state_protection()) is (os.name == "nt")


def test_no_subprocess_call_uses_a_shell_and_ci_covers_native_platforms():
    root = Path(__file__).parents[1]
    for source in (root / "src").rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        assert not any(
            isinstance(node, ast.keyword)
            and node.arg == "shell"
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
            for node in ast.walk(tree)
        )
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    rows = workflow["jobs"]["test"]["strategy"]["matrix"]["include"]
    assert {row["os"] for row in rows} == {"ubuntu-24.04", "windows-latest", "macos-latest"}
    assert {"test (3.11)", "test (3.12)", "test (3.13)"} <= {row["check_name"] for row in rows}
    assert workflow["jobs"]["isolation"]["runs-on"] == "ubuntu-24.04"


def test_docker_desktop_mount_uses_forward_slashes_and_a_literal_argument(tmp_path, monkeypatch):
    # Native Path.as_posix provides this representation on Windows.
    assert PureWindowsPath("C:/project with spaces/source").as_posix() == "C:/project with spaces/source"
    monkeypatch.setattr("finassist.platform_support.shutil.which", lambda _: "docker")

    def supervise(argv, **kwargs):
        mount = argv[argv.index("--mount") + 1]
        assert mount == f"type=bind,src={tmp_path.as_posix()},dst=/workspace,readonly"
        assert kwargs["env"]["DOCKER_CONFIG"] == str(Path.home() / ".docker")
        return {"passed": True, "output": "", "exit_code": 0}

    monkeypatch.setattr("finassist.runner.run_bounded", supervise)
    monkeypatch.setattr(
        "finassist.runner.subprocess.run",
        lambda argv, **_: subprocess.CompletedProcess(argv, 1 if "inspect" in argv else 0, b"", b""),
    )
    config = replace(Config(), runner_image="sha256:" + "a" * 64, recipes={"unit": ["python", "-V"]})
    assert run_recipe(config, "unit", tmp_path)["receipt"]["cleanup_verified"]
