from dataclasses import replace
import sys

import pytest

from finassist.config import Config
from finassist.errors import AssistantError
from finassist.patching import apply_patch_artifact, patch_paths, rollback_patch
from finassist.runner import run_bounded, run_recipe
from finassist.security import canonical, digest
from conftest import command


def artifact(repo, head):
    path = repo / "src/cash.py"
    original = path.read_text()
    path.write_text(original.replace("- deposits", "+ deposits"))
    patch = command(repo, "diff", "--no-ext-diff", "--no-textconv") + "\n"
    path.write_text(original)
    return {"head": head, "patch": patch, "summary": "Restore deposit conservation"}


def test_apply_approved_patch_and_safe_rollback(repository):
    repo, _, head = repository
    proposal = artifact(repo, head)
    approved = digest(canonical(proposal))
    receipt = apply_patch_artifact(repo, proposal, approved, Config())
    assert "+ deposits" in (repo / "src/cash.py").read_text()
    assert not receipt["committed"] and not receipt["tests_executed"]
    rollback_patch(repo, approved)
    assert "- deposits" in (repo / "src/cash.py").read_text()


def test_rollback_preserves_later_operator_work(repository):
    repo, _, head = repository
    proposal = artifact(repo, head)
    approved = digest(canonical(proposal))
    apply_patch_artifact(repo, proposal, approved, Config())
    (repo / "src/cash.py").write_text("later operator work")
    with pytest.raises(AssistantError, match="rollback_would_overwrite_later_work"):
        rollback_patch(repo, approved)
    assert (repo / "src/cash.py").read_text() == "later operator work"


def test_rollback_restores_original_executable_mode(repository):
    repo, _, _ = repository
    path = repo / "src/cash.py"
    path.chmod(0o755)
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-m", "Executable synthetic source")
    head = command(repo, "rev-parse", "HEAD")
    original = path.read_bytes()
    proposal = artifact(repo, head)
    approved = digest(canonical(proposal))
    apply_patch_artifact(repo, proposal, approved, Config())
    rollback_patch(repo, approved)
    assert path.read_bytes() == original
    assert path.stat().st_mode & 0o777 == 0o755
    assert command(repo, "status", "--porcelain") == ""


def test_rollback_refuses_later_permission_changes(repository):
    repo, _, head = repository
    proposal = artifact(repo, head)
    approved = digest(canonical(proposal))
    apply_patch_artifact(repo, proposal, approved, Config())
    (repo / "src/cash.py").chmod(0o755)
    with pytest.raises(AssistantError, match="rollback_would_overwrite_later_work"):
        rollback_patch(repo, approved)


def test_unapproved_stale_dirty_and_main_patches_fail(repository):
    repo, _, head = repository
    proposal = artifact(repo, head)
    approved = digest(canonical(proposal))
    with pytest.raises(AssistantError, match="patch_approval_mismatch"):
        apply_patch_artifact(repo, proposal, "wrong", Config())
    (repo / "untracked.txt").write_text("unrelated")
    with pytest.raises(AssistantError, match="clean_worktree_required"):
        apply_patch_artifact(repo, proposal, approved, Config())
    (repo / "untracked.txt").unlink()
    command(repo, "branch", "-m", "main-candidate")
    command(repo, "branch", "-D", "main")
    command(repo, "branch", "-m", "main")
    with pytest.raises(AssistantError, match="feature_branch_required"):
        apply_patch_artifact(repo, proposal, approved, Config())


@pytest.mark.parametrize(
    "path", ["../escape.py", ".github/workflows/check.yml", "LICENSE", "src/credentials/key.py"]
)
def test_patch_cannot_change_unapproved_paths(path):
    patch = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"
    with pytest.raises(AssistantError):
        patch_paths(patch, Config())


def test_bounded_runner_captures_failures_timeouts_and_overflow(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    result = run_bounded(
        [sys.executable, "-c", 'print("fictional"); raise SystemExit(2)'], cwd=tmp_path, env=env, timeout=2
    )
    assert result["exit_code"] == 2 and not result["passed"]
    result = run_bounded(
        [sys.executable, "-c", 'import time; print("partial", flush=True); time.sleep(10)'],
        cwd=tmp_path,
        env=env,
        timeout=0.15,
    )
    assert result["timed_out"] and "partial" in result["output"]
    result = run_bounded(
        [sys.executable, "-c", 'print("x" * 2000)'], cwd=tmp_path, env=env, timeout=2, max_bytes=100
    )
    assert result["output_limit_exceeded"] and not result["passed"]


def test_local_recipe_needs_explicit_approval(tmp_path):
    config = replace(Config(), recipes={"fake": [sys.executable, "-c", 'print("fictional check")']})
    with pytest.raises(AssistantError, match="local_execution_not_approved"):
        run_recipe(config, "fake", tmp_path, backend="local")
    assert run_recipe(config, "fake", tmp_path, backend="local", approve_local=True)["receipt"]["passed"]
    with pytest.raises(AssistantError, match="pinned_runner_image_required"):
        run_recipe(config, "fake", tmp_path, backend="docker")
