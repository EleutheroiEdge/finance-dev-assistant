"""Exercise installed CI policy gates with synthetic source and optional real OCI checks."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from finassist.platform_support import find_tool
from finassist.scope import git_environment
from finassist.security import canonical, digest

ROOT = Path(__file__).resolve().parents[1]


def exercise_ci_gate(image: str, *, run_checks: bool) -> dict:
    with tempfile.TemporaryDirectory(prefix="finassist-ci-smoke-") as temporary:
        outer = Path(temporary)
        repo = outer / "repository"
        shutil.copytree(ROOT / "examples/github-actions/fixture", repo)

        def git(*args):
            return subprocess.check_output([find_tool("git"), "-c", "core.hooksPath=" + os.devnull, "-C", str(repo), *args],
                                           env=git_environment(), text=True, encoding="utf-8").strip()

        git("init", "-b", "main")
        git("config", "user.name", "Synthetic CI")
        git("config", "user.email", "ci@example.invalid")
        git("config", "core.autocrlf", "false")
        git("remote", "add", "origin", "https://github.com/example/financial-engine.git")
        policy = json.loads((ROOT / "examples/github-actions/finassist-ci.json").read_text(encoding="utf-8"))
        policy["config"]["runner_image"] = image
        policy["review"] = "not-requested" if run_checks else "required"
        raw = canonical(policy) + b"\n"
        (repo / "finassist-ci.json").write_bytes(raw)
        (repo / ".gitignore").write_text(".finassist/\n", encoding="utf-8", newline="\n")
        git("add", ".")
        git("commit", "-m", "Synthetic approved policy and checks")
        base = git("rev-parse", "HEAD")
        source = repo / "src/cash.py"
        source.write_text(source.read_text(encoding="utf-8") + "\n# Synthetic candidate\n", encoding="utf-8", newline="\n")
        git("add", "src/cash.py")
        git("commit", "-m", "Synthetic CI candidate")

        def evaluate(expected_exit):
            event = {"action": "synchronize", "number": 7, "repository": {"full_name": policy["repository"]},
                     "pull_request": {"number": 7, "base": {"ref": "main", "sha": base,
                                                            "repo": {"full_name": policy["repository"]}},
                                      "head": {"sha": git("rev-parse", "HEAD"),
                                               "repo": {"full_name": policy["repository"]}}}}
            event_path = outer / "event.json"
            event_path.write_bytes(canonical(event))
            done = subprocess.run([
                sys.executable, "-I", "-m", "finassist", "ci", "gate", "--repo", str(repo), "--event", str(event_path),
                "--event-name", "pull_request", "--repository", policy["repository"], "--policy-sha256", digest(raw),
                "--state-dir", str(repo / ".finassist/state"),
            ], cwd=outer, capture_output=True, text=True, encoding="utf-8", check=False)
            if done.returncode != expected_exit:
                raise AssertionError("Synthetic CI smoke returned an unexpected exit code")
            return json.loads(done.stdout)

        first = evaluate(0 if run_checks else 1)
        if not run_checks:
            assert first["blocking_reasons"] == ["ci_model_review_required"]
            assert not (repo / ".finassist/state").exists()
            return {"ci_policy_refusal_smoke": "PASS", "model_called": False, "checks_run": False}
        assert first["status"] == "passed" and first["checks"]["completed"] == 2
        source.write_text(source.read_text(encoding="utf-8").replace("opening + deposits - fees", "opening - deposits - fees"),
                          encoding="utf-8", newline="\n")
        git("add", "src/cash.py")
        git("commit", "-m", "Seed synthetic deposit-sign defect")
        failed = evaluate(1)
        assert failed["status"] == "blocked" and "workflow_check_failed" in failed["blocking_reasons"]
        return {"ci_container_gate_smoke": "PASS", "seeded_cash_defect_blocked": True, "model_called": False}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/ci_gate_smoke.py PINNED_PREPARED_IMAGE")
    print(json.dumps(exercise_ci_gate(sys.argv[1], run_checks=True)))
