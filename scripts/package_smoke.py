"""Exercise the installed wheel from an isolated temporary project, without model calls."""

from importlib import metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import finassist
from finassist.platform_support import find_tool
from finassist.guides import GUIDES
from finassist.scope import git_environment

assert "site-packages" in str(Path(finassist.__file__).resolve()), finassist.__file__
if len(sys.argv) != 2:
    raise SystemExit("usage: python scripts/package_smoke.py EXAMPLES_DIRECTORY")
distribution = metadata.distribution("finledgerpoli")
assert distribution.metadata["Name"] == "finledgerpoli"
assert not any(str(entry).startswith("brand/") for entry in distribution.files)
images = [entry for entry in distribution.files if entry.suffix in {".png", ".svg", ".gif"}]
assert len(images) == 3 and all("finassist/resources/dashboard/assets/" in str(entry) for entry in images)
assert sorted(entry.suffix for entry in images) == [".png", ".svg", ".svg"]
assert finassist.installed_version() == distribution.version
examples = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="finassist-wheel-smoke-") as directory:
    root = Path(directory)

    def cli(*args, expected_exit=0):
        result = subprocess.run(
            [sys.executable, "-m", "finassist", *map(str, args)],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        assert result.returncode == expected_exit, (result.returncode, result.stderr)
        if expected_exit == 2:
            return json.loads(result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def git(*args):
        return subprocess.check_output(
            [find_tool("git"), "-c", "core.hooksPath=" + os.devnull, "-C", str(root), *args],
            env=git_environment(),
            text=True,
            encoding="utf-8",
        ).strip()

    for command in ("finassist", "finledgerpoli"):
        executable = Path(sys.executable).with_name(command + (".exe" if sys.platform == "win32" else ""))
        result = subprocess.run(
            [str(executable), "--version"], cwd=root, capture_output=True,
            text=True, encoding="utf-8", check=True, shell=False,
        )
        assert result.stdout.strip() == distribution.version, command
    assert cli("demo")[0]["status"] == "PASS"
    doctor = cli("doctor")[0]
    assert doctor["version"] == distribution.version
    assert doctor["provider"] == "offline" and not doctor["container_daemon_checked"]
    cli("init", "--output", root / "config.json")
    kit = cli("export-kit", "--output", root / "kit")[0]
    assert not kit["installed_into_host"]
    topics = cli("guide")[0]["topics"]
    assert {row["topic"] for row in topics} == set(GUIDES)
    for topic, (_, source, _) in GUIDES.items():
        result = subprocess.run(
            [sys.executable, "-m", "finassist", "guide", topic],
            cwd=root, capture_output=True, check=True, shell=False,
        )
        assert result.stdout == (root / "kit" / source).read_bytes()
    git("init", "-b", "main")
    git("config", "user.name", "Synthetic Tester")
    git("config", "user.email", "tester@example.invalid")
    (root / "src").mkdir()
    (root / "src/cash.py").write_text("def cash(a, b):\n    return a + b\n", encoding="utf-8", newline="\n")
    git("add", "src/cash.py")
    git("commit", "-m", "Synthetic baseline")
    (root / "src/cash.py").write_text("def cash(a, b):\n    return a - b\n", encoding="utf-8", newline="\n")
    git("add", "src/cash.py")
    git("commit", "-m", "Synthetic candidate")
    packet, report = root / "packet.json", root / "report.json"
    cli("plan", "--repo", root, "--base", "HEAD~1", "--output", packet)
    cli("review", "--packet", packet, "--output", report)
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == "offline-analysis"
    gate = cli(
        "verify-gate",
        "--repo",
        root,
        "--expected-head",
        git("rev-parse", "HEAD"),
        "--packet",
        packet,
        "--review",
        report,
        expected_exit=1,
    )[0]
    assert gate["status"] == "blocked" and "model_review_absent" in gate["blocking_reasons"]
    assert not gate["merge_authority"] and not gate["deployment_authority"]
    # The installed wheel must carry the declarative template and new commands.
    # Execution below uses only these synthetic committed-source checks.
    workflow_config = json.loads((root / "config.json").read_text(encoding="utf-8"))
    workflow_config.update(
        recipes={
            "unit": ["python", "-c", "from cash import cash; assert cash(5, 2) == 3"],
            "cash": ["python", "-c", "from cash import cash; assert cash(10, 3) == 7"],
        },
        required_recipes=["unit"],
    )
    config_path = root / "workflow-config.json"
    config_path.write_text(json.dumps(workflow_config), encoding="utf-8", newline="\n")
    template = json.loads((root / "kit/examples/cash-workflow.json").read_text(encoding="utf-8"))
    template["methodology"] = ["src/cash.py"]
    for requirement in template["requirements"]:
        requirement["methodology"] = ["src/cash.py"]
    template_path, plan_path = root / "workflow-template.json", root / "workflow-plan.json"
    template_path.write_text(json.dumps(template), encoding="utf-8", newline="\n")
    cli("--config", config_path, "workflow", "plan", "--repo", root, "--packet", packet,
        "--template", template_path, "--output", plan_path)
    preflight = cli("--config", config_path, "workflow", "preflight", "--repo", root,
                    "--packet", packet, "--plan", plan_path)[0]
    assert preflight["status"] == "preflight-passed" and not preflight["execution_authorized"]
    plan_hash = json.loads(plan_path.read_text(encoding="utf-8"))["plan_hash"]
    created, paused = cli("--config", config_path, "workflow", "run", "--repo", root,
                          "--packet", packet, "--plan", plan_path, "--approve-plan", plan_hash,
                          "--backend", "local", "--approve-local", "--max-steps", "1")
    assert paused["status"] == "paused" and paused["steps"][0]["state"] == "succeeded"
    completed = cli("--config", config_path, "workflow", "resume", "--repo", root,
                    "--run-id", created["workflow_run_id"], "--approve-plan", plan_hash, "--approve-local")[0]
    assert completed["status"] == "completed-checks" and len(completed["check_records"]) == 2
    assert cli("workflow", "status", "--run-id", created["workflow_run_id"])[0]["status"] == "completed-checks"
    refused = cli("github-audit", "--repository", "example/repository", expected_exit=2)
    assert refused["code"] == "network_not_approved"  # Offline refusal; no GitHub request.
    audit = cli("audit", "--export", root / "events.jsonl")[0]
    events = [json.loads(line) for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert audit["events_verified"] == len(events) and not audit["incomplete_runs"]
    assert any(row["payload"]["event"] == "command_failed" for row in events)
    cli("render", "--input", report, "--output", root / "report.html")
    assert cli("finance-check", "--kind", "cash", "--input", examples / "cash-check.json")[0]["passed"]
    cli("evaluate", "--suite", examples / "review-cases.json", "--output", root / "evaluation.json")
    assert not json.loads((root / "evaluation.json").read_text(encoding="utf-8"))["model_quality_measured"]
    entry = cli("evidence", "add", "--input", examples / "evidence-observation.json")[0]
    cli("evidence", "approve", "--id", entry["id"], "--approve-hash", entry["hash"])
    latest = cli("evidence", "latest", "--entity", "Fictional Example", "--metric", "revenue")[0]
    assert latest["status"] == "approved"
print(
    json.dumps(
        {
            "installed_module": str(Path(finassist.__file__).resolve()),
            "offline_package_smoke": "PASS",
            "commands_exercised": [
                "demo",
                "doctor",
                "init",
                "export-kit",
                "guide (all bundled topics)",
                "plan",
                "workflow plan/preflight",
                "workflow run/resume/status (synthetic local checks)",
                "review",
                "verify-gate (blocked offline)",
                "github-audit (network refused)",
                "audit --export",
                "render",
                "finance-check",
                "evaluate",
                "evidence",
            ],
        }
    )
)
