"""Exercise the installed wheel from an isolated temporary project, without model calls."""

from importlib import metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from ci_gate_smoke import exercise_ci_gate
from triage_smoke import exercise_triage_cli
import finassist
from finassist.platform_support import clean_environment, find_tool
from finassist.guides import GUIDES
from finassist.scope import git_environment
from finassist.security import canonical, digest

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
assert exercise_ci_gate("sha256:" + "a" * 64, run_checks=False)["ci_policy_refusal_smoke"] == "PASS"
with tempfile.TemporaryDirectory(prefix="finassist-wheel-smoke-") as directory:
    root = Path(directory)
    home = root / "home"
    home.mkdir()
    environment = clean_environment()
    environment.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / "appdata"),
                       LOCALAPPDATA=str(home / "localappdata"), XDG_CONFIG_HOME=str(home / "config"),
                       XDG_CACHE_HOME=str(home / "cache"), FINASSIST_NO_UPDATE_CHECK="1")

    def cli(*args, expected_exit=0):
        result = subprocess.run(
            [sys.executable, "-m", "finassist", *map(str, args)],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            env=environment,
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
            env=environment,
        )
        assert result.stdout.strip() == distribution.version, command
    assert cli("demo")[0]["status"] == "PASS"
    exercise_triage_cli(cli, root)
    doctor = cli("doctor")[0]
    assert doctor["version"] == distribution.version
    assert doctor["provider"] == "offline" and not doctor["container_daemon_checked"]
    assert doctor["updates"]["status"] == "not checked"
    assert cli("update", "status", "--json")[0]["automatic_installs"] is False
    preview_update = cli("update", "--dry-run")[0]
    assert preview_update["dry_run"] and preview_update["upgrade_argv"][-1] == "finledgerpoli"
    assert cli("doctor", "--check-updates")[0]["updates"]["reason"] == "network-disabled"
    cli("init", "--output", root / "config.json")
    kit = cli("export-kit", "--output", root / "kit")[0]
    assert not kit["installed_into_host"]
    topics = cli("guide")[0]["topics"]
    assert {row["topic"] for row in topics} == set(GUIDES)
    for topic, (_, source, _) in GUIDES.items():
        result = subprocess.run(
            [sys.executable, "-m", "finassist", "guide", topic],
            cwd=root, capture_output=True, check=True, shell=False,
            env=environment,
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
    timeline = cli("--config", root / "missing-config.json", "workflow", "timeline", "--repo", root,
                   "--run-id", created["workflow_run_id"], "--limit", "2")[0]
    assert timeline["chain_verified"] and timeline["recorded_status"] == "completed-checks"
    assert timeline["pagination"]["has_more"] and not timeline["artifacts_verified"]
    # Compose only exported declarative packs; source recipes remain explicit.
    resolved = root / "resolved-packs"
    summary = cli("--config", config_path, "workflow", "resolve", "--repo", root / "kit",
                  "--bundle", root / "kit/examples/workflow-packs/bundle.json", "--output", resolved)[0]
    assert not summary["execution_authorized"]
    effective = json.loads((resolved / "config.json").read_text(encoding="utf-8"))
    assert effective["profile"] == "monetary-review" and not effective["allow_network"]
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
    history_suite = {"version": 1, "cases": [{
        "id": "synthetic-history", "repo_path": ".", "base_sha": git("rev-parse", "HEAD~1"),
        "head_sha": git("rev-parse", "HEAD"), "profile": "finance-saas", "negative_control": False,
        "expected": [{"label": "cash-sign", "paths": ["src/cash.py"], "severity": "high"}]}]}
    history_file, history_output = root / "history.json", root / "history-output.json"
    history_file.write_bytes(canonical(history_suite))
    cli("evaluate", "--history-suite", history_file, "--trials", "2", "--output", history_output)
    history = json.loads(history_output.read_text(encoding="utf-8"))
    assert history["mode"] == "offline" and history["trials"] == 2
    labels_file = root / "history-labels.json"
    labels_file.write_bytes(canonical({"evaluation_hash": history["evaluation_hash"], "runs": []}))
    assert cli("score", "--evaluation", history_output, "--labels", labels_file,
               "--output", root / "offline-score.json", expected_exit=2)["code"] == "offline_run_is_not_model_evaluation"
    # An explicitly synthetic external-review envelope also exercises installed
    # scoring/comparison imports. Empty findings are misses, never model quality.
    history["mode"] = "external"
    for run in history["cases"][0]["runs"]:
        run["status"] = "complete"
    history.pop("evaluation_hash")
    history["evaluation_hash"] = digest(canonical(history))
    history_output.write_bytes(canonical(history))
    labels_file.write_bytes(canonical({"evaluation_hash": history["evaluation_hash"], "runs": [
        {"case_id": "synthetic-history", "trial": trial, "findings": {}} for trial in [1, 2]]}))
    score_output, comparison_output = root / "history-score.json", root / "history-comparison.json"
    cli("score", "--evaluation", history_output, "--labels", labels_file, "--output", score_output)
    assert json.loads(score_output.read_text(encoding="utf-8"))["severity_weighted_recall"] == 0
    cli("score", "--evaluation", history_output, "--labels", labels_file, "--compare", history_output,
        "--compare-labels", labels_file, "--output", comparison_output)
    comparison = json.loads(comparison_output.read_text(encoding="utf-8"))
    assert comparison["overlap"][0]["overlap_jaccard"] is None
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
                "triage validate/evaluate (fictional offline artifacts; required matrix unchanged)",
                "doctor",
                "init",
                "export-kit",
                "guide (all bundled topics)",
                "plan",
                "workflow plan/preflight",
                "workflow run/resume/status (synthetic local checks)",
                "workflow resolve (exported declarative packs)",
                "workflow timeline (read-only historical snapshot)",
                "ci gate (required model review refuses without dispatch)",
                "review",
                "verify-gate (blocked offline)",
                "github-audit (network refused)",
                "audit --export",
                "render",
                "finance-check",
                "evaluate",
                "evaluate --history-suite (offline synthetic revisions)",
                "score/compare (synthetic external envelope; no model calls)",
                "evidence",
            ],
        }
    )
)
