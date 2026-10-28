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
from finassist.scope import git_environment

assert "site-packages" in str(Path(finassist.__file__).resolve()), finassist.__file__
if len(sys.argv) != 2:
    raise SystemExit("usage: python scripts/package_smoke.py EXAMPLES_DIRECTORY")
distribution = metadata.distribution("finledgerpoli")
assert distribution.metadata["Name"] == "finledgerpoli"
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
                "plan",
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
