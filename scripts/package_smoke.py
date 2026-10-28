"""Exercise the installed wheel from an isolated temporary project, without model calls."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import finassist

assert "site-packages" in str(Path(finassist.__file__).resolve()), finassist.__file__
if len(sys.argv) != 2:
    raise SystemExit("usage: python scripts/package_smoke.py EXAMPLES_DIRECTORY")
examples = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="finassist-wheel-smoke-") as directory:
    root = Path(directory)

    def cli(*args):
        result = subprocess.run(
            [sys.executable, "-m", "finassist", *map(str, args)],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        return [json.loads(line) for line in result.stdout.splitlines()]

    def git(*args):
        return subprocess.check_output(
            ["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(root), *args], text=True
        ).strip()

    assert cli("demo")[0]["status"] == "PASS"
    doctor = cli("doctor")[0]
    assert doctor["provider"] == "offline" and not doctor["container_daemon_checked"]
    cli("init", "--output", root / "config.json")
    kit = cli("export-kit", "--output", root / "kit")[0]
    assert not kit["installed_into_host"]
    git("init", "-b", "main")
    git("config", "user.name", "Synthetic Tester")
    git("config", "user.email", "tester@example.invalid")
    (root / "src").mkdir()
    (root / "src/cash.py").write_text("def cash(a, b):\n    return a + b\n")
    git("add", "src/cash.py")
    git("commit", "-m", "Synthetic baseline")
    (root / "src/cash.py").write_text("def cash(a, b):\n    return a - b\n")
    git("add", "src/cash.py")
    git("commit", "-m", "Synthetic candidate")
    packet, report = root / "packet.json", root / "report.json"
    cli("plan", "--repo", root, "--base", "HEAD~1", "--output", packet)
    cli("review", "--packet", packet, "--output", report)
    assert json.loads(report.read_text())["status"] == "offline-analysis"
    cli("render", "--input", report, "--output", root / "report.html")
    assert cli("finance-check", "--kind", "cash", "--input", examples / "cash-check.json")[0]["passed"]
    cli("evaluate", "--suite", examples / "review-cases.json", "--output", root / "evaluation.json")
    assert not json.loads((root / "evaluation.json").read_text())["model_quality_measured"]
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
                "render",
                "finance-check",
                "evaluate",
                "evidence",
            ],
        }
    )
)
