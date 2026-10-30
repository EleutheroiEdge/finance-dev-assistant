"""Exercise the installed CLI's model gate with synthetic source and fake HTTP only."""

from contextlib import redirect_stdout
from functools import partial
from importlib.resources import files
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile

import httpx

from finassist.cli import main
import finassist.model_gate as gate_module
from finassist.scope import git_command, git_environment
from finassist.security import canonical, digest


def exercise_model_gate() -> dict:
    with tempfile.TemporaryDirectory(prefix="finassist-model-smoke-") as temporary:
        root = Path(temporary)
        repo = root / "repository"
        repo.mkdir()

        def git(*args):
            return subprocess.check_output(git_command(repo, *args), env=git_environment(), text=True,
                                           encoding="utf-8").strip()

        git("init", "-b", "main")
        git("config", "user.name", "Synthetic Gate")
        git("config", "user.email", "gate@example.invalid")
        git("config", "core.autocrlf", "false")
        policy = json.loads(files("finassist").joinpath("resources/model-gate-policy.json").read_text(encoding="utf-8"))
        policy["model_review"].update(api_key_env="FINASSIST_SYNTHETIC_SMOKE_KEY", blocking_severities=["high"])
        raw = canonical(policy)
        (repo / "gate-policy.json").write_bytes(raw)
        (repo / "src").mkdir()
        (repo / "src/cash.py").write_text("balance = 1\n", encoding="utf-8")
        git("add", "gate-policy.json", "src/cash.py")
        git("commit", "-m", "Synthetic gate base")
        base = git("rev-parse", "HEAD")
        (repo / "src/cash.py").write_text("balance = 0\n", encoding="utf-8")
        git("add", "src/cash.py")
        git("commit", "-m", "Synthetic gate change")
        head = git("rev-parse", "HEAD")
        calls, scenario = [], ["PASS"]

        def fake_transport(request):
            calls.append(request)
            packet = json.loads(json.loads(request.content)["input"])
            source = packet["files"][0]
            finding = {"severity": "high", "path": source["path"], "line": 1,
                       "claim": "Synthetic changed balance", "impact": "Synthetic arithmetic difference",
                       "reproduction": "Compare synthetic committed values",
                       "evidence": [{"path": source["path"], "side": "after", "line": 1, "sha256": source["after_hash"]}]}
            review = {"head": head, "summary": "Synthetic review", "reviewed_paths": [source["path"]],
                      "findings": [finding] if scenario[0] == "FAIL" else []}
            data = {"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps(review)}]}]}
            if scenario[0] != "BLOCKED":
                data["usage"] = {"input_tokens": 100, "output_tokens": 100}
            return httpx.Response(200, json=data)

        original = gate_module.model_gate
        variable = "FINASSIST_SYNTHETIC_SMOKE_KEY"
        previous = os.environ.get(variable)
        os.environ[variable] = "fictional-smoke-value"
        # Only this synthetic harness supplies a local event context and fake
        # transport; the production CLI/Action retains its context validation.
        gate_module.model_gate = partial(original, environment={}, transport=httpx.MockTransport(fake_transport))
        try:
            for index, expected in enumerate(("PASS", "FAIL", "BLOCKED", "BLOCKED")):
                scenario[0] = expected
                output = root / f"report-{index}.json"
                with redirect_stdout(io.StringIO()):
                    code = main(["gate", "run", "--repo", str(repo), "--base", base, "--head", head,
                                 "--policy", "gate-policy.json", "--policy-sha256", digest(raw),
                                 "--state-dir", str(root / "retained-state"), "--output", str(output)])
                report = json.loads(output.read_text(encoding="utf-8"))
                assert report["verdict"] == expected and code == gate_module.EXIT_CODES[expected]
                gate_module.validate_model_report(report)
            assert len(calls) == 3  # The fourth attempt cannot retry unknown usage.
        finally:
            gate_module.model_gate = original
            if previous is None:
                os.environ.pop(variable, None)
            else:
                os.environ[variable] = previous
    return {"installed_model_gate_smoke": "PASS", "transport": "synthetic-fake-only", "unknown_attempt_retried": False}


if __name__ == "__main__":
    print(json.dumps(exercise_model_gate()))
