"""GitHub Actions entrypoint and reduced summary/output projection; no GitHub API writes."""

import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile

from .ci_gate import ci_gate
from .ci_policy import read_document
from .errors import AssistantError
from .github_context import pull_request_context
from .security import canonical, digest, regular_path, write_private


def _report_identity(report: dict) -> None:
    if (
        type(report.get("schema_version")) is not int or report["schema_version"] != 1 or report.get("mode") != "checks-only"
        or report.get("status") not in {"passed", "blocked", "error"}
        or not isinstance(report.get("blocking_reasons"), list) or len(report["blocking_reasons"]) > 128
        or any(not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,80}", code) is None
               for code in report["blocking_reasons"])
        or report.get("report_hash") != digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
        or (report["status"] == "passed" and (report["blocking_reasons"] or report.get("model_review") != "not-requested"))
    ):
        raise AssistantError("ci_report_invalid")
    if report["status"] == "passed":
        checks = report.get("checks", {})
        if (
            not isinstance(checks, dict) or type(checks.get("required")) is not int
            or type(checks.get("completed")) is not int or not 1 <= checks["required"] <= 64
            or checks["completed"] != checks["required"]
        ):
            raise AssistantError("ci_report_invalid")
    elif not report["blocking_reasons"]:
        raise AssistantError("ci_report_invalid")


def summary_markdown(report: dict) -> str:
    _report_identity(report)
    lines = ["## finledgerpoli financial check gate", "", "Result: **" + report["status"] + "**.",
             "", "Mode: deterministic checks only. No AI review or merge authorization is implied.",
             "", "Report hash: `" + report["report_hash"] + "`."]
    if report["blocking_reasons"]:
        lines += ["", "Blocking reasons:", "", *("- `" + code + "`" for code in report["blocking_reasons"])]
    return "\n".join(lines) + "\n"


def publish_action_report(report: dict, report_path: Path, summary_path: Path, outputs_path: Path) -> None:
    summary = summary_markdown(report)
    path_value = str(report_path)
    if any(ord(character) < 32 or ord(character) == 127 for character in path_value):
        raise AssistantError("ci_output_path_invalid")
    path_value = str(regular_path(report_path))
    if any(ord(character) < 32 or ord(character) == 127 for character in path_value):
        raise AssistantError("ci_output_path_invalid")
    selected_summary, selected_outputs = regular_path(summary_path), regular_path(outputs_path)
    with selected_summary.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(summary)
    with selected_outputs.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("status=" + report["status"] + "\nreport-hash=" + report["report_hash"] +
                     "\nreport-path=" + path_value + "\n")


def _run_github_action(environment) -> int:
    """Trusted caller wiring supplies event identity and a base-policy byte pin."""
    report = None
    try:
        if environment.get("GITHUB_ACTIONS") != "true":
            raise AssistantError("ci_github_context_required")
        workspace = regular_path(Path(environment["GITHUB_WORKSPACE"]))
        relative = environment.get("FINASSIST_CI_REPOSITORY_PATH", ".")
        repo = regular_path(workspace / relative)
        if not repo.is_relative_to(workspace):
            raise AssistantError("ci_checkout_path_invalid")
        context = pull_request_context(read_document(Path(environment["GITHUB_EVENT_PATH"])),
                                       environment["GITHUB_EVENT_NAME"], environment["GITHUB_REPOSITORY"])
        private_root = regular_path(Path(environment["RUNNER_TEMP"]))
        private_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="finassist-ci-", dir=private_root))
        report = ci_gate(repo, context, environment.get("FINASSIST_CI_POLICY_PATH", "finassist-ci.json"),
                         environment["FINASSIST_CI_POLICY_SHA256"], directory / "state")
    except AssistantError as exc:
        code = exc.code
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
        code = "ci_action_input_or_audit_unavailable"
    else:
        code = None
    if code is not None:
        # Never copy exceptions, PR titles/bodies, paths, source or tool output.
        if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,80}", code) is None:
            code = "ci_action_failed"
        report = {"schema_version": 1, "mode": "checks-only", "status": "error", "blocking_reasons": [code],
                  "model_review": "not-run", "readiness_evaluated": False, "merge_authority": False,
                  "deployment_authority": False}
        report["report_hash"] = digest(canonical(report))
        # Report failures only when the runner's private output root is valid.
        private_root = regular_path(Path(environment["RUNNER_TEMP"]))
        private_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="finassist-ci-refused-", dir=private_root))
    report_path = directory / "report.json"
    write_private(report_path, canonical(report) + b"\n")
    publish_action_report(report, report_path, Path(environment["GITHUB_STEP_SUMMARY"]), Path(environment["GITHUB_OUTPUT"]))
    print(json.dumps({"status": report["status"], "report_hash": report["report_hash"]}))
    return 0 if report["status"] == "passed" else 1 if report["status"] == "blocked" else 2


def run_github_action(environment) -> int:
    try:
        return _run_github_action(environment)
    except Exception:
        # Invalid/unwritable runner output paths must fail without a traceback
        # revealing path values or accidentally leaving a successful job exit.
        print(json.dumps({"status": "error", "code": "ci_action_output_unavailable"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(run_github_action(os.environ))
