"""Reproducible synthetic review tasks; model quality requires explicit human adjudication."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import subprocess
import tempfile

from .config import Config
from .errors import AssistantError
from .review import review_packet
from .scope import build_packet
from .security import canonical, check_text, digest


def validate_suite(
    suite: dict, *, extra_patterns: tuple[str, ...] = (), config: Config | None = None
) -> None:
    check_text(canonical(suite).decode(), extra_patterns=extra_patterns)
    if set(suite) != {"version", "cases"} or suite["version"] != 1:
        raise AssistantError("invalid_eval_suite")
    if not isinstance(suite["cases"], list) or not 1 <= len(suite["cases"]) <= 50:
        raise AssistantError("invalid_eval_cases")
    identifiers = set()
    for case in suite["cases"]:
        if set(case) != {"id", "path", "before", "after", "expected_defect"}:
            raise AssistantError("invalid_eval_case")
        if (
            not isinstance(case["id"], str)
            or not case["id"]
            or case["id"] in identifiers
            or type(case["expected_defect"]) is not bool
        ):
            raise AssistantError("invalid_eval_identity")
        identifiers.add(case["id"])
        (config or Config()).check_path(case["path"])
        for side in ("before", "after"):
            if not isinstance(case[side], str) or not case[side] or len(case[side].encode()) > 48_000:
                raise AssistantError("invalid_eval_source")
            check_text(case[side], extra_patterns=extra_patterns)


def _fixture_git(repo: Path, *args: str) -> None:
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C.UTF-8",
        "HOME": str(repo),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
    }
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    try:
        subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True, timeout=15, check=True)
    except subprocess.SubprocessError as exc:
        raise AssistantError("eval_fixture_git_failed") from exc


def evaluate(
    suite: dict,
    config: Config,
    state: Path,
    *,
    approved_suite_hash: str | None = None,
    network_approved: bool = False,
    transport=None,
) -> dict:
    config.validate()
    validate_suite(suite, extra_patterns=config.extra_sensitive_patterns, config=config)
    suite_hash = digest(canonical(suite))
    if config.provider != "offline" and approved_suite_hash != suite_hash:
        raise AssistantError("eval_suite_approval_required")
    reports = []
    for case in suite["cases"]:
        with tempfile.TemporaryDirectory(prefix="finassist-eval-") as root:
            repo = Path(root)
            _fixture_git(repo, "init", "-b", "main")
            _fixture_git(repo, "config", "user.name", "Synthetic Evaluation")
            _fixture_git(repo, "config", "user.email", "evaluation@example.invalid")
            target = repo / case["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(case["before"])
            _fixture_git(repo, "add", "--", case["path"])
            _fixture_git(repo, "commit", "-m", "Synthetic baseline")
            target.write_text(case["after"])
            _fixture_git(repo, "add", "--", case["path"])
            _fixture_git(repo, "commit", "-m", "Synthetic candidate")
            local_config = replace(config, allow_paths=(case["path"],))
            packet = build_packet(repo, "HEAD~1", "HEAD", local_config)
            # Labels never enter the model packet; suite approval authorizes these
            # exact synthetic sources through this deterministic construction.
            review = review_packet(
                packet,
                local_config,
                state / "audit.sqlite",
                network_approved=network_approved,
                approved_packet_hash=packet["packet_hash"],
                transport=transport,
            )
            reports.append({"id": case["id"], "expected_defect": case["expected_defect"], "report": review})
    result = {
        "suite_hash": suite_hash,
        "provider": config.provider,
        "model": config.model,
        "cases": reports,
        "model_quality_measured": False,
        "qualification": "Discovery outputs need independent human adjudication.",
        "source": "versioned public synthetic cases; use private held-out cases for stronger evidence",
    }
    return {**result, "evaluation_hash": digest(canonical(result))}


def score(evaluation: dict, labels: dict) -> dict:
    expected_hash = digest(canonical({k: v for k, v in evaluation.items() if k != "evaluation_hash"}))
    if evaluation.get("evaluation_hash") != expected_hash or labels.get("evaluation_hash") != expected_hash:
        raise AssistantError("evaluation_hash_mismatch")
    if evaluation["provider"] == "offline":
        raise AssistantError("offline_run_is_not_model_evaluation")
    cases = {case["id"]: case for case in evaluation["cases"]}
    outcomes = labels.get("outcomes", {})
    if set(outcomes) != set(cases):
        raise AssistantError("adjudication_incomplete")
    counts = {"confirmed-hit": 0, "miss": 0, "clean": 0, "false-alarm": 0, "unresolved": 0}
    for identifier, outcome in outcomes.items():
        if outcome not in counts:
            raise AssistantError("invalid_adjudication")
        expected = cases[identifier]["expected_defect"]
        if outcome != "unresolved" and (
            (expected and outcome not in {"confirmed-hit", "miss"})
            or (not expected and outcome not in {"clean", "false-alarm"})
        ):
            raise AssistantError("adjudication_label_conflict")
        counts[outcome] += 1
    positive, negative = counts["confirmed-hit"] + counts["miss"], counts["clean"] + counts["false-alarm"]
    return {
        "evaluation_hash": expected_hash,
        "counts": counts,
        "case_recall": counts["confirmed-hit"] / positive if positive else None,
        "negative_control_false_alarm_rate": counts["false-alarm"] / negative if negative else None,
        "complete": counts["unresolved"] == 0,
        "qualification": "Operator-adjudicated case metrics, not finding-level precision.",
    }
