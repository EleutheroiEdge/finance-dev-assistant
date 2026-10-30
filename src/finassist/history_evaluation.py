"""Bounded trials over frozen local history; every live attempt uses the model gate."""

from copy import deepcopy
import os
from pathlib import Path
import time
from uuid import uuid4

from .config import Config
from .errors import AssistantError
from .history_suite import history_approval_hash, plan_history, prepare_history_case
from .ledger import Ledger
from .model_gate import _evaluate_model_gate, prepare_model_request
from .model_policy import load_model_policy
from .security import canonical, digest, regular_path, write_private


def _signed(evaluation: dict) -> dict:
    data = {key: value for key, value in evaluation.items() if key != "evaluation_hash"}
    return {**data, "evaluation_hash": digest(canonical(data))}


def check_result_capacity(result: dict, prepared: list[dict], trials: int) -> None:
    """Refuse before dispatch if worst-case compact findings cannot be scored."""
    bound = len(canonical(_signed(result)))
    for source in prepared:
        longest = max((item["path"] for item in source["packet"]["files"]),
                      key=lambda path: len(canonical(path)))
        finding = {"id": "f-" + "f" * 64, "path": longest, "severity": "critical"}
        # At most50 findings per gate response; metadata/reasons/report reference
        # are bounded independently. Canonical length counts Unicode escaping.
        bound += trials * (50 * (len(canonical(finding)) + 1) + 2048)
    if bound > 64_000_000:
        raise AssistantError("history_evaluation_size_exceeded")


def run_history_gate(repo: Path, case: dict, binding, state: Path, *, transport, request_hash: str) -> dict:
    """History-only policy selection; ordinary model_gate exposes no override."""
    def load(_source):
        return load_model_policy(binding.repo, binding.commit, binding.path, binding.sha256), binding.repo
    return _evaluate_model_gate(repo, case["base_sha"], case["head_sha"], load, state,
                                transport=transport, expected_request_hash=request_hash)


def evaluate_history(suite: dict, suite_directory: Path, config: Config, state_dir: Path, *,
                     trials: int = 1, approved_suite_hash: str | None = None,
                     network_approved: bool = False, transport=None) -> dict:
    """No fetch, retry, fallback, parallel dispatch or implicit resumption.

    A suite approval binds trial count and the exact local case/policy selection.
    Successful FAIL verdicts are observations, not transport failures. BLOCKED
    stops the whole evaluation and retains unattempted trials in the denominator.
    """
    # Own the nested input before computing approval or constructing requests.
    suite = deepcopy(suite)
    suite_hash = history_approval_hash(suite, trials)
    root = regular_path(suite_directory)
    prepared = []
    if network_approved:
        if approved_suite_hash != suite_hash:
            raise AssistantError("eval_suite_approval_required")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            raise AssistantError("history_ci_execution_forbidden")
        # Screen EVERY case before the first key read, reservation or dispatch.
        for case in suite["cases"]:
            if "policy" not in case:
                raise AssistantError("history_policy_required")
            prepared.append(prepare_history_case(case, root, config))
        # All source preflights have finished. Now validate every exact request,
        # including key-echo and wire-size checks, before reserving any spend.
        for source in prepared:
            source["request_sha256"] = prepare_model_request(source["policy"], source["packet"])[0]
    else:
        prepared = plan_history(suite, root, config, trials=trials)["cases"]
    cases = [{"id": case["id"], "base_sha": case["base_sha"], "head_sha": case["head_sha"],
              "profile": case["profile"], "source_hash": source["source_hash"],
              "reviewer": ({"provider": source["policy"].config.provider,
                            "model": source["policy"].config.model,
                            "policy_repo_path": str(source["binding"].repo),
                            "policy_commit": source["binding"].commit, "policy_path": case["policy"]["path"],
                            "policy_sha256": case["policy"]["sha256"]}
                           if network_approved else {"provider": "offline", "model": None}),
              "expected": case["expected"], "negative_control": case["negative_control"],
              "runs": [{"trial": trial, "status": "not-run" if network_approved else "offline",
                        "findings": [], "actual_usd": None, "elapsed_seconds": None}
                       for trial in range(1, trials + 1)]}
             for case, source in zip(suite["cases"], prepared, strict=True)]
    result = {"schema_version": 2, "kind": "history-evaluation", "suite_hash": suite_hash,
              "trials": trials, "mode": "model" if network_approved else "offline", "cases": cases,
              "model_quality_measured": False,
              "qualification": "Discovery output requires independent human adjudication. "
              "Offline planning makes no model call. Unknown attempts stop all later trials; "
              "retain the journal and reconcile the shared budget ledger before any new run."}
    if not network_approved:
        return _signed(result)
    if state_dir is None:
        raise AssistantError("gate_state_directory_required")
    state = regular_path(state_dir)
    journal = state / "history" / (uuid4().hex + ".json")
    result["journal"] = str(journal)
    check_result_capacity(result, prepared, trials)
    write_private(journal, canonical(_signed(result)) + b"\n")
    with Ledger(state / "audit.sqlite") as ledger:
        ledger.verify()
        ledger.append({"event": "history_suite_approved", "suite_hash": suite_hash, "trials": trials,
                       "journal_id": journal.stem,
                       "cases": [{"source_hash": source["source_hash"],
                                  "policy_sha256": case["policy"]["sha256"],
                                  "request_sha256": source["request_sha256"]}
                                 for case, source in zip(suite["cases"], prepared, strict=True)]})
    for case_index, (case, source, output) in enumerate(zip(suite["cases"], prepared, cases, strict=True)):
        for run in output["runs"]:
            # If the process dies during dispatch, the journal keeps a blocked
            # attempt rather than making it look safe to rerun automatically.
            run.update(status="blocked", reason="history_attempt_outcome_unknown")
            write_private(journal, canonical(_signed(result)) + b"\n", replace=True)
            started = time.monotonic()
            report = run_history_gate(source["repo"], case, source["binding"], state,
                                      transport=transport, request_hash=source["request_sha256"])
            elapsed = time.monotonic() - started
            report_file = journal.with_name(f"{journal.stem}-{case_index}-{run['trial']}.report.json")
            write_private(report_file, canonical(report) + b"\n")
            run.update(report_file=report_file.name, report_hash=report["report_hash"],
                       request_sha256=report["request_sha256"], policy_sha256=report["policy_sha256"],
                       elapsed_seconds=elapsed, actual_usd=report["spend"]["actual_usd"])
            run["reason"] = report["reasons"]
            if report["verdict"] in {"PASS", "FAIL"}:
                run["status"] = "complete"
                run["findings"] = [{"id": "f-" + digest(canonical({"index": index, "finding": finding})),
                                    "path": finding["file"], "severity": finding["severity"]}
                                   for index, finding in enumerate(report["findings"])]
            write_private(journal, canonical(_signed(result)) + b"\n", replace=True)
            if run["status"] == "blocked":
                return _signed(result)
    return _signed(result)
