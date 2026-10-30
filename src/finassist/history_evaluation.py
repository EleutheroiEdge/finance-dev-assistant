"""Bounded trials over frozen local history; every live attempt uses the model gate."""

from copy import deepcopy
import os
from pathlib import Path
import time
from uuid import uuid4

from .config import Config
from .errors import AssistantError
from .history_suite import history_approval_hash, plan_history, source_identity
from .ledger import Ledger
from .model_gate import _context, model_gate, prepare_model_request, prepare_model_source
from .model_policy import load_model_policy
from .scope import resolve
from .security import canonical, digest, regular_path, write_private


def _signed(evaluation: dict) -> dict:
    data = {key: value for key, value in evaluation.items() if key != "evaluation_hash"}
    return {**data, "evaluation_hash": digest(canonical(data))}


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
        # Screen EVERY case before the first key read, reservation or dispatch.
        for case in suite["cases"]:
            if "policy" not in case:
                raise AssistantError("history_policy_required")
            repo = regular_path(root / case["repo_path"])
            base, head = case["base_sha"], case["head_sha"]
            if resolve(repo, base) != base or resolve(repo, head) != head:
                raise AssistantError("history_revision_mismatch")
            _context(repo, base, head, os.environ)
            policy = load_model_policy(repo, base, case["policy"]["path"], case["policy"]["sha256"])
            if policy.config.profile != case["profile"]:
                raise AssistantError("history_policy_profile_mismatch")
            packet = prepare_model_source(repo, base, head, policy)
            paths = {item["path"] for item in packet["files"]}
            if any(path not in paths for item in case["expected"] for path in item["paths"]):
                raise AssistantError("history_expected_outside_scope")
            prepared.append({"repo": repo, "source_hash": source_identity(packet), "packet": packet,
                             "policy": policy})
        # All source preflights have finished. Now validate every exact request,
        # including key-echo and wire-size checks, before reserving any spend.
        for source in prepared:
            source["request_sha256"] = prepare_model_request(source["policy"], source["packet"])[0]
    else:
        prepared = plan_history(suite, root, config, trials=trials)["cases"]
    cases = [{"id": case["id"], "base_sha": case["base_sha"], "head_sha": case["head_sha"],
              "profile": case["profile"], "source_hash": source["source_hash"],
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
    write_private(journal, canonical(_signed(result)) + b"\n")
    with Ledger(state / "audit.sqlite") as ledger:
        ledger.verify()
        ledger.append({"event": "history_suite_approved", "suite_hash": suite_hash, "trials": trials,
                       "journal_id": journal.stem,
                       "cases": [{"source_hash": source["source_hash"],
                                  "policy_sha256": case["policy"]["sha256"],
                                  "request_sha256": source["request_sha256"]}
                                 for case, source in zip(suite["cases"], prepared, strict=True)]})
    for case, source, output in zip(suite["cases"], prepared, cases, strict=True):
        for run in output["runs"]:
            # If the process dies during dispatch, the journal keeps a blocked
            # attempt rather than making it look safe to rerun automatically.
            run.update(status="blocked", reason="history_attempt_outcome_unknown")
            write_private(journal, canonical(_signed(result)) + b"\n", replace=True)
            started = time.monotonic()
            report = model_gate(source["repo"], case["base_sha"], case["head_sha"],
                                case["policy"]["path"], case["policy"]["sha256"], state,
                                transport=transport, expected_request_hash=source["request_sha256"])
            elapsed = time.monotonic() - started
            run.update(report=report, elapsed_seconds=elapsed, actual_usd=report["spend"]["actual_usd"])
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
