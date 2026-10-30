"""Local frozen history cases. Expected findings are held out of source packets."""

from dataclasses import dataclass, replace
from pathlib import Path
import re

from .ci_policy import revision
from .config import Config
from .errors import AssistantError
from .model_gate import _scope_path, _screen_ignores, prepare_model_source
from .model_policy import load_model_policy
from .scope import build_packet, git, resolve
from .security import canonical, check_text, digest, regular_path

SEVERITY_WEIGHTS = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_CASE_FIELDS = {"id", "repo_path", "base_sha", "head_sha", "profile", "expected", "negative_control"}


def identifier(value) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value) is None:
        raise AssistantError("history_identity_invalid")
    return value


def validate_expected(expected, negative_control) -> None:
    if (type(negative_control) is not bool or not isinstance(expected, list) or len(expected) > 50
            or negative_control != (len(expected) == 0)):
        raise AssistantError("history_expected_invalid")
    labels = set()
    for item in expected:
        if not isinstance(item, dict) or set(item) != {"label", "paths", "severity"}:
            raise AssistantError("history_expected_invalid")
        label = identifier(item["label"])
        if (label in labels or not isinstance(item["severity"], str)
                or item["severity"] not in SEVERITY_WEIGHTS):
            raise AssistantError("history_expected_invalid")
        labels.add(label)
        paths = item["paths"]
        if (not isinstance(paths, list) or not 1 <= len(paths) <= 50
                or any(not isinstance(path, str) for path in paths) or len(set(paths)) != len(paths)):
            raise AssistantError("history_expected_invalid")
        for path in paths:
            _scope_path(path)


def validate_history_suite(suite: dict, *, trials: int = 1) -> str:
    """Validate the entire input before looking at repositories, keys or networks."""
    if (not isinstance(suite, dict) or set(suite) != {"version", "cases"}
            or type(suite["version"]) is not int or suite["version"] != 1
            or type(trials) is not int or not 1 <= trials <= 20):
        raise AssistantError("history_suite_invalid")
    raw = canonical(suite)
    if len(raw) > 1_000_000:
        raise AssistantError("history_suite_too_large")
    check_text(raw.decode())
    cases = suite["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 50:
        raise AssistantError("history_cases_invalid")
    seen = set()
    for case in cases:
        if (not isinstance(case, dict) or not _CASE_FIELDS <= set(case)
                or set(case) - _CASE_FIELDS - {"policy"}):
            raise AssistantError("history_case_invalid")
        name = identifier(case["id"])
        if name in seen:
            raise AssistantError("history_identity_invalid")
        seen.add(name)
        if (not isinstance(case["repo_path"], str) or not case["repo_path"]
                or len(case["repo_path"]) > 4096 or "://" in case["repo_path"]):
            raise AssistantError("history_repository_invalid")
        revision(case["base_sha"])
        revision(case["head_sha"])
        identifier(case["profile"])
        validate_expected(case["expected"], case["negative_control"])
        if "policy" in case:
            policy = case["policy"]
            if (not isinstance(policy, dict) or not {"path", "sha256"} <= set(policy)
                    or set(policy) - {"repo_path", "commit", "path", "sha256"}
                    or not isinstance(policy["path"], str) or not isinstance(policy["sha256"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", policy["sha256"]) is None):
                raise AssistantError("history_policy_invalid")
            _scope_path(policy["path"])
            if "repo_path" in policy and (not isinstance(policy["repo_path"], str)
                    or not policy["repo_path"] or len(policy["repo_path"]) > 4096
                    or "://" in policy["repo_path"]):
                raise AssistantError("history_policy_repository_invalid")
            commit = policy.get("commit", case["base_sha"])
            if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
                raise AssistantError("history_policy_commit_invalid")
    return digest(raw)


@dataclass(frozen=True)
class HistoryPolicyBinding:
    repo: Path
    commit: str
    path: str
    sha256: str


def history_policy_binding(case: dict, suite_directory: Path) -> HistoryPolicyBinding:
    if "policy" not in case:
        raise AssistantError("history_policy_required")
    selection = case["policy"]
    repo = regular_path(suite_directory / selection.get("repo_path", case["repo_path"]))
    # Reject a non-repo subdirectory that would otherwise inherit an ancestor's
    # Git identity. No remote inspection, fetch or working-tree mutation occurs.
    if not repo.is_dir() or regular_path(Path(git(repo, "rev-parse", "--show-toplevel"))) != repo:
        raise AssistantError("history_policy_repository_invalid")
    commit = selection.get("commit", case["base_sha"])
    if resolve(repo, commit) != commit:
        raise AssistantError("history_policy_revision_mismatch")
    return HistoryPolicyBinding(repo, commit, selection["path"], selection["sha256"])


def history_approval_hash(suite: dict, trials: int = 1) -> str:
    return digest(canonical({"suite_content_hash": validate_history_suite(suite, trials=trials),
                             "trials": trials}))


def source_identity(packet: dict) -> str:
    """Comparable source identity excludes local clone location, model and profile."""
    return digest(canonical({key: packet[key] for key in ("base", "head", "merge_base", "files")}))


def prepare_history_case(case: dict, root: Path, config: Config) -> dict:
    repo = regular_path(root / case["repo_path"])
    if not repo.is_dir():
        raise AssistantError("history_repository_unavailable")
    base, head = case["base_sha"], case["head_sha"]
    if resolve(repo, base) != base or resolve(repo, head) != head:
        raise AssistantError("history_revision_mismatch")
    result = {"repo": repo}
    if "policy" in case:
        binding = history_policy_binding(case, root)
        policy = load_model_policy(binding.repo, binding.commit, binding.path, binding.sha256)
        if policy.config.profile != case["profile"]:
            raise AssistantError("history_policy_profile_mismatch")
        packet = prepare_model_source(repo, base, head, policy, policy_repo=binding.repo)
        result.update(binding=binding, policy=policy)
    else:
        local = replace(config, provider="offline", allow_network=False, profile=case["profile"])
        local.validate()
        packet = build_packet(repo, base, head, local)
        paths = [item["path"] for item in packet["files"]]
        if not paths or packet["omitted"]:
            raise AssistantError("scope_incomplete")
        for path in paths:
            _scope_path(path)
        _screen_ignores(repo, {base, packet["merge_base"]}, paths)
    paths = {item["path"] for item in packet["files"]}
    if any(path not in paths for item in case["expected"] for path in item["paths"]):
        raise AssistantError("history_expected_outside_scope")
    return {**result, "source_hash": source_identity(packet), "packet": packet}


def plan_history(suite: dict, suite_directory: Path, config: Config, *, trials: int = 1) -> dict:
    """Screen all cases offline, without resolving refs remotely or reading a key.

    Paths are anchored at the suite file's directory. This is an inspection plan,
    not model-call authority; a live evaluation also needs its pinned gate policy.
    """
    suite_hash = history_approval_hash(suite, trials)
    root = regular_path(suite_directory)
    cases = []
    for case in suite["cases"]:
        prepared = prepare_history_case(case, root, config)
        # Explicit projection: case IDs, labels, paths to repos and expected
        # severities cannot be accidentally included by serializing the case.
        cases.append({"id": case["id"], "source_hash": prepared["source_hash"], "packet": prepared["packet"]})
    plan = {"schema_version": 1, "kind": "history-plan", "suite_hash": suite_hash,
            "trials": trials, "cases": cases, "network_authorized": False}
    return {**plan, "plan_hash": digest(canonical(plan))}
