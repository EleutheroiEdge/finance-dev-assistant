"""Local frozen history cases. Expected findings are held out of source packets."""

from dataclasses import dataclass, replace
from pathlib import Path
import re

from .config import Config
from .document_contracts import validate_document_shape
from .errors import AssistantError
from .model_gate import _scope_path, _screen_ignores, prepare_model_source
from .model_policy import load_model_policy
from .scope import build_packet, git, resolve
from .security import canonical, check_text, digest, regular_path

SUITE_VERSION = 1
MAX_CASES = 50
MAX_EXPECTED = 50
MAX_EXPECTED_PATHS = 50
MAX_REPOSITORY_LENGTH = 4096
MAX_TRIALS = 20
MAX_SUITE_BYTES = 1_000_000
IDENTIFIER_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}"
POLICY_COMMIT_PATTERN = r"[0-9a-f]{40}"
SEVERITY_WEIGHTS = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def identifier(value) -> str:
    if not isinstance(value, str) or re.fullmatch(IDENTIFIER_PATTERN, value) is None:
        raise AssistantError("history_identity_invalid")
    return value


def validate_expected(expected, negative_control) -> None:
    validate_document_shape({"expected": expected, "negative_control": negative_control},
                            "history-expected", "history_expected_invalid")
    labels = set()
    for item in expected:
        if item["label"] in labels:
            raise AssistantError("history_expected_invalid")
        labels.add(item["label"])
        for path in item["paths"]:
            _scope_path(path)


def validate_history_suite(suite: dict, *, trials: int = 1) -> str:
    """Validate the entire input before looking at repositories, keys or networks."""
    validate_document_shape(suite, "history-suite", "history_suite_invalid")
    if (any(type(suite[key]) is not int for key in ("version", "schema_version") if key in suite)
            or type(trials) is not int or not 1 <= trials <= MAX_TRIALS):
        raise AssistantError("history_suite_invalid")
    raw = canonical(suite)
    if len(raw) > MAX_SUITE_BYTES:
        raise AssistantError("history_suite_too_large")
    check_text(raw.decode())
    seen = set()
    for case in suite["cases"]:
        if case["id"] in seen:
            raise AssistantError("history_identity_invalid")
        seen.add(case["id"])
        validate_expected(case["expected"], case["negative_control"])
        if "policy" in case:
            _scope_path(case["policy"]["path"])
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
    # Git may expand Windows 8.3 names. Compare directory identity only after
    # both spellings pass the existing symlink/reparse-point screening.
    if not repo.is_dir():
        raise AssistantError("history_policy_repository_invalid")
    try:
        top = regular_path(Path(git(repo, "rev-parse", "--show-toplevel")))
    except AssistantError as exc:
        if exc.code == "git_read_failed":
            raise AssistantError("history_policy_repository_invalid") from exc
        raise
    if not top.samefile(repo):
        raise AssistantError("history_policy_repository_invalid")
    commit = selection.get("commit", case["base_sha"])
    try:
        resolved = resolve(repo, commit)
    except AssistantError as exc:
        if exc.code == "git_commit_unavailable":
            raise AssistantError("history_policy_commit_unavailable") from exc
        raise
    if resolved != commit:
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
    if not regular_path(Path(git(repo, "rev-parse", "--show-toplevel"))).samefile(repo):
        raise AssistantError("history_repository_root_required")
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
