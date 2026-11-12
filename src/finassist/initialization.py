"""First-run orchestration; detection reads only committed repository content."""

from dataclasses import replace
from pathlib import Path
import subprocess

from .config import Config, config_document, save_config
from .errors import AssistantError
from .model_policy import check_draft, missing_fields
from .scope import git, git_command, git_environment, resolve
from .security import canonical
from .initialization_state import save_initial_config, local_state_exclude


def _empty_proposal(args, configured, *, head):
    from .detect import PURPOSES
    profile = PURPOSES.get(args.purpose, args.profile or "general")
    proposed = replace(configured, allow_paths=(), generated_paths=(), protected_paths=(), profile=profile)
    document = config_document(proposed)
    draft = {"schema_version": 2, "model_review": {"enabled": True, "allow_paths": [], "profile": profile}}
    return {"schema_version": 1, "mode": "init-detect", "head": head,
            "config": document, "gate_policy_draft": draft, "gate_policy_missing": missing_fields(draft),
            "tests": [], "private_paths": {"count": 0, "examples": []}, "evidence": {},
            "evidence_not_listed": {}, "warnings": [{"code": "no_source_detected"}],
            "purpose_choices": sorted(PURPOSES), "files_read_from": "committed revision only",
            "commands_run": [], "source_detected": False, "written": False, "empty_repository": True}, proposed


def _detect_proposal(args, configured):
    from .detect import detect, _provider_fields
    from .config_preflight import budgets_for_the_packet_limit
    from .health import config_warnings
    repo = Path(args.detect_repo or ".")
    stated = None if args.purpose or configured.profile == Config().profile and not args.profile else configured.profile
    try:
        proposal = detect(repo, revision=args.revision or "HEAD", purpose=args.purpose, profile=stated)
    except AssistantError as exc:
        if exc.code == "detect_empty_repository":
            return _empty_proposal(args, configured, head=resolve(repo, args.revision or "HEAD"))
        if exc.code != "git_commit_unavailable" or args.revision not in (None, "HEAD"):
            raise
        # An unborn branch has no reviewed revision. Verify a real checkout and
        # symbolic HEAD; never mask missing tools, corrupt Git or an arbitrary bad ref.
        if git(repo, "rev-parse", "--is-inside-work-tree").strip() != "true":
            raise
        ref = git(repo, "symbolic-ref", "--quiet", "HEAD")
        try:
            lookup = subprocess.run(git_command(repo, "show-ref", "--verify", "--quiet", ref),
                                    env=git_environment(), capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            raise AssistantError("git_read_failed") from None
        if lookup.returncode != 1:  # Exactly an absent ref; broken objects/config are failures.
            raise exc
        return _empty_proposal(args, configured, head=None)
    detected = proposal["config"]
    packet = max(configured.max_packet_bytes, detected["max_packet_bytes"])
    proposed = replace(configured, allow_paths=tuple(detected["allow_paths"]),
                       generated_paths=tuple(detected["generated_paths"]),
                       protected_paths=tuple(detected["protected_paths"]),
                       max_file_bytes=detected["max_file_bytes"], max_packet_bytes=packet, profile=detected["profile"])
    budgets = budgets_for_the_packet_limit(proposed)
    proposed = replace(proposed, **budgets)
    proposed.validate()
    if warnings := config_warnings(proposed, file_selected=True):
        proposal["config_warnings"] = warnings
    document = config_document(proposed)
    proposal["config"] = {key: document[key] for key in (
        "provider", "model", "profile", "allow_paths", "generated_paths", "protected_paths", "max_file_bytes",
        "max_packet_bytes", "input_usd_per_million", "output_usd_per_million", *budgets)}
    for name, value in budgets.items():
        proposal["evidence"].setdefault(name, []).append(
            {"value": value, "rule": "one_packet_at_the_limit", "document": "config"})
    if budgets:
        proposal["warnings"].append({"code": "budget_raised_for_packet_limit", **budgets})
    model = proposal["gate_policy_draft"]["model_review"]
    model.update(_provider_fields(configured, model))
    proposal["gate_policy_missing"] = missing_fields(proposal["gate_policy_draft"])
    if "max_run_usd" in model:
        proposal["evidence"].setdefault("max_run_usd", []).append(
            {"value": model["max_run_usd"], "rule": "one_request_at_the_limit"})
    if not proposal["gate_policy_missing"]:
        try:
            check_draft(proposal["gate_policy_draft"])
        except AssistantError:
            proposal["warnings"].append({"code": "gate_policy_invalid"})
    return proposal, proposed


def run_init(args, config: Config) -> int:
    from .detect import _configured, _DETECT_ONLY
    from .health import config_warnings
    template = getattr(args, "template", False)
    if template and any(getattr(args, name) not in (None, False) for name in _DETECT_ONLY):
        raise AssistantError("init_option_requires_detect")
    configured = _configured(args, config)
    if template:
        save_config(Path(args.output), configured)
        warnings = config_warnings(configured, file_selected=True)
        print(canonical({"created": args.output, "network_enabled": False,
                         "local_ignore": local_state_exclude(Path.cwd()),
                         **({"config_warnings": warnings} if warnings else {})}).decode())
        return 0
    proposal, proposed = _detect_proposal(args, configured)
    plain = not args.detect
    if plain or args.write:
        if args.detect and not proposal["source_detected"] and not proposal.get("empty_repository"):
            raise AssistantError("detect_no_source_to_write")
        state = Path(args.audit_dir) if args.audit_dir else Path.cwd() / ".finassist"
        replaced = save_initial_config(Path(args.output), proposed, state, remember=plain, replace_initial=args.detect)
        proposal.update(written=True, created=args.output, replaced_initial_config=replaced,
                        local_ignore=local_state_exclude(Path.cwd()))
    print(canonical(proposal).decode())
    return 0
