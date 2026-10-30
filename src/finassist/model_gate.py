"""Portable policy-approved model review. PASS is component completion, not merge authority."""

from decimal import Decimal
from importlib.resources import files
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile

import jsonschema

from .ci_policy import read_document, revision
from .errors import AssistantError
from .github_context import pull_request_context, verify_origin
from .ledger import Ledger
from .model_policy import load_model_policy
from .providers import request_identity, request_shape
from .review import PolicyRequestApproval, call_model, review_schema, validate_review
from .scope import build_packet, git, git_command, git_environment, read_entry, resolve
from .security import canonical, check_path, digest, regular_path

EXIT_CODES = {"PASS": 0, "FAIL": 1, "BLOCKED": 2}
_PRIVATE = {"data", "private", "client", "clients", "household", "households",
            "client-config", "client_config", "household-config", "household_config"}


def _contains_key(value, key: str) -> bool:
    """Inspect decoded strings, so JSON escaping cannot hide a literal key."""
    if isinstance(value, str):
        return key in value
    if isinstance(value, dict):
        return any(_contains_key(name, key) or _contains_key(item, key) for name, item in value.items())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


def validate_model_report(report: dict) -> None:
    schema = json.loads(files("finassist").joinpath("resources/model-gate-report.schema.json").read_text(encoding="utf-8"))
    try:
        jsonschema.Draft202012Validator(schema).validate(report)
    except jsonschema.ValidationError as exc:
        raise AssistantError("gate_report_invalid") from exc
    if (report["report_hash"] != digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
            or (report["verdict"] == "PASS" and (report["reasons"] or None in (
                report["policy_sha256"], report["request_sha256"], report["usage"]["input_tokens"],
                report["usage"]["output_tokens"], report["spend"]["actual_usd"],
            ))) or (report["verdict"] != "PASS" and not report["reasons"])):
        raise AssistantError("gate_report_invalid")


def _scope_path(path: str) -> str:
    check_path(path)
    if len(path) > 512 or any(part.lower() in _PRIVATE for part in PurePosixPath(path).parts):
        raise AssistantError("gate_private_path")
    name = PurePosixPath(path).name.lower()
    if name in {"client.json", "clients.json", "household.json", "households.json",
                "credentials.json", "credential.json", "secrets.json"} or re.search(
        r"(?:household|client)[_-]?(?:config|settings|profile)", name
    ):
        raise AssistantError("gate_private_path")
    return path


def _ignored(repo: Path, paths: list[str]) -> bool:
    result = subprocess.run(git_command(repo, "check-ignore", "--no-index", "-z", "--stdin"),
                            input=("\0".join(paths) + "\0").encode(), capture_output=True,
                            timeout=30, env=git_environment(), check=False)
    if result.returncode not in {0, 1}:
        raise AssistantError("gate_ignore_check_unavailable")
    return result.returncode == 0


def _screen_ignores(repo: Path, revisions: set[str], paths: list[str]) -> None:
    if _ignored(repo, paths):
        raise AssistantError("gate_ignored_path")
    # Read immutable ignore rules from the policy base AND merge base. A stale
    # PR or dirty checkout cannot remove baseline exclusions to authorize source.
    directories = {parent for path in paths for parent in PurePosixPath(path).parents}
    for sha in revisions:
        with tempfile.TemporaryDirectory(prefix="finassist-ignore-") as temporary:
            snapshot = Path(temporary)
            git(snapshot, "init", "--quiet", "--template=")
            for parent in directories:
                target = snapshot / str(parent)
                target.mkdir(parents=True, exist_ok=True)
                name = str(parent / ".gitignore")
                raw, _ = read_entry(repo, sha, name, 128_000)
                if raw is not None:
                    (target / ".gitignore").write_bytes(raw)
            if _ignored(snapshot, paths):
                raise AssistantError("gate_ignored_path")


def _context(repo: Path, base: str, head: str, environment) -> None:
    if environment.get("GITHUB_ACTIONS") != "true":
        return
    context = pull_request_context(read_document(Path(environment["GITHUB_EVENT_PATH"])),
                                   environment["GITHUB_EVENT_NAME"], environment["GITHUB_REPOSITORY"])
    if context.head_repository != context.repository:
        raise AssistantError("gate_fork_not_allowed")
    if (base, head) != (context.base_sha, context.head_sha):
        raise AssistantError("gate_event_revision_mismatch")
    verify_origin(repo, context.repository)


def _blank_report() -> dict:
    return {"schema_version": 1, "mode": "model-review", "verdict": "BLOCKED", "reasons": [],
            "base": None, "head": None, "policy_sha256": None, "request_sha256": None,
            "findings": [], "usage": {"input_tokens": None, "output_tokens": None},
            "spend": {"reserved_usd": None, "actual_usd": None, "scope": "caller-retained-ledger"},
            "merge_authority": False, "deployment_authority": False,
            "summary": "Advisory model-review component only. Source references are checked; claims are not reproduced."}


def refused_model_report(code: str) -> dict:
    """Keep the versioned verdict contract when caller preflight cannot enter the core."""
    report = _blank_report()
    report["reasons"] = [code if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,80}", code)
                         else "gate_action_refused"]
    report["report_hash"] = digest(canonical(report))
    validate_model_report(report)
    return report


def prepare_model_source(repo: Path, base: str, head: str, policy) -> dict:
    """Shared offline source construction; never reads a provider key or ledger."""
    rules, config = policy.document["model_review"], policy.config
    ancestor = git(repo, "merge-base", base, head)
    paths = list(filter(None, git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                                 "--name-only", "-z", ancestor, head, binary=True).decode().split("\0")))
    if not paths:
        raise AssistantError("empty_review_scope")
    if len(paths) > rules["max_files"]:
        raise AssistantError("gate_file_count_exceeded")
    guarded = set(paths)
    guarded.update(filter(None, git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                                   "--name-only", "-z", base, head, binary=True).decode().split("\0")))
    if policy.path in guarded:
        raise AssistantError("gate_policy_change_requires_review")
    if any(PurePosixPath(path).name == ".gitignore" for path in guarded):
        raise AssistantError("gate_ignore_change_requires_review")
    for path in paths:
        _scope_path(path)
        if any(path.startswith(prefix) if prefix.endswith("/") else path == prefix
               for prefix in rules["deny_paths"]):
            raise AssistantError("gate_denied_path")
        if not config.allows(path):
            raise AssistantError("gate_path_not_allowed")
    _screen_ignores(repo, {base, ancestor}, paths)
    packet = build_packet(repo, base, head, config)
    if packet["omitted"] or len(packet["files"]) != len(paths):
        raise AssistantError("scope_incomplete")
    return packet


def prepare_model_request(policy, packet: dict) -> tuple[str, dict, str]:
    """Bind screened source to the exact wire body; credentials stay out of hashes."""
    config = policy.config
    schema, system = review_schema(), config.instructions()
    shape = request_shape(config, system, packet, schema)
    request_hash, body = request_identity(*shape)
    key = os.environ.get(config.key_name, "")
    if key and any(_contains_key(value, key) for value in (packet, shape[0], shape[2])):
        raise AssistantError("gate_key_in_source_context")
    if len(body) > policy.document["model_review"]["max_request_bytes"]:
        raise AssistantError("gate_request_bytes_exceeded")
    return request_hash, schema, system


def model_gate(repo: Path, base: str, head: str, policy_path: str, policy_pin: str, state_dir: Path,
               *, environment=None, transport=None, expected_request_hash: str | None = None) -> dict:
    """Evaluate all policy rules before approving/reserving one exact request.

    Caller-retained state is mandatory. Environment metadata is trusted caller
    wiring, never PR text. The provider reads ONLY its named process variable.
    No retry or fallback occurs, including after missing usage or a timeout.
    """
    report = _blank_report()
    ledger_path, reservation = None, None
    try:
        revision(base)
        revision(head)
        report.update(base=base, head=head)
        repo = regular_path(repo)
        if resolve(repo, base) != base or resolve(repo, head) != head:
            raise AssistantError("gate_revision_mismatch")
        _context(repo, base, head, os.environ if environment is None else environment)
        if state_dir is None:
            raise AssistantError("gate_state_directory_required")
        policy = load_model_policy(repo, base, policy_path, policy_pin)
        report["policy_sha256"] = policy.sha256
        rules, config = policy.document["model_review"], policy.config
        packet = prepare_model_source(repo, base, head, policy)
        # Keys are first accessed here, after identity, scope and screening.
        request_hash, schema, system = prepare_model_request(policy, packet)
        if expected_request_hash is not None and request_hash != expected_request_hash:
            raise AssistantError("gate_request_hash_mismatch")
        report["request_sha256"] = request_hash
        ledger_path = regular_path(Path(state_dir) / "audit.sqlite")
        result, reservation = call_model(
            packet, config, ledger_path, schema, system, network_approved=True,
            approved_packet_hash=packet["packet_hash"],
            policy_approval=PolicyRequestApproval(policy.sha256, request_hash), transport=transport,
        )
        report["usage"] = {"input_tokens": result.input_tokens, "output_tokens": result.output_tokens}
        if result.input_tokens is None or result.output_tokens is None:
            raise AssistantError("unreconciled_model_usage")
        key = os.environ.get(config.key_name, "")
        if key and key in result.text:
            raise AssistantError("gate_provider_echoed_key")
        try:
            data = json.loads(result.text)
        except ValueError as exc:
            raise AssistantError("review_json_invalid") from exc
        if key and _contains_key(data, key):
            raise AssistantError("gate_provider_echoed_key")
        validate_review(data, packet, config=config)
        report["findings"] = [{"severity": finding["severity"], "file": finding["path"],
                               "line": finding["line"], "claim": finding["claim"],
                               "evidence_status": "source-reference-validated-not-reproduced"}
                              for finding in data["findings"]]
        report["verdict"] = "FAIL" if any(f["severity"] in rules["blocking_severities"]
                                          for f in data["findings"]) else "PASS"
        if report["verdict"] == "FAIL":
            report["reasons"] = ["gate_blocking_findings"]
    except AssistantError as exc:
        code = exc.code if re.fullmatch(r"[a-z][a-z0-9_]{0,80}", exc.code) else "gate_failed"
        report["reasons"] = [code]
    except Exception:
        # A malformed input, provider transport, audit or output failure never
        # returns success or exposes exception strings/paths/source/credentials.
        report["reasons"] = ["gate_input_or_audit_unavailable"]
    if ledger_path is not None and ledger_path.exists():
        try:
            with Ledger(ledger_path, read_only=True) as ledger, ledger.transaction():
                ledger.verify()
                held = sum((Decimal(row["reserved"]) for row in ledger.open_reservations()), Decimal(0))
                report["spend"]["reserved_usd"] = str(held)
                if reservation:
                    row = ledger.db.execute("SELECT actual FROM reservations WHERE id=?", (reservation,)).fetchone()
                    report["spend"]["actual_usd"] = row[0] if row else None
                if ledger.open_reservations():
                    report.update(verdict="BLOCKED", reasons=sorted(set(report["reasons"] + ["unreconciled_model_usage"])), findings=[])
        except Exception:
            report.update(verdict="BLOCKED", reasons=["gate_audit_unavailable"], findings=[])
    report["report_hash"] = digest(canonical(report))
    validate_model_report(report)
    return report
