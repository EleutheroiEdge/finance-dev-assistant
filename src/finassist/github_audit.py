"""Bounded, explicit GitHub metadata GETs. No settings, PR, merge or deploy writes."""

from datetime import datetime, timezone
import json
import os
import re
import subprocess
from urllib.parse import quote

from .config import Config
from .platform_support import find_tool
from .errors import AssistantError
from .security import canonical, digest


def inspect_github(repository: str, branch: str, config: Config, *, network_approved: bool) -> dict:
    config.validate()
    if not config.allow_network or not network_approved:
        raise AssistantError("network_not_approved")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
        raise AssistantError("github_repository_invalid")
    if (
        not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}", branch)
        or any(part in {"", ".", ".."} for part in branch.split("/"))
        or ".." in branch
    ):
        raise AssistantError("github_branch_invalid")
    executable = find_tool("gh")
    requests = []
    # Retain only the existing CLI's required OS/auth inputs. Do not inherit
    # unrelated provider keys, proxy/debug routing or GH host/repo/config overrides.
    names = (
        "PATH",
        "HOME",
        "LANG",
        "SYSTEMROOT",
        "SystemRoot",
        "WINDIR",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "WSL_INTEROP",
        "WSL_DISTRO_NAME",
    )
    names += (
        ("GH_TOKEN", "GITHUB_TOKEN")
        if config.github_host == "github.com"
        else ("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
    )
    environment = {name: os.environ[name] for name in names if name in os.environ}
    if config.github_host.endswith(".ghe.com"):
        # gh uses the cloud token variable for ghe.com. Only an explicitly
        # supplied Enterprise credential may populate it for another tenant.
        enterprise = environment.pop("GH_ENTERPRISE_TOKEN", None) or environment.pop(
            "GITHUB_ENTERPRISE_TOKEN", None
        )
        if enterprise:
            environment["GH_TOKEN"] = enterprise
    environment.update(GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1")

    def get(suffix: str, *, missing_ok: bool = False):
        endpoint = "repos/" + repository + suffix
        requests.append(digest(endpoint.encode()))
        try:
            result = subprocess.run(
                [executable, "api", endpoint, "--hostname", config.github_host],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=min(config.timeout_seconds, 120),
                check=False,
                env=environment,
            )
            if len(result.stdout.encode()) > 1_000_000:
                raise AssistantError("github_metadata_limit")
            value = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise AssistantError("github_metadata_unavailable") from exc
        if (
            missing_ok
            and result.returncode != 0
            and isinstance(value, dict)
            and str(value.get("status")) == "404"
        ):
            return None
        if result.returncode != 0 or not isinstance(value, (dict, list)):
            raise AssistantError("github_metadata_unavailable")
        return value

    metadata = get("")
    branch_path = "/branches/" + quote(branch, safe="")
    before = get(branch_path)
    protection = get(branch_path + "/protection", missing_ok=True)
    rules = get("/rules/branches/" + quote(branch, safe=""))
    after = get(branch_path)
    if (
        not isinstance(metadata, dict)
        or metadata.get("full_name", "").lower() != repository.lower()
        or not isinstance(before, dict)
        or not isinstance(after, dict)
        or before.get("name") != branch
        or before != after
        or not isinstance(rules, list)
    ):
        raise AssistantError("github_snapshot_changed_or_invalid")
    commit = before.get("commit")
    if not isinstance(commit, dict):
        raise AssistantError("github_head_invalid")
    observed_head = commit.get("sha", "")
    if not re.fullmatch(r"[0-9a-f]{40,64}", observed_head):
        raise AssistantError("github_head_invalid")
    issues, controls, observations = [], {}, []
    if before.get("protected") is not True and not rules:
        issues.append("branch_unprotected")
    if protection is None:
        issues.append("classic_protection_absent")
        if rules:
            issues.append("ruleset_equivalence_requires_review")
    elif not isinstance(protection, dict):
        raise AssistantError("github_protection_invalid")
    else:
        checks = protection.get("required_status_checks") or {}
        if not isinstance(checks, dict):
            raise AssistantError("github_protection_invalid")
        reviews = protection.get("required_pull_request_reviews")

        def flag(name: str, expected: bool) -> bool:
            value = protection.get(name)
            return isinstance(value, dict) and value.get("enabled") is expected

        controls = {
            "pull_request_required": isinstance(reviews, dict),
            "required_approvals": reviews.get("required_approving_review_count")
            if isinstance(reviews, dict)
            else None,
            "ci_required": bool(checks.get("checks") or checks.get("contexts")),
            "up_to_date_required": checks.get("strict") is True,
            "admins_enforced": flag("enforce_admins", True),
            "force_pushes_disabled": flag("allow_force_pushes", False),
            "deletion_disabled": flag("allow_deletions", False),
        }
        for name, enabled in controls.items():
            if name != "required_approvals" and enabled is not True:
                issues.append(name + "_missing")
        if controls["required_approvals"] == 0:
            observations.append("formal_approvals_not_required")
    report = {
        "repository": repository,
        "host": config.github_host,
        "branch": branch,
        "observed_head": observed_head,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "protected": before.get("protected") is True,
        "controls": controls,
        "issues": sorted(issues),
        "observations": observations,
        "effective_rule_count": len(rules),
        "requests": requests,
        "status": "attention-required" if issues else "configuration-observed",
        "merge_authority": False,
        "deployment_authority": False,
        "qualification": "Read-only configuration snapshot. Ruleset equivalence, current PR approval/CI/threads and deployment evidence need separate verification. No setting was changed.",
    }
    return {**report, "snapshot_hash": digest(canonical(report))}
