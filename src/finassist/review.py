"""Advisory reviews with validated source references and private budget receipts."""

from __future__ import annotations

from .platform_support import read_utf8

from decimal import Decimal
from dataclasses import asdict, dataclass
from importlib.resources import files
import json
from pathlib import Path
import re

import jsonschema

from .config import Config
from .errors import AssistantError
from .ledger import Ledger
from .providers import invoke, request_identity, request_shape
from .scope import triage, verify_packet, review_omissions
from .security import canonical, check_text, digest


@dataclass(frozen=True)
class PolicyRequestApproval:
    """A computed policy decision, not a replacement for the policy evaluator."""

    policy_sha256: str
    request_sha256: str

    def validate(self, actual_request_hash: str) -> None:
        if any(not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
               for value in (self.policy_sha256, self.request_sha256)):
            raise AssistantError("policy_request_approval_invalid")
        if self.request_sha256 != actual_request_hash:
            raise AssistantError("request_approval_mismatch")


def review_schema() -> dict:
    return json.loads(read_utf8(files("finassist").joinpath("resources/review.schema.json")))


def validate_review(
    result: dict, packet: dict, *, extra_patterns: tuple[str, ...] = (), config: Config | None = None
) -> None:
    verify_packet(packet, config)
    try:
        jsonschema.Draft202012Validator(review_schema()).validate(result)
    except jsonschema.ValidationError as exc:
        raise AssistantError("review_schema_invalid") from exc
    if result["head"] != packet["head"]:
        raise AssistantError("review_head_mismatch")
    source = {f["path"]: f for f in packet["files"]}
    if set(result["reviewed_paths"]) != set(source):
        raise AssistantError("review_coverage_mismatch")
    for finding in result["findings"]:
        if finding["path"] not in source:
            raise AssistantError("finding_outside_scope")
        current = source[finding["path"]]
        if finding["line"] > max(
            1, *(len((current[side] or "").splitlines()) for side in ("before", "after"))
        ):
            raise AssistantError("finding_line_invalid")
        if not any(e["path"] == finding["path"] for e in finding["evidence"]):
            raise AssistantError("finding_evidence_invalid")
        if not any(
            e["path"] == finding["path"]
            and current[e["side"]] is not None
            and finding["line"] <= max(1, len(current[e["side"]].splitlines()))
            for e in finding["evidence"]
        ):
            raise AssistantError("finding_line_invalid")
        for evidence in finding["evidence"]:
            file = source.get(evidence["path"])
            if (
                file is None
                or file[evidence["side"] + "_hash"] != evidence["sha256"]
                or file[evidence["side"]] is None
                or evidence["line"] > max(1, len(file[evidence["side"]].splitlines()))
            ):
                raise AssistantError("finding_evidence_invalid")
    check_text(canonical(result).decode(), extra_patterns=extra_patterns)


def call_model(
    packet: dict,
    config: Config,
    ledger_path: Path,
    schema: dict,
    system: str,
    *,
    network_approved: bool,
    approved_packet_hash: str | None,
    transport=None,
    policy_approval: PolicyRequestApproval | None = None,
):
    verify_packet(packet, config)
    config.validate()
    check_text(canonical(packet).decode(), extra_patterns=config.extra_sensitive_patterns)
    if approved_packet_hash != packet["packet_hash"]:
        raise AssistantError("packet_approval_required")
    if not config.allow_network or not network_approved:
        raise AssistantError("network_not_approved")
    if config.profile != packet["profile"]:
        raise AssistantError("profile_mismatch")
    if len(canonical({k: v for k, v in packet.items() if k != "packet_hash"})) > config.max_packet_bytes:
        raise AssistantError("packet_limit_exceeded")
    for file in packet["files"]:
        if not config.allows(file["path"]):
            raise AssistantError("scope_not_approved")
        for side in ("before", "after"):
            if file[side] is not None:
                if len(file[side].encode()) > config.file_byte_limit(file["path"]):
                    raise AssistantError("file_limit_exceeded")
                check_text(file[side], extra_patterns=config.extra_sensitive_patterns)
    if not packet["changed_paths"]:
        raise AssistantError("empty_review_scope")
    if review_omissions(packet) and not config.allow_partial_review:
        raise AssistantError("scope_incomplete")
    if not packet["files"]:
        raise AssistantError("empty_model_context")
    shape = request_shape(config, system, packet, schema)  # credential/config preflight, no IO
    request_hash, request_body = request_identity(*shape)
    if policy_approval is not None:
        policy_approval.validate(request_hash)
    paid = config.provider != "ollama"
    if paid and (config.input_usd_per_million <= 0 or config.output_usd_per_million <= 0):
        raise AssistantError("provider_prices_required")
    if not config.allow_network or not network_approved:
        raise AssistantError("network_not_approved")
    # A conservative byte-based estimate plus envelope allowance is a planning
    # reservation, not a provider-enforced billing cap or tokenizer guarantee.
    input_bound = len(canonical(packet)) + len(system.encode()) + 16_384
    if policy_approval is not None:
        input_bound = max(input_bound, len(request_body) + 16_384)
    price_in, price_out = (
        Decimal(str(config.input_usd_per_million)),
        Decimal(str(config.output_usd_per_million)),
    )
    estimate = (Decimal(input_bound) * price_in + Decimal(config.max_output_tokens) * price_out) / 1_000_000
    with Ledger(ledger_path) as ledger:
        ledger.verify()
        reservation = ledger.reserve(
            estimate,
            Decimal(str(config.daily_budget_usd)),
            Decimal(str(config.max_run_usd)),
            Decimal(str(config.monthly_budget_usd)),
            require_reconciled=policy_approval is not None,
        )
        if policy_approval is not None:
            ledger.append({
                "event": "request_approved", "approved_by": "policy",
                "policy_sha256": policy_approval.policy_sha256,
                "request_sha256": policy_approval.request_sha256,
                "reservation": reservation,
            })
        ledger.append(
            {
                "event": "review_requested",
                "reservation": reservation,
                "packet_hash": packet["packet_hash"],
                "provider": config.provider,
                "model": config.model,
                "profile": config.profile,
                "config_hash": digest(canonical(asdict(config))),
            }
        )
        result = invoke(config, system, packet, schema, network_approved=True, transport=transport,
                        approved_request_hash=policy_approval.request_sha256 if policy_approval else None)
        ledger.append(
            {
                "event": "model_usage",
                "reservation": reservation,
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
            }
        )
        # Settle usage before validating semantics, including refused/malformed output.
        if price_in == price_out == 0 and (
            policy_approval is None or (result.input_tokens is not None and result.output_tokens is not None)
        ):
            ledger.settle(reservation, Decimal(0))
        elif result.input_tokens is not None and result.output_tokens is not None:
            actual = (
                Decimal(result.input_tokens) * price_in + Decimal(result.output_tokens) * price_out
            ) / 1_000_000
            if result.input_tokens > input_bound or actual > Decimal(str(config.max_run_usd)):
                ledger.append({"event": "provider_usage_out_of_bounds", "reservation": reservation})
                raise AssistantError("provider_usage_exceeds_limit")
            ledger.settle(reservation, actual)
        return result, reservation


def review_packet(
    packet: dict,
    config: Config,
    ledger_path: Path,
    *,
    network_approved: bool = False,
    approved_packet_hash: str | None = None,
    transport=None,
) -> dict:
    verify_packet(packet, config)
    config.validate()
    check_text(canonical(packet).decode(), extra_patterns=config.extra_sensitive_patterns)
    triaged = triage(packet, config)
    if not packet["changed_paths"]:
        raise AssistantError("empty_review_scope")
    if config.provider == "offline":
        return {
            "status": "offline-analysis",
            "packet_hash": packet["packet_hash"],
            "head": packet["head"],
            "provider": "offline",
            "triage": triaged,
            "findings": [],
            "qualification": "No model review or test execution performed.",
            "merge_authority": False,
        }
    result, reservation = call_model(
        packet,
        config,
        ledger_path,
        review_schema(),
        config.instructions(),
        network_approved=network_approved,
        approved_packet_hash=approved_packet_hash,
        transport=transport,
    )
    try:
        data = json.loads(result.text)
    except ValueError as exc:
        raise AssistantError("review_json_invalid") from exc
    validate_review(data, packet, extra_patterns=config.extra_sensitive_patterns, config=config)
    report = {
        "status": "partial-review"
        if review_omissions(packet)
        else ("findings" if data["findings"] else "no-findings-reported"),
        "packet_hash": packet["packet_hash"],
        "head": packet["head"],
        "base": packet["base"],
        "provider": config.provider,
        "model": config.model,
        "config_hash": digest(canonical(asdict(config))),
        "review": data,
        "triage": triaged,
        "reservation": reservation,
        "merge_authority": False,
        "omitted": packet["omitted"],
        "qualification": "Source-bound advisory findings. Reproductions have not been executed.",
    }
    with Ledger(ledger_path) as ledger:
        report["receipt"] = ledger.append(
            {
                "event": "review_completed",
                "packet_hash": packet["packet_hash"],
                "report_hash": digest(canonical(report)),
                "profile": config.profile,
                "findings_by_severity": {
                    severity: sum(f["severity"] == severity for f in data["findings"])
                    for severity in ("critical", "high", "medium", "low", "info")
                },
            }
        )
    return report
