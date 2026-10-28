"""Advisory reviews with validated source references and private budget receipts."""

from __future__ import annotations

from .platform_support import read_utf8

from decimal import Decimal
from dataclasses import asdict
from importlib.resources import files
import json
from pathlib import Path

import jsonschema

from .config import Config
from .errors import AssistantError
from .ledger import Ledger
from .profiles import instructions
from .providers import invoke, request_shape
from .scope import triage, verify_packet
from .security import canonical, check_text, digest


def review_schema() -> dict:
    return json.loads(read_utf8(files("finassist").joinpath("resources/review.schema.json")))


def validate_review(result: dict, packet: dict, *, extra_patterns: tuple[str, ...] = ()) -> None:
    verify_packet(packet)
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
):
    verify_packet(packet)
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
                if len(file[side].encode()) > config.max_file_bytes:
                    raise AssistantError("file_limit_exceeded")
                check_text(file[side], extra_patterns=config.extra_sensitive_patterns)
    if not packet["changed_paths"]:
        raise AssistantError("empty_review_scope")
    if packet["omitted"] and not config.allow_partial_review:
        raise AssistantError("scope_incomplete")
    if not packet["files"]:
        raise AssistantError("empty_model_context")
    request_shape(config, system, packet, schema)  # credential/config preflight, no IO
    paid = config.provider != "ollama"
    if paid and (config.input_usd_per_million <= 0 or config.output_usd_per_million <= 0):
        raise AssistantError("provider_prices_required")
    if not config.allow_network or not network_approved:
        raise AssistantError("network_not_approved")
    # A conservative byte-based estimate plus envelope allowance is a planning
    # reservation, not a provider-enforced billing cap or tokenizer guarantee.
    input_bound = len(canonical(packet)) + len(system.encode()) + 16_384
    price_in, price_out = (
        Decimal(str(config.input_usd_per_million)),
        Decimal(str(config.output_usd_per_million)),
    )
    estimate = (Decimal(input_bound) * price_in + Decimal(config.max_output_tokens) * price_out) / 1_000_000
    with Ledger(ledger_path) as ledger:
        ledger.verify()
        reservation = ledger.reserve(
            estimate, Decimal(str(config.daily_budget_usd)), Decimal(str(config.max_run_usd))
        )
        ledger.append(
            {
                "event": "review_requested",
                "reservation": reservation,
                "packet_hash": packet["packet_hash"],
                "provider": config.provider,
                "model": config.model,
                "config_hash": digest(canonical(asdict(config))),
            }
        )
        result = invoke(config, system, packet, schema, network_approved=True, transport=transport)
        # Settle usage before validating semantics, including refused/malformed output.
        if price_in == price_out == 0:
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
    verify_packet(packet)
    config.validate()
    check_text(canonical(packet).decode(), extra_patterns=config.extra_sensitive_patterns)
    triaged = triage(packet)
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
        instructions(config.profile),
        network_approved=network_approved,
        approved_packet_hash=approved_packet_hash,
        transport=transport,
    )
    try:
        data = json.loads(result.text)
    except ValueError as exc:
        raise AssistantError("review_json_invalid") from exc
    validate_review(data, packet, extra_patterns=config.extra_sensitive_patterns)
    report = {
        "status": "partial-review"
        if packet["omitted"]
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
            }
        )
    return report
