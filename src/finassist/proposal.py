"""Generate code proposals as data; applying them is an independent operator action."""

import json
from pathlib import Path

import jsonschema

from .config import Config
from .errors import AssistantError
from .patching import patch_paths
from .ledger import Ledger
from .profiles import instructions
from .review import call_model
from .security import canonical, check_text, digest

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["head", "patch", "summary"],
    "properties": {
        "head": {"type": "string"},
        "patch": {"type": "string", "maxLength": 120000},
        "summary": {"type": "string", "minLength": 1, "maxLength": 4000},
    },
}


def propose(
    packet: dict,
    config: Config,
    ledger_path: Path,
    *,
    network_approved: bool,
    approved_packet_hash: str,
    transport=None,
) -> dict:
    system = instructions(config.profile) + (
        "\nPropose the smallest corrective unified Git patch for concrete defects. "
        "Do not change policy, credentials, deployment, permissions or protected paths. "
        "Do not execute commands. Use only supplied paths and the exact head. "
        "Return head, patch and summary. Do not invent extra requirements."
    )
    result, reservation = call_model(
        packet,
        config,
        ledger_path,
        SCHEMA,
        system,
        network_approved=network_approved,
        approved_packet_hash=approved_packet_hash,
        transport=transport,
    )
    try:
        artifact = json.loads(result.text)
        jsonschema.validate(artifact, SCHEMA)
    except (ValueError, jsonschema.ValidationError) as exc:
        raise AssistantError("proposal_schema_invalid") from exc
    if artifact["head"] != packet["head"]:
        raise AssistantError("proposal_head_mismatch")
    check_text(canonical(artifact).decode(), extra_patterns=config.extra_sensitive_patterns)
    paths = patch_paths(artifact["patch"], config)
    if not set(paths) <= {file["path"] for file in packet["files"]}:
        raise AssistantError("proposal_outside_review_scope")
    proposal = {
        "artifact": artifact,
        "approval_hash": digest(canonical(artifact)),
        "reservation": reservation,
        "applied": False,
    }
    with Ledger(ledger_path) as ledger:
        proposal["audit_receipt"] = ledger.append(
            {
                "event": "proposal_completed",
                "head": artifact["head"],
                "packet_hash": packet["packet_hash"],
                "proposal_hash": proposal["approval_hash"],
            }
        )
    return proposal
