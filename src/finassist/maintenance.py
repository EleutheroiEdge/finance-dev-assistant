"""Explicit local doctor fixes: preflight all changes, preserve backups, no network."""

from pathlib import Path

from .auditing import command_audit
from .config import load_config
from .config_compat import apply_config_migration, preview_config_migration
from .evidence_schema import migrate_evidence_store, resolve_evidence_path
from .health import doctor_report
from .ledger import Ledger
from .security import digest, regular_path


def fix_local_state(config_path: Path | None, state_dir: Path) -> dict:
    state_dir = regular_path(state_dir)
    plan = preview_config_migration(config_path) if config_path is not None else None
    config = load_config(config_path, content=plan.after) if plan is not None else load_config()
    evidence_path = state_dir / "evidence.sqlite"
    evidence_plan = migrate_evidence_store(evidence_path) if resolve_evidence_path(evidence_path).exists() else None
    # Both preflights finish before any backup/DDL/audit write. A future reader
    # floor or newer store cannot be "fixed" by lowering its declared version.
    config_result, evidence_result = None, None
    with command_audit(state_dir / "audit.sqlite", "doctor-fix", config) as outcome:
        if plan is not None:
            config_result = apply_config_migration(plan)
        if evidence_plan is not None:
            evidence_result = migrate_evidence_store(evidence_path, dry_run=False)
        with Ledger(state_dir / "audit.sqlite") as ledger:
            ledger.append({"event": "doctor_fixed", "configuration_changed": bool(config_result and config_result["written"]),
                           "config_source_sha256": digest(plan.before) if plan is not None else None,
                           "config_target_sha256": digest(plan.after) if plan is not None else None,
                           "evidence_changed": bool(evidence_result and evidence_result["written"]),
                           "evidence_source_sha256": (evidence_result or {}).get("source_sha256"),
                           "evidence_target_sha256": (evidence_result or {}).get("destination_sha256")})
        outcome["exit_code"] = 0
    if config_result:
        config_result = {key: value for key, value in config_result.items() if key != "diff"}
    return {**doctor_report(config), "fixes": {"configuration": config_result, "evidence": evidence_result},
            "network_called": False}
