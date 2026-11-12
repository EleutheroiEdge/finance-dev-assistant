"""Plain doctor report assembly; range preflight and explicit fixes retain their routes."""

from pathlib import Path

from .config import Config
from .health import doctor_report
from .state_location import moved_from, state_location


def doctor_result(args, config: Config) -> tuple[dict, int]:
    from .doctor_environment import environment_report
    from .doctor_package import add_package_details
    from .update_check import check_once

    checked = check_once(network_allowed=config.allow_network) if args.check_updates else None
    state, origin = state_location(args, refuse=False)  # Doctor diagnoses a moved ledger; it does not refuse.
    report = doctor_report(config, update_check=checked, config_path=args.config,
                           state_dir=state, include_key_read=True)
    report["environment"] = environment_report(config, config_path=args.config, state_dir=state)
    if (previous := moved_from(args, state, origin)) is not None:
        from .doctor_environment import _shown_path
        from .error_hints import error_fields

        report["environment"]["paths"]["previous_state"] = {"path": _shown_path(str(previous)), "holds_ledger": True}
        report["environment"]["warnings"].append({"code": "state_location_moved", "path_role": "previous_state",
                                                  **error_fields("state_location_moved")})
    add_package_details(report)
    return report, 1 if report["environment"]["blockers"] else 0


def fix_doctor(args, state: Path) -> dict:
    from .maintenance import fix_local_state

    path = args.config
    if path is None and Path("finassist.json").exists():
        path = Path("finassist.json")
    return fix_local_state(path, state)
