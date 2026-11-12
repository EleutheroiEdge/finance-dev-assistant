"""Plain doctor report assembly; range preflight and explicit fixes retain their routes."""

from pathlib import Path

from .config import Config
from .health import doctor_report


def doctor_result(args, config: Config) -> tuple[dict, int]:
    from .doctor_environment import environment_report
    from .doctor_package import add_package_details
    from .update_check import check_once

    checked = check_once(network_allowed=config.allow_network) if args.check_updates else None
    state = args.audit_dir or args.state_dir or Path(".finassist")
    report = doctor_report(config, update_check=checked, config_path=args.config,
                           state_dir=state, include_key_read=True)
    report["environment"] = environment_report(config, config_path=args.config, state_dir=state)
    add_package_details(report)
    return report, 1 if report["environment"]["blockers"] else 0


def fix_doctor(args, state: Path) -> dict:
    from .maintenance import fix_local_state

    path = args.config
    if path is None and Path("finassist.json").exists():
        path = Path("finassist.json")
    return fix_local_state(path, state)
