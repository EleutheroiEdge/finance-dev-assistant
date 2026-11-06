"""Argument definitions for first-run setup and local health checks."""
from pathlib import Path

from .config import PROVIDERS


def add_onboarding_commands(commands) -> None:
    init = commands.add_parser("init", help="Create offline-by-default configuration")
    init.add_argument("--output", default="finassist.json")
    init.add_argument("--provider", choices=sorted(PROVIDERS), default="offline")
    init.add_argument("--model", default="")
    init.add_argument("--profile", help="Name in the configured profile registry")
    init.add_argument("--purpose", choices=("accounting", "general", "quant", "research"),
                      help="Choose the review profile by what the code does, instead of --profile")
    init.add_argument("--input-usd-per-million", type=float, help="Input price; required for paid providers")
    init.add_argument("--output-usd-per-million", type=float, help="Output price; required for paid providers")
    init.add_argument("--api-key-env", help="Name of the variable that holds the key; never the key")
    detect = init.add_argument_group("detect", "Propose settings from the committed layout; nothing is run")
    detect.add_argument("--detect", action="store_true", help="Print a proposal; write only with --write")
    detect.add_argument("--repo", help="Repository checkout to read (default: current directory)")
    detect.add_argument("--revision", help="Committed revision to read (default: HEAD)")
    detect.add_argument("--write", action="store_true", help="Also write the proposed configuration")
    doctor = commands.add_parser(
        "doctor", help="Check runtime, provider setup and container availability without network"
    )
    doctor.add_argument("--fix", action="store_true", help="Apply only explicit safe reversible local migrations")
    doctor.add_argument("--state-dir", type=Path)
    doctor.add_argument("--check-updates", action="store_true", help="Check PyPI once when project network use is allowed")
    preflight = doctor.add_argument_group("gate preflight", "Report every gate blocker for one range, offline and without reading a key")
    preflight.add_argument("--policy", help="Gate policy path, read at --base")
    preflight.add_argument("--policy-sha256", help="Expected sha256 of the policy bytes at base")
    preflight.add_argument("--repo", help="Repository checkout; checked before it is used as a path")
    preflight.add_argument("--base")
    preflight.add_argument("--head")
