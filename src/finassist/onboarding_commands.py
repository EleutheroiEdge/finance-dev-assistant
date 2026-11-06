"""Argument definitions for first-run setup and local health checks."""
from pathlib import Path

from .config import PROVIDERS


def add_onboarding_commands(commands) -> None:
    init = commands.add_parser("init", help="Create offline-by-default configuration")
    init.add_argument("--output", default="finassist.json")
    init.add_argument("--provider", choices=sorted(PROVIDERS), default="offline")
    init.add_argument("--model", default="")
    init.add_argument("--profile", help="Name in the configured profile registry")
    doctor = commands.add_parser(
        "doctor", help="Check runtime, provider setup and container availability without network"
    )
    doctor.add_argument("--fix", action="store_true", help="Apply only explicit safe reversible local migrations")
    doctor.add_argument("--state-dir", type=Path)
    doctor.add_argument("--check-updates", action="store_true", help="Check PyPI once when project network use is allowed")
