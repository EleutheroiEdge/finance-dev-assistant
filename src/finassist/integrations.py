"""Export reviewed integration templates without touching a user's agent setup."""

from dataclasses import asdict
from importlib.resources import files
from pathlib import Path

from .config import Config
from .errors import AssistantError
from .guides import GUIDES
from .security import canonical, regular_path, write_private


def export_kit(destination: Path) -> dict:
    destination = regular_path(destination)
    if destination.exists():
        raise AssistantError("integration_destination_exists")
    destination.mkdir(mode=0o700, parents=True)
    mapping = {
        "schemas/finassist.schema.json": "finassist.schema.json",
        "schemas/model-gate-report.schema.json": "model-gate-report.schema.json",
        "examples/model-gate/policy.json": "model-gate-policy.json",
        "examples/model-gate/caller.py": "model-gate-caller.py",
        "evidence-review/SKILL.md": "skill.md",
        "roles/claude-reviewer.md": "claude-reviewer.md",
        "roles/codex-reviewer.toml": "codex-reviewer.toml",
        "examples/fork-config.json": "fork-config.json",
        "examples/dashboard.json": "dashboard-config.json",
        "examples/cash-workflow.json": "cash-workflow.json",
        "examples/github-actions/finassist-ci.json": "github-ci-policy.json",
        "examples/workflow-packs/bundle.json": "cash-workflow-bundle.json",
        "examples/workflow-packs/workflow.json": "cash-workflow-pack.json",
        "examples/workflow-packs/checks.json": "cash-check-pack.json",
        "examples/workflow-packs/profile.json": "cash-profile-pack.json",
        "examples/workflow-packs/policy.json": "cash-policy-pack.json",
        "examples/profiles/engineering.json": "engineering-profile.json",
        "docs/maintainers/branch-protection-proposal.json": "branch-protection-proposal.json",
    }
    mapping.update({source: resource for _, source, resource in GUIDES.values()})
    for target, resource in mapping.items():
        content = files("finassist").joinpath("resources/" + resource).read_bytes()
        write_private(destination / target, content)
    write_private(destination / "configuration.json", canonical(asdict(Config())) + b"\n")
    write_private(
        destination / "README.txt",
        (
            "Review these templates, then copy only the desired skill/role into your host's documented location.\n"
            "Resolve the installed skill path when adapting role files. Do not replace existing project rules,\n"
            "credentials, model routes or permissions. Configuration is offline by default.\n"
        ).encode(),
    )
    return {"directory": str(destination), "templates": list(mapping), "installed_into_host": False}
