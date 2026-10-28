"""Export reviewed integration templates without touching a user's agent setup."""

from dataclasses import asdict
from importlib.resources import files
from pathlib import Path

from .config import Config
from .errors import AssistantError
from .security import canonical, regular_path, write_private


def export_kit(destination: Path) -> dict:
    destination = regular_path(destination)
    if destination.exists():
        raise AssistantError("integration_destination_exists")
    destination.mkdir(mode=0o700, parents=True)
    mapping = {
        "evidence-review/SKILL.md": "skill.md",
        "roles/claude-reviewer.md": "claude-reviewer.md",
        "roles/codex-reviewer.toml": "codex-reviewer.toml",
        "docs/workflows.md": "workflow-guide.md",
        "docs/providers.md": "provider-guide.md",
        "docs/readiness-and-auditing.md": "readiness-guide.md",
        "docs/platforms.md": "platform-guide.md",
    }
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
