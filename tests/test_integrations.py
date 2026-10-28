from importlib.resources import files
from pathlib import Path
import tomllib

import pytest
import yaml

from finassist.errors import AssistantError
from finassist.integrations import export_kit


def test_export_is_explicit_and_never_overwrites_host_configuration(tmp_path):
    destination = tmp_path / "kit"
    result = export_kit(destination)
    assert result["installed_into_host"] is False
    assert (destination / "configuration.json").exists()
    skill = (destination / "evidence-review/SKILL.md").read_text()
    frontmatter = yaml.safe_load(skill.split("---", 2)[1])
    assert frontmatter["name"] == "evidence-review" and frontmatter["description"]
    role = tomllib.loads((destination / "roles/codex-reviewer.toml").read_text())
    assert role["sandbox_mode"] == "read-only"
    with pytest.raises(AssistantError, match="integration_destination_exists"):
        export_kit(destination)


@pytest.mark.parametrize(
    "original,resource",
    [
        ("skills/evidence-review/SKILL.md", "skill.md"),
        (".claude/agents/finance-reviewer.md", "claude-reviewer.md"),
        (".codex/agents/finance-reviewer.toml", "codex-reviewer.toml"),
        ("docs/workflows.md", "workflow-guide.md"),
        ("docs/providers.md", "provider-guide.md"),
        ("docs/readiness-and-auditing.md", "readiness-guide.md"),
    ],
)
def test_installed_templates_match_reviewed_source(original, resource):
    root = Path(__file__).parents[1]
    assert (root / original).read_bytes() == files("finassist").joinpath("resources/" + resource).read_bytes()
