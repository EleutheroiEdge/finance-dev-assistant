"""Read a fixed registry of packaged guides without configuration or network access."""

from importlib.resources import files

from .errors import AssistantError

# Topic -> (display title, source/export path, installed resource).
GUIDES = {
    "agents": ("AI coding agents", "docs/agents.md", "agents-guide.md"),
    "configuration": ("Configuration", "docs/configuration.md", "configuration-guide.md"),
    "cli-contracts": ("CLI output contracts", "docs/cli-contracts.md", "cli-contracts-guide.md"),
    "workflows": ("Workflows", "docs/workflows.md", "workflow-guide.md"),
    "workflow-plans": ("Workflow plans", "docs/workflow-plans.md", "workflow-plans-guide.md"),
    "workflow-execution": ("Durable workflow execution", "docs/workflow-execution.md", "workflow-execution-guide.md"),
    "workflow-packs": ("Workflow packs", "docs/workflow-packs.md", "workflow-packs-guide.md"),
    "workflow-timelines": ("Workflow audit timelines", "docs/workflow-timelines.md", "workflow-timelines-guide.md"),
    "ci-gates": ("GitHub Actions check gates", "docs/ci-gates.md", "ci-gates-guide.md"),
    "pre-merge-gate": ("Using finledgerpoli as a pre-merge gate", "docs/pre-merge-gate.md", "pre-merge-gate-guide.md"),
    "providers": ("Providers", "docs/providers.md", "provider-guide.md"),
    "readiness": ("Auditing and readiness", "docs/readiness-and-auditing.md", "readiness-guide.md"),
    "platforms": ("Supported platforms", "docs/platforms.md", "platform-guide.md"),
    "threat-model": ("Threat model", "docs/threat-model.md", "threat-model-guide.md"),
    "architecture": ("Architecture", "docs/architecture.md", "architecture-guide.md"),
    "dashboard": ("Dashboard", "docs/dashboard.md", "dashboard-guide.md"),
    "evaluation": ("Evaluation", "docs/evaluation.md", "evaluation-guide.md"),
    "customize": ("Fork and customize", "docs/fork-and-customize.md", "customize-guide.md"),
    "integrations": ("Coding-agent integration", "docs/integrations.md", "integrations-guide.md"),
    "research-inputs": ("Research inputs", "docs/research-inputs.md", "research-inputs-guide.md"),
    "security-design": ("Security design", "docs/security-design.md", "security-design-guide.md"),
    "design-principles": ("Design principles", "docs/design-principles.md", "design-principles-guide.md"),
    "security": ("Security policy", "SECURITY.md", "security-policy.md"),
    "releasing": ("Release preparation", "docs/maintainers/releasing.md", "releasing-guide.md"),
    "repository-settings": (
        "Repository settings", "docs/maintainers/repository-settings.md", "repository-settings-guide.md"
    ),
}


def guide_index() -> dict:
    return {"topics": [{"topic": topic, "title": title} for topic, (title, _, _) in GUIDES.items()]}


def guide_text(topic: str) -> str:
    if topic not in GUIDES:
        raise AssistantError("unknown_guide")
    resource = GUIDES[topic][2]
    return files("finassist").joinpath("resources/" + resource).read_text(encoding="utf-8")
