"""Public product claims, metadata and canonical guide navigation stay in sync."""

from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parent.parent
DESCRIPTION = ("AI code review for financial software that keeps your code local and backs every finding "
               "with evidence. Works with OpenAI, Anthropic, Gemini or Ollama.")
KEYWORDS = ["ai code review", "code review", "llm", "finance", "fintech", "quantitative finance",
            "portfolio optimization", "rebalancing", "model risk", "audit trail", "reproducibility",
            "developer tools", "local-first", "offline", "ollama", "ai agents"]
CLASSIFIERS = [
    "Development Status :: 4 - Beta", "Environment :: Console", "Environment :: Web Environment",
    "Intended Audience :: Developers", "Intended Audience :: Financial and Insurance Industry",
    "Operating System :: OS Independent", "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.11", "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13", "Topic :: Office/Business :: Financial :: Investment",
    "Topic :: Software Development :: Quality Assurance", "Topic :: Software Development :: Testing",
]


def test_metadata_llms_and_about_description_agree():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == "0.4.0"
    assert project["description"] == DESCRIPTION
    assert project["keywords"] == KEYWORDS
    assert project["classifiers"] == CLASSIFIERS
    assert "mcp" not in project["keywords"]
    summary = (ROOT / "llms.txt").read_text(encoding="utf-8").splitlines()[2]
    assert summary == "> " + DESCRIPTION
    settings = (ROOT / "docs/maintainers/repository-settings.md").read_text(encoding="utf-8")
    assert DESCRIPTION in settings
    assert "https://pypi.org/project/finledgerpoli/" in settings
    topics = settings.split("**Topics (20):** ")[1].splitlines()[0]
    assert len(re.findall(r"`([^`]+)`", topics)) == 20
    assert "brand/social-dark.png" in settings


def test_readme_has_plain_headings_in_requested_order_and_audience_table():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.startswith("# finledgerpoli\n\n")
    assert re.findall(r"^## (.+)$", readme, re.MULTILINE) == [
        "Why finledgerpoli", "Who it's for", "Quick start", "How it works", "Dashboard",
        "Use it with AI agents", "Guides", "Safety and limits", "Contribute", "License",
    ]
    assert not re.search(r"<h[1-6](?:>|\s)", readme)
    assert readme.count("[![") == 3
    audience = readme.split("## Who it's for\n", 1)[1].split("\n## Quick start", 1)[0]
    assert "| When you... | finledgerpoli helps you... |" in audience
    assert len([line for line in audience.splitlines() if line.startswith("| ")]) == 7
    assert "**Why not a general AI code reviewer?**" in audience
    # Examples retain literal CLI syntax; prose must use everyday terms.
    prose = re.sub(r"```.*?```|`[^`]*`", "", readme, flags=re.DOTALL)
    assert not re.search(r"\b(packet|oracle|operator|receipt)\b|fail closed|readiness eligibility", prose, re.I)
    assert "audit evidence for your change records" in audience


def test_docs_define_receipt_once_and_use_saved_record_in_prose():
    definitions = []
    for path in (ROOT / "docs").rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        # Command flags and JSON field spellings remain exact technical contracts.
        prose = re.sub(r"```.*?```|`[^`]*`", "", text, flags=re.DOTALL)
        for line in prose.splitlines():
            if re.search(r"\breceipts?\b", line, re.I):
                definitions.append((path.relative_to(ROOT).as_posix(), line))
    assert len(definitions) == 1
    assert definitions[0][0] == "docs/cli-contracts.md"
    assert "saved record" in definitions[0][1]
    assert "--receipt" in (ROOT / "docs/readiness-and-auditing.md").read_text(encoding="utf-8")


def test_navigation_does_not_link_deleted_redirect_pages():
    old = {"docs/releasing.md", "docs/repository-settings.md", "docs/security-review.md", "docs/production-design.md"}
    for name in old:
        assert not (ROOT / name).exists()
    sources = [ROOT / "README.md", ROOT / "llms.txt", *(ROOT / "docs").rglob("*.md")]
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for name in old:
            assert name not in text, (source, name)
        assert not re.match(r"# .*\n\n.*(?:moved to|redirect)", text, re.I), source
