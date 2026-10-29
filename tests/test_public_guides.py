"""Public navigation, neutral review handoffs and portable host recipes."""

from html.parser import HTMLParser
from pathlib import Path
import re
import shlex
import subprocess
import sys
from urllib.parse import unquote, urlsplit

import comrak
import pytest

from finassist.integrations import export_kit

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "/EleutheroiEdge/finance-dev-assistant/"


class Targets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.targets = []

    def handle_starttag(self, tag, attrs):
        self.targets.extend(value for key, value in attrs if key in {"href", "src"})

    handle_startendtag = handle_starttag


def targets(text):
    options = comrak.RenderOptions()
    options.unsafe_ = True
    parser = Targets()
    parser.feed(comrak.render_markdown(text, render_options=options))
    parser.close()
    return parser.targets


def repository_path(target, source):
    parsed = urlsplit(target)
    path = unquote(parsed.path)
    if parsed.netloc:
        prefixes = {
            "github.com": [REPOSITORY + "blob/main/", REPOSITORY + "tree/main/"],
            "raw.githubusercontent.com": [REPOSITORY + "main/"],
        }.get(parsed.hostname, [])
        prefix = next((prefix for prefix in prefixes if path.startswith(prefix)), None)
        return (ROOT / path[len(prefix):]).resolve() if prefix else None
    if parsed.scheme or not path:
        return None
    return (source.parent / path).resolve()


def assert_link_exists(target, source):
    path = repository_path(target, source)
    if path is not None:
        assert path.is_relative_to(ROOT) and path.exists(), (source.relative_to(ROOT), target)


def test_llms_convention_links_are_absolute_and_resolve():
    text = (ROOT / "llms.txt").read_text(encoding="utf-8")
    assert text.startswith("# finledgerpoli\n\n> ")
    links = targets(text)
    expected = {"README.md", "docs/agents.md", "docs/configuration.md", "schemas/finassist.schema.json",
                "docs/cli-contracts.md", "docs/providers.md", "docs/threat-model.md"}
    actual = set()
    for target in links:
        parsed = urlsplit(target)
        assert parsed.scheme == "https" and parsed.hostname == "github.com"
        path = repository_path(target, ROOT / "llms.txt")
        assert path is not None and path.is_file(), target
        actual.add(path.relative_to(ROOT).as_posix())
    assert expected <= actual


def test_user_guide_links_and_renamed_documents_resolve():
    for source in (ROOT / "docs").rglob("*.md"):
        for target in targets(source.read_text(encoding="utf-8")):
            assert_link_exists(target, source)
    for name in ["releasing.md", "repository-settings.md", "branch-protection-proposal.json"]:
        assert (ROOT / "docs/maintainers" / name).is_file()
    assert (ROOT / "docs/security-design.md").is_file()
    assert (ROOT / "docs/design-principles.md").is_file()
    assert not (ROOT / "docs/security-review.md").exists()
    assert not (ROOT / "docs/production-design.md").exists()
    # Old URLs remain useful while the marketing README is owned separately.
    for name in ["releasing.md", "repository-settings.md"]:
        assert f"(maintainers/{name})" in (ROOT / "docs" / name).read_text(encoding="utf-8")


def test_exported_guide_relative_links_resolve_inside_kit(tmp_path):
    destination = tmp_path / "kit"
    export_kit(destination)
    for source in destination.rglob("*.md"):
        for target in targets(source.read_text(encoding="utf-8")):
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            path = (source.parent / unquote(parsed.path)).resolve()
            assert path.is_relative_to(destination) and path.exists(), (source.relative_to(destination), target)


def test_public_docs_have_no_internal_review_or_dated_memo_headers():
    sources = list((ROOT / "docs").rglob("*.md"))
    sources += list((ROOT / "src/finassist/resources").glob("*.md"))
    sources += [ROOT / name for name in ["AGENTS.md", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md",
                                       ".github/pull_request_template.md", "llms.txt"]]
    for source in sources:
        text = source.read_text(encoding="utf-8")
        assert "Ready for Claude" not in text, source
        assert "upstream owner" not in text.lower(), source
        assert not re.search(r"(?im)^(?:#+\s*.*\b(?:memo|reviewed|dated)\b.*\b20\d{2}\b|Reviewed\s+\w+\s+\d{1,2},\s+20\d{2})", text), source
    template = (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8")
    assert "Ready for review at <full commit sha>" in template


@pytest.mark.parametrize("host,relative", [
    ("Claude Code", ".claude/skills/evidence-review"),
    ("Codex", ".agents/skills/evidence-review"),
    ("Cursor", ".cursor/skills/evidence-review"),
])
def test_agent_copy_recipes_are_portable_and_never_overwrite(tmp_path, host, relative):
    export_kit(tmp_path / "assistant-integration")
    existing_rules = tmp_path / "AGENTS.md"
    existing_rules.write_text("Synthetic governing policy\n", encoding="utf-8", newline="\n")
    document = (ROOT / "docs/agents.md").read_text(encoding="utf-8")
    section = document.split("### " + host + "\n", 1)[1].split("\n### ", 1)[0]
    command = re.search(r'```sh\n(python -c .+)\n```', section).group(1)
    argv = shlex.split(command)
    argv[0] = sys.executable
    subprocess.run(argv, cwd=tmp_path, check=True, shell=False, capture_output=True)
    installed = tmp_path / relative / "SKILL.md"
    assert installed.read_bytes() == (ROOT / "skills/evidence-review/SKILL.md").read_bytes()
    installed.write_text("Existing reviewed skill\n", encoding="utf-8", newline="\n")
    repeated = subprocess.run(argv, cwd=tmp_path, check=False, shell=False, capture_output=True)
    assert repeated.returncode != 0
    assert installed.read_text(encoding="utf-8") == "Existing reviewed skill\n"
    assert existing_rules.read_text(encoding="utf-8") == "Synthetic governing policy\n"
