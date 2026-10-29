"""README navigation must work from GitHub and the PyPI description, offline."""

from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import tomllib

import comrak
import pytest
from readme_renderer.markdown import render

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "/EleutheroiEdge/finance-dev-assistant"


class Targets(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.targets = []

    def handle_starttag(self, tag, attrs):
        self.targets.extend(value for key, value in attrs if key in {"href", "src"})

    handle_startendtag = handle_starttag


def html_targets(html):
    parser = Targets()
    parser.feed(html)
    parser.close()
    return parser.targets


def markdown_targets(text):
    # Preserve HTML before sanitization, so invalid links cannot simply disappear.
    options = comrak.RenderOptions()
    options.unsafe_ = True
    return html_targets(comrak.render_markdown(text, render_options=options))


def assert_absolute(targets):
    assert targets, "README unexpectedly has no navigation"
    for target in targets:
        assert isinstance(target, str), "href/src must have a URL"
        parsed = urlsplit(target)
        assert parsed.scheme in {"http", "https"} and parsed.netloc, target


def assert_repository_target_exists(target):
    parsed = urlsplit(target)
    if parsed.hostname == "raw.githubusercontent.com":
        prefix = REPOSITORY + "/main/"
        if not parsed.path.startswith(prefix):
            return
        relative, directory = parsed.path[len(prefix):], False
    elif parsed.hostname == "github.com":
        prefixes = {REPOSITORY + "/blob/main/": False, REPOSITORY + "/tree/main/": True}
        match = next((prefix for prefix in prefixes if parsed.path.startswith(prefix)), None)
        if match is None:
            return
        relative, directory = parsed.path[len(match):], prefixes[match]
    else:
        return
    path = (ROOT / unquote(relative)).resolve()
    assert path.is_relative_to(ROOT), target
    assert path.is_dir() if directory else path.is_file(), target


def test_readme_markdown_and_html_targets_are_absolute_and_exist():
    targets = markdown_targets((ROOT / "README.md").read_text(encoding="utf-8"))
    assert_absolute(targets)
    for target in targets:
        assert_repository_target_exists(target)
    raw = "https://raw.githubusercontent.com" + REPOSITORY + "/main/"
    for name in ["configuration", "statistics", "health"]:
        assert raw + f"docs/images/dashboard-{name}.png" in targets
    assert raw + "docs/images/demo.cast.txt" in targets
    assert "https://github.com" + REPOSITORY + "/tree/main/examples/" in targets


def test_pypi_rendered_description_has_no_relative_links_or_images():
    html = render((ROOT / "README.md").read_text(encoding="utf-8"))
    assert html, "readme_renderer must successfully render Markdown"
    targets = html_targets(html)
    assert_absolute(targets)
    for target in targets:
        assert_repository_target_exists(target)
    assert len([target for target in targets if "/docs/images/dashboard-" in target]) == 3


@pytest.mark.parametrize("text", [
    "[file](LICENSE)", "![image](docs/images/demo.png)",
    "[![badge](https://example.invalid/badge.svg)](LICENSE)",
    "[guide][reference]\n\n[reference]: docs/guide.md",
    '<details><summary>More</summary><img src="local.png"></details>',
    "<a href='docs/guide.md'>Guide</a>", "<img src=local.png />",
    '<a href="//example.invalid/guide">Guide</a>', '<a href="#guide">Guide</a>',
])
def test_link_parser_rejects_relative_markdown_and_html(text):
    with pytest.raises(AssertionError):
        assert_absolute(markdown_targets(text))


def test_project_sidebar_urls_are_absolute_and_point_to_existing_source():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    base = "https://github.com" + REPOSITORY
    assert project["urls"] == {
        "Homepage": base, "Repository": base, "Documentation": base + "/tree/main/docs/",
        "Issues": base + "/issues", "Changelog": base + "/blob/main/CHANGELOG.md",
        "Security": base + "/blob/main/SECURITY.md",
    }
    assert_absolute(list(project["urls"].values()))
    for target in project["urls"].values():
        assert_repository_target_exists(target)
