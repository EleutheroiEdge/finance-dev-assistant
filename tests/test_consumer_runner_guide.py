"""The documented synthetic recipe stays loadable without a container or network."""
import ast
import json
from pathlib import Path
import re

import jsonschema

from finassist.config import load_config
from finassist.config_schema import configuration_schema

ROOT = Path(__file__).resolve().parent.parent


def test_documented_consumer_runner_recipe_validates_and_names_existing_test():
    guide = (ROOT / "docs/ci-gates.md").read_text(encoding="utf-8")
    section = guide.split("### Exact test IDs on a read-only workspace", 1)[1]
    raw = re.search(r"```json\n(.*?)\n```", section, re.DOTALL).group(1)
    data = json.loads(raw)
    jsonschema.validate(data, configuration_schema())
    config = load_config(content=raw.encode())
    assert config.provider == "offline" and not config.allow_network
    assert config.required_recipes == ("unit", "cash")
    argv = config.recipes["unit"]
    assert argv[:7] == ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--basetemp=/tmp/pytest"]
    filename, class_name, method_name = argv[-1].split("::")
    tree = ast.parse((ROOT / "examples/github-actions/fixture" / filename).read_text(encoding="utf-8"))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    assert any(isinstance(node, ast.FunctionDef) and node.name == method_name for node in cls.body)
    assert config.recipes["cash"] == ["python", "-m", "tests.check_cash"]
