"""The setup skill and the example gate policies (#64 phase 2c).

Every repository, policy, figure and key here is synthetic.
"""

import contextlib
import io
import json
import re
import shlex
from pathlib import Path

import pytest
import yaml

from conftest import command
from test_model_gate import run
from test_providers_review import envelope
from finassist.cli import main, parser
from finassist.error_hints import explain_arguments, explain_parser
from finassist.integrations import export_kit
from finassist.model_policy import _SCHEMA
from finassist.onboarding import policy_preflight
from finassist.security import canonical, digest

ROOT = Path(__file__).parents[1]
SKILL = ROOT / "skills/finassist-setup/SKILL.md"
KEY_VALUE = "fictional-provider-value"
# Setup stays offline: these are the only commands the skill may run.
OFFLINE_COMMANDS = {"doctor", "explain", "export-kit", "init"}
QUANT = {
    "base": {"engine/pricing.py": "def price(rate, years):\n    return (1 + rate) ** years\n",
             "tests/test_pricing.py": "def test_price():\n    assert True\n"},
    "head": {"engine/pricing.py": "def price(rate, years):\n    return (1 + rate) ** years - 1\n",
             "engine/risk.py": "def drawdown(values):\n    return max(values) - min(values)\n",
             "scripts/backtest.py": "print('synthetic')\n",
             "tests/fixtures/prices/synthetic_prices.csv": "date,close\n2020-01-01,1.00\n",
             "data/synthetic_positions.csv": "symbol,quantity\nSYNTHETIC,1\n",
             "docs/notes.md": "Synthetic notes.\n"},
}
REBALANCER = {
    "base": {"engine/rebalance.py": "def drift(target, actual):\n    return actual - target\n",
             "web/src/app.ts": "export const app = 'synthetic';\n",
             "tests/test_rebalance.py": "def test_drift():\n    assert True\n"},
    "head": {"engine/rebalance.py": "def drift(target, actual):\n    return abs(actual - target)\n",
             "web/src/components/Table.tsx": "export const Table = () => null;\n",
             "tests/fixtures/accounts.yaml": "accounts:\n  - name: Synthetic\n",
             "docs/guide.md": "Synthetic guide.\n"},
}


def _skill() -> tuple[dict, str]:
    _, frontmatter, body = SKILL.read_text(encoding="utf-8").split("---", 2)
    return yaml.safe_load(frontmatter), body


def _section(body: str, number: int) -> str:
    return re.search(rf"^## {number}\. .*?(?=^## |\Z)", body, re.M | re.S).group(0)


def _names(text: str) -> set[str]:
    return set(re.findall(r"`([a-z_]+)`", text))


def _repository(tmp_path, policy: str, shape: dict, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", KEY_VALUE)
    repo = tmp_path / "repo"
    repo.mkdir()
    command(repo, "init", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    raw = (ROOT / "examples/policies" / policy).read_bytes()
    (repo / "gate-policy.json").write_bytes(raw)
    for stage in ("base", "head"):
        for name, text in {**shape[stage], **({".gitignore": ".finassist/\n"} if stage == "base" else {})}.items():
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(text, encoding="utf-8", newline="\n")
        command(repo, "add", "-A")
        command(repo, "commit", "-q", "-m", f"Synthetic {stage}")
        if stage == "base":
            base = command(repo, "rev-parse", "HEAD")
    return {"repo": repo, "base": base, "head": command(repo, "rev-parse", "HEAD"), "pin": digest(raw),
            "state": tmp_path / "private-state"}


def _preflight(case) -> dict:
    report = policy_preflight(case["repo"], case["base"], case["head"], "gate-policy.json", case["pin"])
    assert KEY_VALUE not in canonical(report).decode()
    assert not report["network_used"] and not report["key_value_read"]
    return report


def test_the_skill_follows_the_portable_skill_format():
    frontmatter, body = _skill()
    assert frontmatter["name"] == SKILL.parent.name == "finassist-setup"
    assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", frontmatter["name"]) and len(frontmatter["name"]) <= 64
    assert 0 < len(frontmatter["description"]) <= 1024 and frontmatter["license"] == "MIT"
    # Printable ASCII only, so every host reads it the same way.
    assert all(char == "\n" or " " <= char <= "~" for char in SKILL.read_text(encoding="utf-8"))
    assert [int(n) for n in re.findall(r"^## (\d+)\. ", body, re.M)] == list(range(1, 9))


def test_every_command_in_the_skill_parses_and_stays_offline(capsys):
    _, body = _skill()
    lines = [line for block in re.findall(r"```sh\n(.*?)```", body, re.S) for line in block.splitlines() if line]
    assert lines and all(line.startswith("finassist ") for line in lines)
    used = set()
    for line in lines:
        argv = shlex.split(line)[1:]
        root = parser()
        if argv == ["--version"]:
            with pytest.raises(SystemExit) as stopped:
                root.parse_args(argv)
            assert stopped.value.code == 0
            continue
        if (rest := explain_arguments(root, argv)) is not None:
            explain_parser().parse_args(rest)
            used.add("explain")
            continue
        args = root.parse_args(argv)  # A SystemExit here means the skill names an option that doesn't exist.
        used.add(args.command)
        assert not {"--allow-network", "--approve-local", "--approve-packet"} & set(argv)
    capsys.readouterr()
    assert used == OFFLINE_COMMANDS


def test_the_skill_shows_every_field_the_proposal_has(tmp_path, monkeypatch, capsys):
    case = _repository(tmp_path, "quant-engine.json", QUANT, monkeypatch)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert main(["init", "--detect", "--repo", str(case["repo"]), "--purpose", "quant"]) == 0
    proposal = json.loads(output.getvalue())
    step = _section(_skill()[1], 4)
    config = re.search(r"under `config`:(.*?);", step, re.S).group(1)
    draft = re.search(r"under `gate_policy_draft`:(.*?);", step, re.S).group(1)
    # Equality: a field added to the proposal fails here until the skill shows it too.
    assert _names(config) == set(proposal["config"])
    assert _names(draft) == set(proposal["gate_policy_draft"]["model_review"])
    for name in ("evidence", "private_paths", "tests", "warnings"):
        assert f"`{name}`" in step and name in proposal
    # The choices left to the person are real policy fields.
    fields = _SCHEMA["properties"]["model_review"]["properties"]
    assert {"blocking_severities", "fixture_roots", "private_paths"} <= _names(step) & set(fields)
    assert set(fields["private_paths"]["enum"]) == {"refuse", "skip-and-report"}


def test_the_kit_exports_the_skill_and_every_example_it_names(tmp_path):
    kit = tmp_path / "kit"
    result = export_kit(kit)
    assert (kit / "finassist-setup/SKILL.md").read_bytes() == SKILL.read_bytes()
    named = set(re.findall(r"`(examples/[a-z/.-]+\.json)`", SKILL.read_text(encoding="utf-8")))
    assert named == {"examples/policies/quant-engine.json", "examples/policies/rebalancer.json"}
    for path in named:
        assert path in result["templates"] and (kit / path).read_bytes() == (ROOT / path).read_bytes()


@pytest.mark.parametrize("policy", ["quant-engine.json", "rebalancer.json"])
def test_the_examples_hold_placeholders_never_operator_values(policy):
    model = json.loads((ROOT / "examples/policies" / policy).read_text(encoding="utf-8"))["model_review"]
    assert model["model"] == "operator-selected" and model["api_key_env"] == "REVIEW_PROVIDER_KEY"
    assert model["provider"] != "offline" and model["input_usd_per_million"] > 0  # Prices to replace.
    assert "forbidden_token_file" not in model and "profile_path" not in model


def test_the_quant_example_is_ready_and_withholds_private_data(tmp_path, monkeypatch):
    report = _preflight(_repository(tmp_path, "quant-engine.json", QUANT, monkeypatch))
    assert report["status"] == "ready" and report["blockers"] == [] and not report["coverage_complete"]
    statuses = {row["path"]: row["status"] for row in report["paths"]}
    assert statuses.pop("data/synthetic_positions.csv") == "withheld"
    assert set(statuses.values()) == {"included"} and "tests/fixtures/prices/synthetic_prices.csv" in statuses
    assert [warning["code"] for warning in report["warnings"]] == ["private_paths_withheld"]


def test_the_rebalancer_example_is_ready_with_complete_coverage(tmp_path, monkeypatch):
    report = _preflight(_repository(tmp_path, "rebalancer.json", REBALANCER, monkeypatch))
    assert report["status"] == "ready" and report["blockers"] == [] and report["coverage_complete"]
    assert {row["status"] for row in report["paths"]} == {"included"} and report["warnings"] == []


@pytest.mark.parametrize("policy, shape, status", [
    ("quant-engine.json", QUANT, "withheld"),
    ("rebalancer.json", REBALANCER, "refused"),
])
def test_a_private_name_inside_the_scope_follows_the_examples_choice(tmp_path, monkeypatch, policy, shape, status):
    changed = {**shape, "head": {**shape["head"], "engine/client/settings.py": "LIMIT = 1\n"}}
    report = _preflight(_repository(tmp_path, policy, changed, monkeypatch))
    row = next(row for row in report["paths"] if row["path"] == "engine/client/settings.py")
    assert row["status"] == status
    assert (report["status"] == "ready") is (status == "withheld")


def test_a_change_outside_the_examples_scope_is_refused(tmp_path, monkeypatch):
    changed = {**QUANT, "head": {**QUANT["head"], "notebooks/explore.py": "X = 1\n"}}
    report = _preflight(_repository(tmp_path, "quant-engine.json", changed, monkeypatch))
    assert report["status"] == "blocked"
    assert [blocker["code"] for blocker in report["blockers"]] == ["gate_path_not_allowed"]


def test_the_quant_example_gate_run_passes_with_incomplete_coverage(tmp_path, monkeypatch):
    case = _repository(tmp_path, "quant-engine.json", QUANT, monkeypatch)

    def clean(packet):
        return envelope(json.dumps({"head": packet["head"], "summary": "No defect in the synthetic change.",
                                    "reviewed_paths": [file["path"] for file in packet["files"]], "findings": []}))

    report, calls = run(case, clean)
    assert report["verdict"] == "PASS" and report["coverage"] == {"complete": False, "withheld": 1}
    assert len(calls) == 1
    for text in (canonical(report).decode(), calls[0].content.decode()):
        assert "synthetic_positions" not in text and "SYNTHETIC,1" not in text
