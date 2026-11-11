"""`init --detect` proposes something a real repository can use as it stands. Synthetic data only."""

from decimal import Decimal
import json
import subprocess

import pytest

from conftest import command
from test_model_gate import run
from test_providers_review import envelope
from finassist import detect as detect_module
from finassist.cli import main
from finassist.model_policy import check_draft, missing_fields
from finassist.onboarding import policy_preflight
from finassist.review import ENVELOPE_ALLOWANCE, reserved_usd
from finassist.security import canonical, digest

NEAR_LIMIT = 17_500  # Bytes per module: three of them changed make a request just under the 120,000 floor.

QUANT_README = ("# Synthetic engine\n\nA portfolio rebalancing engine. The optimizer sizes trades from holdings,\n"
                "tax lot by tax lot, and the backtest replays them.\n")
PROVIDER = ["--provider", "openai", "--model", "operator-selected", "--api-key-env", "REVIEW_PROVIDER_KEY",
            "--input-usd-per-million", "1", "--output-usd-per-million", "2"]
MODULE = "def total(values):\n    return sum(values)\n"


def _repo(tmp_path, files: dict):
    repo = tmp_path / "adopter"
    repo.mkdir()
    command(repo, "init", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    _commit(repo, files, "Synthetic baseline")
    return repo


def _commit(repo, files: dict, message: str) -> str:
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "--allow-empty", "-m", message)
    return command(repo, "rev-parse", "HEAD")


def _proposal(capsys, argv) -> dict:
    assert main(argv) == 0
    return json.loads(capsys.readouterr().out)


LAYOUT = {"engine/core.py": MODULE, "tests/test_core.py": "def test_core():\n    pass\n", "README.md": QUANT_README,
          "ROADMAP.md": "# Roadmap\n", "CONSTITUTION.md": "# Rules\n", "requirements.txt": "pytest\n",
          "ops/review/settings.json": "{}\n", "FLAGS/first.md": "A flag.\n", "data/prices.csv": "day,price\n1,2\n",
          "examples/sample.md": "An example.\n", ".internal/notes.md": "Hidden.\n", "uv.lock": "version = 1\n",
          "assets/logo.png": "not really an image\n", ".gitignore": ".finassist/\n"}


def test_root_text_files_and_other_text_directories_are_proposed(tmp_path):
    proposal = detect_module.detect(_repo(tmp_path, LAYOUT))
    allow = proposal["config"]["allow_paths"]
    assert {"engine/", "tests/", "README.md", "ROADMAP.md", "CONSTITUTION.md", "requirements.txt", "ops/",
            "FLAGS/", ".internal/"} <= set(allow)  # A hidden directory of text is proposed like any other.
    # Private data, example directories, lock files and binary assets are not proposed.
    assert not {"data/", "examples/", "uv.lock", "assets/", ".gitignore"} & set(allow)
    assert proposal["gate_policy_draft"]["model_review"]["allow_paths"] == allow
    rules = {entry["value"]: entry["rule"] for entry in proposal["evidence"]["allow_paths"]}
    assert rules["ROADMAP.md"] == "root_text_file" and rules["ops/"] == "text_files"


def test_a_roadmap_change_is_covered_by_the_proposed_paths(tmp_path, capsys):
    """The stop a first adopter hit: every pull request also edits a root roadmap file."""
    repo = _repo(tmp_path, LAYOUT)
    config = tmp_path / "finassist.json"
    _proposal(capsys, ["init", "--detect", "--repo", str(repo), "--write", "--output", str(config)])
    base = command(repo, "rev-parse", "HEAD")
    head = _commit(repo, {"engine/core.py": MODULE + "X = 1\n", "ROADMAP.md": "# Roadmap\n\nNext.\n"}, "Change")
    report = _proposal(capsys, ["--config", str(config), "doctor", "--repo", str(repo), "--base", base, "--head", head])
    assert report["status"] == "ready" and report["coverage_complete"] is True
    assert {row["status"] for row in report["paths"]} == {"included"}


def test_the_profile_follows_the_repositorys_own_description(tmp_path):
    proposal = detect_module.detect(_repo(tmp_path, LAYOUT))
    assert proposal["config"]["profile"] == "quant-review"
    (evidence,) = proposal["evidence"]["profile"]
    assert evidence["rule"] == "described_as" and evidence["purpose"] == "quant"
    assert {"portfolio", "rebalanc", "optimizer"} <= set(evidence["words"])
    assert "purpose_not_stated" not in {entry["code"] for entry in proposal["warnings"]}


def test_an_unclear_description_keeps_the_default_and_says_so(tmp_path):
    files = {**LAYOUT, "README.md": "# Synthetic\n\nA portfolio ledger with invoices.\n"}
    proposal = detect_module.detect(_repo(tmp_path, files))
    assert proposal["config"]["profile"] == "finance-saas"
    assert proposal["evidence"]["profile"] == [{"value": "finance-saas", "rule": "default"}]
    (warning,) = [entry for entry in proposal["warnings"] if entry["code"] == "purpose_not_stated"]
    assert warning["choices"] == ["accounting", "general", "quant", "research"]


@pytest.mark.parametrize("option, profile, rule", [
    (["--purpose", "accounting"], "finance-saas", "purpose"),
    (["--profile", "general"], "general", "stated"),
    (["--profile", "finance-saas"], "finance-saas", "stated"),
])
def test_a_stated_purpose_or_profile_is_never_overridden(tmp_path, capsys, option, profile, rule):
    repo = _repo(tmp_path, LAYOUT)
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo), *option])
    assert proposal["config"]["profile"] == profile
    assert proposal["gate_policy_draft"]["model_review"]["profile"] == profile
    assert [entry["rule"] for entry in proposal["evidence"]["profile"]] == [rule]
    assert "purpose_not_stated" not in {entry["code"] for entry in proposal["warnings"]}


def test_without_a_provider_the_draft_lists_exactly_what_is_left_to_choose(tmp_path, capsys):
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(_repo(tmp_path, LAYOUT))])
    draft = proposal["gate_policy_draft"]
    assert draft["schema_version"] == 2 and draft["model_review"]["enabled"] is True
    assert proposal["gate_policy_missing"] == missing_fields(draft) == [
        "allowed_host", "api_key_env", "daily_budget_usd", "endpoint", "input_usd_per_million", "max_run_usd",
        "model", "output_usd_per_million", "provider"]
    # Nothing is invented for a field that is the person's choice.
    assert not set(proposal["gate_policy_missing"]) & set(draft["model_review"])


def test_with_a_provider_the_draft_is_a_whole_policy_the_gate_accepts(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "fictional-provider-value")
    repo = _repo(tmp_path, LAYOUT)
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo), *PROVIDER])
    draft = proposal["gate_policy_draft"]
    assert proposal["gate_policy_missing"] == []
    check_draft(draft)
    model = draft["model_review"]
    assert (model["provider"], model["allowed_host"], model["api_key_env"]) == (
        "openai", "api.openai.com", "REVIEW_PROVIDER_KEY")
    assert proposal["evidence"]["max_run_usd"] == [{"value": model["max_run_usd"], "rule": "one_request_at_the_limit"}]
    # Committed as it stands, it lets a change through to the provider call.
    (repo / "gate-policy.json").write_bytes(canonical(draft))
    base = _commit(repo, {}, "Synthetic policy from the draft")
    head = _commit(repo, {"engine/core.py": MODULE + "X = 1\n", "ROADMAP.md": "# Roadmap\n\nNext.\n"}, "Change")
    report = policy_preflight(repo, base, head, "gate-policy.json", digest(canonical(draft)))
    assert report["status"] == "ready", report["blockers"]
    assert {row["status"] for row in report["paths"]} == {"included"}


def test_the_drafted_budget_covers_a_request_near_the_drafted_limit(tmp_path, capsys, monkeypatch):
    """Prices high enough that the default budget of 1 can't hide a shortfall, and a request near the limit."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "fictional-provider-value")
    line = "value = compute_total(opening, deposits)  # synthetic {n:07d}\n"
    body = lambda seed: "".join(line.format(n=seed * 100_000 + number) for number in range(NEAR_LIMIT // len(line)))  # noqa: E731
    repo = _repo(tmp_path, {**LAYOUT, **{f"engine/part_{n}.py": body(n) for n in range(3)}})
    pricey = [*PROVIDER[:-4], "--input-usd-per-million", "100", "--output-usd-per-million", "2"]
    draft = _proposal(capsys, ["init", "--detect", "--repo", str(repo), *pricey])["gate_policy_draft"]
    model = draft["model_review"]
    assert model["max_request_bytes"] == 120_000
    (repo / "gate-policy.json").write_bytes(canonical(draft))
    case = {"repo": repo, "base": _commit(repo, {}, "Synthetic policy from the draft"),
            "pin": digest(canonical(draft)), "state": tmp_path / "private-state"}
    case["head"] = _commit(repo, {f"engine/part_{n}.py": body(n + 10) for n in range(3)}, "Synthetic large change")
    report = policy_preflight(repo, case["base"], case["head"], "gate-policy.json", case["pin"])
    assert report["status"] == "ready", report["blockers"]
    size = report["request"]["bytes"]
    assert size <= model["max_request_bytes"]
    needed = reserved_usd(size + ENVELOPE_ALLOWANCE, model["max_output_tokens"], 100, 2)
    # This request is one that a budget of five percent over the limit's bytes, with no allowance, refuses.
    assert needed > Decimal(model["max_request_bytes"]) * Decimal("1.05") * 100 / 1_000_000 + Decimal("0.01")
    assert Decimal(report["request"]["reserved_usd"]) == needed <= Decimal(str(model["max_run_usd"]))
    at_the_limit = reserved_usd(model["max_request_bytes"] + ENVELOPE_ALLOWANCE, model["max_output_tokens"], 100, 2)
    assert at_the_limit <= Decimal(str(model["max_run_usd"])) < at_the_limit + Decimal("0.01")
    # The gate reserves that amount and makes the call.
    result, calls = run(case, lambda packet: envelope(json.dumps({
        "head": packet["head"], "summary": "No findings.", "findings": [],
        "reviewed_paths": [file["path"] for file in packet["files"]]})))
    assert result["verdict"] == "PASS", result["reasons"]
    assert len(calls) == 1 and len(calls[0].content) == size


BUDGETS = {"run_budget_exceeded", "daily_budget_exceeded", "monthly_budget_exceeded"}


def _near_the_limit(tmp_path):
    """A repository whose latest change makes a packet near the 120,000-byte floor of the drafted limit."""
    line = "value = compute_total(opening, deposits)  # synthetic {n:07d}\n"
    body = lambda seed: "".join(line.format(n=seed * 100_000 + number) for number in range(NEAR_LIMIT // len(line)))  # noqa: E731
    repo = _repo(tmp_path, {**LAYOUT, **{f"engine/part_{n}.py": body(n) for n in range(3)}})
    base = command(repo, "rev-parse", "HEAD")
    return repo, base, _commit(repo, {f"engine/part_{n}.py": body(n + 10) for n in range(3)}, "Synthetic large change")


def _doctor(capsys, path, repo, base, head) -> dict:
    """The configuration preflight's report. It exits with 1 while the network is not approved."""
    main(["--config", str(path), "doctor", "--repo", str(repo), "--base", base, "--head", head])
    return json.loads(capsys.readouterr().out.splitlines()[-1])


def test_the_drafted_configuration_can_pay_for_a_request_near_its_own_packet_limit(tmp_path, capsys, monkeypatch):
    """Prices high enough that the default budget of 1 is too small for the packet limit the draft proposes."""
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "fictional-provider-value")
    repo, base, head = _near_the_limit(tmp_path)
    pricey = [*PROVIDER[:-4], "--input-usd-per-million", "100", "--output-usd-per-million", "2"]
    path = tmp_path / "finassist.json"
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo), *pricey, "--write", "--output", str(path)])
    config = proposal["config"]
    run, daily = Decimal(str(config["max_run_usd"])), Decimal(str(config["daily_budget_usd"]))
    # One request at the limit, by the configuration route's arithmetic, and not a cent more than it needs.
    bare = reserved_usd(config["max_packet_bytes"] + ENVELOPE_ALLOWANCE, 4096, 100, 2)
    assert bare < run < bare + Decimal("1.00") and daily == 3 * run and "monthly_budget_usd" not in config
    assert {"code": "budget_raised_for_packet_limit", "max_run_usd": float(run), "daily_budget_usd": float(daily)} in proposal["warnings"]
    assert {"value": float(run), "rule": "one_packet_at_the_limit", "document": "config"} in proposal["evidence"]["max_run_usd"]
    assert {"value": float(daily), "rule": "one_packet_at_the_limit", "document": "config"} in proposal["evidence"]["daily_budget_usd"]
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert (saved["max_run_usd"], saved["daily_budget_usd"]) == (float(run), float(daily))
    # The saved draft reviews the change it made room for, and the default budget would not have.
    report = _doctor(capsys, path, repo, base, head)
    assert not BUDGETS & {blocker["code"] for blocker in report["blockers"]}
    assert Decimal("1") < Decimal(report["request"]["reserved_usd"]) <= run
    assert 0 < report["packet"]["bytes"] <= report["packet"]["limit"] == config["max_packet_bytes"]
    path.write_text(json.dumps({**saved, "max_run_usd": 1.0, "daily_budget_usd": 5.0}), encoding="utf-8")
    report = _doctor(capsys, path, repo, base, head)
    assert BUDGETS & {blocker["code"] for blocker in report["blockers"]} == {"run_budget_exceeded", "daily_budget_exceeded"}


def test_a_budget_that_is_enough_is_left_alone_and_none_is_lowered(tmp_path, capsys):
    repo, _base, _head = _near_the_limit(tmp_path)
    # Ordinary prices: the default budget pays for the drafted limit, so the draft names no budget.
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo), *PROVIDER])
    assert not {"max_run_usd", "daily_budget_usd", "monthly_budget_usd"} & set(proposal["config"])
    assert "budget_raised_for_packet_limit" not in {entry["code"] for entry in proposal["warnings"]}
    # No provider: nothing can be worked out, and nothing is invented.
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    assert not {"max_run_usd", "daily_budget_usd", "monthly_budget_usd"} & set(proposal["config"])
    # A stated budget that is already enough stays as stated, with high prices too.
    pricey = [*PROVIDER[:-4], "--input-usd-per-million", "100", "--output-usd-per-million", "2"]
    stated = tmp_path / "stated.json"
    stated.write_text(json.dumps({"max_run_usd": 50, "daily_budget_usd": 60}), encoding="utf-8")
    proposal = _proposal(capsys, ["--config", str(stated), "init", "--detect", "--repo", str(repo), *pricey])
    assert not {"max_run_usd", "daily_budget_usd", "monthly_budget_usd"} & set(proposal["config"])
    assert "budget_raised_for_packet_limit" not in {entry["code"] for entry in proposal["warnings"]}


def test_a_month_cannot_hold_less_than_a_day_of_the_drafted_budget(tmp_path, capsys):
    repo, _base, _head = _near_the_limit(tmp_path)
    costly = [*PROVIDER[:-4], "--input-usd-per-million", "400", "--output-usd-per-million", "2"]
    config = _proposal(capsys, ["init", "--detect", "--repo", str(repo), *costly])["config"]
    assert config["max_run_usd"] > 48 and config["daily_budget_usd"] == 3 * config["max_run_usd"]
    assert config["monthly_budget_usd"] == config["daily_budget_usd"] > 100


@pytest.mark.parametrize("stated,raised,refused", [
    ({"max_run_usd": 50, "daily_budget_usd": 0.01}, {"daily_budget_usd"}, {"daily_budget_exceeded"}),
    ({"max_run_usd": 50, "daily_budget_usd": 60, "monthly_budget_usd": 0.01}, {"monthly_budget_usd"},
     {"monthly_budget_exceeded"}),
    ({"max_run_usd": 50, "daily_budget_usd": 0.01, "monthly_budget_usd": 0.01},
     {"daily_budget_usd", "monthly_budget_usd"}, {"daily_budget_exceeded", "monthly_budget_exceeded"}),
])
def test_a_day_or_a_month_too_small_for_one_request_is_raised_on_its_own(tmp_path, capsys, monkeypatch, stated, raised,
                                                                        refused):
    """Codex P109-1: a run budget that is enough does not excuse the other two."""
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "fictional-provider-value")
    repo, base, head = _near_the_limit(tmp_path)
    pricey = [*PROVIDER[:-4], "--input-usd-per-million", "100", "--output-usd-per-million", "2"]
    given, path = tmp_path / "stated.json", tmp_path / "finassist.json"
    given.write_text(json.dumps(stated), encoding="utf-8")
    proposal = _proposal(capsys, ["--config", str(given), "init", "--detect", "--repo", str(repo), *pricey,
                                  "--write", "--output", str(path)])
    config = proposal["config"]
    names = {"max_run_usd", "daily_budget_usd", "monthly_budget_usd"}
    assert names & set(config) == raised  # The run budget of 50 was enough and stays as stated.
    amounts = {name: config[name] for name in raised}
    assert {"code": "budget_raised_for_packet_limit", **amounts} in proposal["warnings"]
    bare = reserved_usd(config["max_packet_bytes"] + ENVELOPE_ALLOWANCE, 4096, 100, 2)
    if "daily_budget_usd" in raised:  # three requests at the limit, as when the run budget is raised
        assert 3 * bare < Decimal(str(config["daily_budget_usd"])) < 3 * (bare + Decimal("1.00"))
    if "monthly_budget_usd" in raised:  # the day beside it: the proposed one, or the stated 60
        assert config["monthly_budget_usd"] == config.get("daily_budget_usd", 60.0)
    for name in raised:
        assert {"value": config[name], "rule": "one_packet_at_the_limit", "document": "config"} in proposal["evidence"][name]
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["max_run_usd"] == 50 and all(saved[name] == config[name] for name in raised)
    # The saved draft pays for the change it made room for. With the budgets as they were stated, it does not.
    report = _doctor(capsys, path, repo, base, head)
    assert not BUDGETS & {blocker["code"] for blocker in report["blockers"]}
    path.write_text(json.dumps({**saved, **stated}), encoding="utf-8")
    report = _doctor(capsys, path, repo, base, head)
    assert BUDGETS & {blocker["code"] for blocker in report["blockers"]} == refused


def test_a_month_that_holds_one_request_stays_beside_a_larger_day(tmp_path, capsys):
    repo, _base, _head = _near_the_limit(tmp_path)
    pricey = [*PROVIDER[:-4], "--input-usd-per-million", "100", "--output-usd-per-million", "2"]
    stated = tmp_path / "stated.json"
    # One request reserves about 12.6: the month holds it, though it is smaller than the day.
    stated.write_text(json.dumps({"max_run_usd": 50, "daily_budget_usd": 60, "monthly_budget_usd": 20}), encoding="utf-8")
    proposal = _proposal(capsys, ["--config", str(stated), "init", "--detect", "--repo", str(repo), *pricey])
    assert not {"max_run_usd", "daily_budget_usd", "monthly_budget_usd"} & set(proposal["config"])
    assert "budget_raised_for_packet_limit" not in {entry["code"] for entry in proposal["warnings"]}


def test_a_draft_the_gate_schema_refuses_is_reported_and_the_proposal_still_prints(tmp_path, capsys):
    crowded = {**LAYOUT, **{f"NOTE_{number:03d}.md": "A note.\n" for number in range(130)}}
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(_repo(tmp_path, crowded)), *PROVIDER])
    assert len(proposal["gate_policy_draft"]["model_review"]["allow_paths"]) > 128  # Over the policy's limit.
    assert proposal["gate_policy_missing"] == []
    assert {"code": "gate_policy_invalid"} in proposal["warnings"]
    assert proposal["evidence"]["max_run_usd"][0]["rule"] == "one_request_at_the_limit"


def test_a_name_a_gate_policy_would_refuse_as_a_prefix_is_not_proposed(tmp_path):
    proposal = detect_module.detect(_repo(tmp_path, {**LAYOUT, "notes[old]/plan.md": "A plan.\n"}))
    assert not [prefix for prefix in proposal["config"]["allow_paths"] if "[" in prefix]


def _history(tmp_path, changes: int = 3, files: int = 6, size: int = 40_000):
    """A repository whose recent changes each rewrite several mid-sized modules."""
    line = "value = compute_total(opening, deposits)  # synthetic {n:07d}\n"
    body = lambda seed: "".join(line.format(n=seed * 100_000 + number) for number in range(size // len(line)))  # noqa: E731
    repo = _repo(tmp_path, {**LAYOUT, **{f"engine/part_{n}.py": body(n) for n in range(files)}})
    heads = [command(repo, "rev-parse", "HEAD")]
    for round_ in range(1, changes + 1):
        heads.append(_commit(repo, {f"engine/part_{n}.py": body(n + 10 * round_) for n in range(files)},
                             f"Synthetic change {round_}"))
    return repo, heads


def test_limits_fit_the_largest_recent_change_not_only_the_largest_file(tmp_path, capsys):
    repo, heads = _history(tmp_path)
    proposal = detect_module.detect(repo)
    one_file = 2 * 40_000  # What a single file's change needs, before escaping.
    assert proposal["config"]["max_packet_bytes"] > 6 * one_file
    (evidence,) = proposal["evidence"]["max_packet_bytes"]
    assert evidence["rule"] == "largest_recent_change" and evidence["changes_measured"] == 3
    assert any(head.startswith(evidence["commit"]) for head in heads)
    assert proposal["gate_policy_draft"]["model_review"]["max_request_bytes"] >= proposal["config"]["max_packet_bytes"]
    assert proposal["gate_policy_draft"]["model_review"]["max_files"] >= 20
    # The written configuration plans the latest of those changes without a limit error.
    config = tmp_path / "finassist.json"
    _proposal(capsys, ["init", "--detect", "--repo", str(repo), "--write", "--output", str(config)])
    report = _proposal(capsys, ["--config", str(config), "doctor", "--repo", str(repo), "--base", heads[-2],
                                "--head", heads[-1]])
    assert report["status"] == "ready" and report["packet"]["bytes"] <= report["packet"]["limit"]


def test_history_asks_git_only_for_sizes_and_never_for_a_private_name(tmp_path, monkeypatch):
    repo, _heads = _history(tmp_path, changes=1)
    private = command(repo, "rev-parse", "HEAD:data/prices.csv")
    _commit(repo, {"data/prices.csv": "day,price\n1,3\n", "engine/part_0.py": MODULE}, "Private and source change")
    changed_private = command(repo, "rev-parse", "HEAD:data/prices.csv")
    asked, real = [], subprocess.run

    def recording(argv, *args, **kwargs):
        if "--batch-check" in argv:
            asked.extend(kwargs["input"].decode("ascii").split())
        return real(argv, *args, **kwargs)

    monkeypatch.setattr(detect_module.subprocess, "run", recording)
    detect_module.detect(repo)
    assert asked and not {private, changed_private} & set(asked)


def test_a_repository_with_one_commit_falls_back_to_the_single_file_rule(tmp_path):
    proposal = detect_module.detect(_repo(tmp_path, LAYOUT))
    assert "max_packet_bytes" not in proposal["evidence"]
    assert proposal["gate_policy_draft"]["model_review"]["max_files"] == 20
