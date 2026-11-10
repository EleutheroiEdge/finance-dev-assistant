"""The configuration route's one-pass preflight, evidence after an upgrade, and the adopter scenario.

The scenario is a synthetic repository shaped like a quant engine an adopter evaluated: an
engine/ module over 200 KB, twelve price fixtures of about 19 KB, a data file, docs and scripts,
with a configuration that lists .csv in text_suffixes, a paid provider with zero prices and no
key variable. Every name and value here is synthetic.
"""

from dataclasses import replace
import json

import pytest

from conftest import command
from test_model_policy import model_policy
from finassist.cli import main
from finassist.config import Config, save_config
from finassist.config_preflight import config_preflight
from finassist.ledger import Ledger
from finassist.onboarding import policy_preflight
from finassist.security import canonical, digest

pytest_plugins = ("test_model_gate", "test_model_policy")
KEY_VALUE = "fictional-provider-value"
WALKDOWN = "".join(f"def step_{n}(x):\n    return x + {n}\n" for n in range(7_000))
PRICES = "date,symbol,volume,close\n" + "".join(f"2026-01-02,SYNTH,{n},100.25\n" for n in range(720))
FIXTURES = [f"tests/fixtures/r2_12_prices/prices/p{n:02}.csv" for n in range(1, 13)]
DATA = "data/securities_master_legacy.csv"


def _write(repo, files):
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
    command(repo, "add", "-A")


@pytest.fixture
def adopter(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    repo = tmp_path / "engine-repo"
    repo.mkdir()
    command(repo, "init", "-q", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    _write(repo, {"engine/core.py": "def stage(x):\n    return x + 1\n", "engine/walkdown.py": WALKDOWN,
                  "scripts/run.py": "print('synthetic')\n", "docs/guide.md": "# Synthetic guide\n",
                  "tests/test_core.py": "def test_stage():\n    assert True\n", DATA: "id,symbol\n1,SYNTH\n",
                  ".gitignore": ".finassist/\n"})
    command(repo, "commit", "-q", "-m", "Synthetic engine baseline")
    base = command(repo, "rev-parse", "HEAD")
    command(repo, "switch", "-q", "-c", "candidate")
    _write(repo, {"engine/core.py": "def stage(x):\n    return x + 2\n",
                  "engine/walkdown.py": WALKDOWN + "def last(x):\n    return x\n",
                  "scripts/run.py": "print('synthetic two')\n", "docs/guide.md": "# Synthetic guide\n\nMore.\n",
                  DATA: "id,symbol\n1,SYNTH\n2,SYNTH2\n", **dict.fromkeys(FIXTURES, PRICES)})
    command(repo, "commit", "-q", "-m", "Synthetic candidate an adopter would evaluate")
    config = replace(Config(), provider="google", model="synthetic-model", allow_paths=("engine/", "tests/", "docs/"),
                     text_suffixes=(*Config().text_suffixes, ".csv"))
    path = tmp_path / "finassist.json"
    save_config(path, config)
    assert len(WALKDOWN) > 200_000 and 18_000 < len(PRICES) < 21_000
    return {"repo": repo, "base": base, "head": command(repo, "rev-parse", "HEAD"), "config": config, "path": path}


def doctor(capsys, *argv) -> tuple[int, dict]:
    code = main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def test_the_configuration_route_reports_every_blocker_in_one_pass(adopter, capsys):
    code, report = doctor(capsys, "--config", str(adopter["path"]), "doctor", "--repo", str(adopter["repo"]),
                          "--base", adopter["base"], "--head", adopter["head"])
    assert code == 1 and report["mode"] == "config-preflight" and report["status"] == "blocked"
    assert not report["network_used"] and not report["key_value_read"] and not report["ledger_opened"]
    grouped = {entry["code"]: entry for entry in report["blockers"] if "paths" in entry}
    single = {entry["code"]: entry for entry in report["blockers"] if "paths" not in entry}
    assert grouped["private_or_binary_path"]["count"] == 13
    assert sorted(grouped["private_or_binary_path"]["paths"]) == sorted([*FIXTURES, DATA])
    assert grouped["file_limit_exceeded"]["paths"] == ["engine/walkdown.py"]
    assert grouped["scope_incomplete"]["paths"] == ["scripts/run.py"]
    assert single["network_not_approved"]["allow_network"] is False
    assert single["provider_prices_required"]["missing"] == ["input_usd_per_million", "output_usd_per_million"]
    assert single["provider_key_missing"]["variable"] == "GEMINI_API_KEY"
    assert {"text_suffix_always_denied", "provider_prices_missing"} <= {item["code"] for item in report["warnings"]}
    rows = {row["path"]: row for row in report["paths"]}
    assert rows["engine/core.py"] == {"path": "engine/core.py", "status": "included"}
    assert rows["engine/walkdown.py"]["limit"] == 48_000 and rows["engine/walkdown.py"]["bytes"] > 200_000
    assert rows["scripts/run.py"]["reason"] == "outside_allowlist"
    assert all(entry["hint"] for entry in report["blockers"])
    assert report["packet"] is None and report["coverage_complete"] is False


def test_plan_names_the_same_refused_files(adopter, tmp_path, capsys):
    assert main(["--config", str(adopter["path"]), "--audit-dir", str(tmp_path / "audit"), "plan",
                 "--repo", str(adopter["repo"]), "--base", adopter["base"], "--head", adopter["head"],
                 "--output", str(tmp_path / "plan.json")]) == 2
    local = json.loads(capsys.readouterr().err)["local"]
    named = {name for group in local["refused_paths"] for name in group["paths"]}
    assert named == {*FIXTURES, DATA}
    assert {item["code"] for item in local["config_warnings"]} >= {"text_suffix_always_denied"}


def test_a_past_range_checks_against_a_policy_file_without_authorizing_a_run(adopter, tmp_path, monkeypatch):
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", KEY_VALUE)
    document = model_policy()
    document["model_review"].update(allow_paths=["engine/", "scripts/", "tests/", "docs/"], max_file_bytes=300_000,
                                    max_request_bytes=2_000_000, max_files=100, private_paths="skip-and-report")
    policy = tmp_path / "proposed-policy.json"
    policy.write_bytes(canonical(document))
    report = policy_preflight(adopter["repo"], adopter["base"], adopter["head"], "", policy_file=str(policy))
    # data/ is outside allow_paths: its file is withheld all the same, since it is never reviewed.
    assert KEY_VALUE not in canonical(report).decode()
    assert report["status"] == "ready" and report["policy"]["source"] == "working-tree"
    assert isinstance(report["next_step"], str)  # No gate run command.
    withheld = sorted(row["path"] for row in report["paths"] if row["status"] == "withheld")
    assert withheld == sorted([*FIXTURES, DATA]) and report["coverage_complete"] is False
    assert "policy_from_working_tree" in {item["code"] for item in report["warnings"]}


def test_init_warns_about_a_suffix_that_has_no_effect(adopter, tmp_path, capsys):
    offline = tmp_path / "offline.json"
    save_config(offline, replace(Config(), text_suffixes=(*Config().text_suffixes, ".csv")))
    assert main(["--config", str(offline), "init", "--output", str(tmp_path / "written.json")]) == 0
    written = json.loads(capsys.readouterr().out)
    assert [item["code"] for item in written["config_warnings"]] == ["text_suffix_always_denied"]
    assert main(["--config", str(offline), "init", "--detect", "--repo", str(adopter["repo"])]) == 0
    proposal = json.loads(capsys.readouterr().out)
    assert "text_suffix_always_denied" in {item["code"] for item in proposal["config_warnings"]}


def test_a_ready_range_gives_the_next_commands_and_plan_agrees(repository, tmp_path, capsys, monkeypatch):
    repo, base, head = repository
    monkeypatch.setenv("OPENAI_API_KEY", KEY_VALUE)
    config = replace(Config(), provider="openai", model="synthetic-model", allow_network=True,
                     input_usd_per_million=1, output_usd_per_million=2)
    path = tmp_path / "finassist.json"
    save_config(path, config)
    code, report = doctor(capsys, "--config", str(path), "doctor", "--repo", str(repo), "--base", base, "--head", head)
    assert code == 0 and report["status"] == "ready" and report["blockers"] == []
    assert KEY_VALUE not in canonical(report).decode() and report["provider"]["key_variable_set"]
    assert 0 < report["packet"]["bytes"] <= report["packet"]["limit"] and report["request"]["bytes"] > 0
    plan, review = report["next_step"]["commands"]
    assert plan[plan.index("--head") + 1] == head and "--allow-network" in review
    assert main(["--config", str(path), "--audit-dir", str(tmp_path / "audit"), "plan", "--repo", str(repo),
                 "--base", base, "--head", head, "--output", str(tmp_path / "plan.json")]) == 0
    summary = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert summary["packet_hash"] == report["packet"]["packet_hash"]


def test_without_a_configuration_the_defaults_are_checked(repository, capsys):
    repo, base, head = repository
    code, report = doctor(capsys, "doctor", "--repo", str(repo), "--base", base, "--head", head)
    assert code == 0 and report["mode"] == "config-preflight" and report["config"]["source"] == "defaults"
    assert report["provider"] is None and report["paths"] == [{"path": "src/cash.py", "status": "included"}]


def _with_script(repository, *, only_script=False):
    """A range that also changes tools/run.py, outside the default allow list, or only that file."""
    repo, base, _head = repository
    if only_script:
        command(repo, "switch", "-q", "-c", "script-only", base)
    _write(repo, {"tools/run.py": "print('synthetic')\n"})
    command(repo, "commit", "-q", "-m", "Synthetic change outside the allow list")
    return repo, base, command(repo, "rev-parse", "HEAD")


MODEL = replace(Config(), provider="openai", model="synthetic-model", allow_network=True,
                input_usd_per_million=1, output_usd_per_million=2)


def test_offline_review_takes_a_partial_range(repository):
    repo, base, head = _with_script(repository)
    report = config_preflight(repo, base, head, Config())
    assert report["status"] == "ready" and report["packet"]["bytes"] > 0
    assert {row["path"]: row["status"] for row in report["paths"]} == {"tools/run.py": "omitted",
                                                                        "src/cash.py": "included"}


def test_a_model_review_refuses_a_partial_range(repository, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", KEY_VALUE)
    repo, base, head = _with_script(repository)
    report = config_preflight(repo, base, head, MODEL)
    (entry,) = [entry for entry in report["blockers"] if entry["code"] == "scope_incomplete"]
    assert entry["paths"] == ["tools/run.py"]
    assert config_preflight(repo, base, head, replace(MODEL, allow_partial_review=True))["status"] == "ready"


def test_a_range_with_nothing_to_send_blocks_only_a_model_review(repository, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", KEY_VALUE)
    repo, base, head = _with_script(repository, only_script=True)
    assert config_preflight(repo, base, head, Config())["status"] == "ready"
    partial = replace(MODEL, allow_partial_review=True)
    assert [entry["code"] for entry in config_preflight(repo, base, head, partial)["blockers"]] == [
        "empty_model_context"]


def test_a_budget_the_request_would_exceed_is_named(repository, monkeypatch):
    repo, base, head = repository
    monkeypatch.setenv("OPENAI_API_KEY", KEY_VALUE)
    config = replace(Config(), provider="openai", model="synthetic-model", allow_network=True,
                     input_usd_per_million=1_000_000, output_usd_per_million=1_000_000, max_run_usd=0.01)
    report = config_preflight(repo, base, head, config)
    assert "run_budget_exceeded" in [entry["code"] for entry in report["blockers"]]


@pytest.mark.parametrize("extra,code", [(["--fix"], "doctor_config_preflight_conflict"),
                                        (["--check-updates"], "doctor_config_preflight_conflict")])
def test_the_preflight_runs_on_its_own(repository, capsys, extra, code):
    repo, base, head = repository
    assert main(["doctor", "--repo", str(repo), "--base", base, "--head", head, *extra]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == code


def test_a_partial_range_is_named(repository, capsys):
    repo, base, _head = repository
    assert main(["doctor", "--repo", str(repo), "--base", base]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "doctor_policy_range_required"


def test_doctor_flags_evidence_recorded_under_another_configuration(tmp_path, capsys):
    state = tmp_path / "state"
    current = digest(canonical(__import__("dataclasses").asdict(Config())))
    with Ledger(state / "audit.sqlite") as ledger:
        for bound in ("1" * 64, current):
            ledger.append({"event": "check_completed", "head": "0" * 40, "receipt_hash": "2" * 64,
                           "config_hash": bound, "recipe": "unit", "passed": True})
    code, report = doctor(capsys, "doctor", "--state-dir", str(state))
    assert code == 0 and report["evidence"]["recorded"]["check_records"] == 2
    (warning,) = [item for item in report["config_warnings"] if item["code"] == "evidence_configuration_changed"]
    assert warning["check_records"] == 1 and "finassist check" in warning["hint"]


def test_doctor_is_quiet_when_evidence_matches(tmp_path, capsys):
    state = tmp_path / "state"
    current = digest(canonical(__import__("dataclasses").asdict(Config())))
    with Ledger(state / "audit.sqlite") as ledger:
        ledger.append({"event": "check_completed", "head": "0" * 40, "receipt_hash": "2" * 64,
                       "config_hash": current, "recipe": "unit", "passed": True})
    _code, report = doctor(capsys, "doctor", "--state-dir", str(state))
    assert report["evidence"]["other_configuration"] == {"check_records": 0, "workflow_plans": 0}
    assert "evidence_configuration_changed" not in {item["code"] for item in report["config_warnings"]}


def test_the_packet_limit_error_says_by_how_much(repository, tmp_path, capsys):
    repo, base, head = repository
    path = tmp_path / "finassist.json"
    save_config(path, replace(Config(), max_packet_bytes=100))
    assert main(["--config", str(path), "--audit-dir", str(tmp_path / "audit"), "plan", "--repo", str(repo),
                 "--base", base, "--head", head, "--output", str(tmp_path / "plan.json")]) == 2
    record = json.loads(capsys.readouterr().err)
    assert record["code"] == "packet_limit_exceeded" and record["limit"] == 100 and record["bytes"] > 100
