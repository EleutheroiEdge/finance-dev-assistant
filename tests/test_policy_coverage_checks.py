"""The draft check, doctor and the gate refuse a gate policy's coverage settings with one code.

All repositories, policies and digests are synthetic.
"""

import json

import pytest

from conftest import command
from test_model_gate import change_policy, run
from test_model_policy import model_policy
from finassist.cli import main
from finassist.errors import AssistantError
from finassist.model_policy import check_draft
from finassist.security import canonical

pytest_plugins = ("test_model_gate", "test_model_policy")
OCCURRENCES = "placeholder_credential_occurrences"


def _entry(path: str) -> dict:
    return {OCCURRENCES: [{"path": path, "occurrence_sha256": "a" * 64}]}


CASES = {  # name: (policy changes, the code, the field doctor names)
    "data-suffix": ({"text_suffixes": [".py", ".csv"]}, "gate_policy_invalid", "/model_review/text_suffixes"),
    "binary-suffix": ({"text_suffixes": [".pdf"]}, "gate_policy_invalid", "/model_review/text_suffixes"),
    "occurrence-not-yaml": (_entry("src/app.py"), "invalid_placeholder_credential_occurrences",
                            f"/model_review/{OCCURRENCES}/0"),
    "occurrence-pattern": (_entry("ci/*.yaml"), "invalid_placeholder_credential_occurrences",
                           f"/model_review/{OCCURRENCES}/0"),
    "occurrence-outside": (_entry("../a.yaml"), "invalid_placeholder_credential_occurrences",
                           f"/model_review/{OCCURRENCES}/0"),
}


def _doctor(argv, capsys):
    code = main(["doctor", *argv])
    report = json.loads(capsys.readouterr().out)
    return code, report["status"], [(item["code"], item.get("field")) for item in report["blockers"]]


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_draft_check_doctor_and_the_gate_give_one_code(name, gate_case, tmp_path, capsys):
    changes, code, field = CASES[name]
    document = model_policy()
    document["model_review"].update(changes)
    with pytest.raises(AssistantError, match=f"^{code}$"):
        check_draft(document)
    policy = tmp_path / "policy.json"
    policy.write_bytes(canonical(document))
    range_args = ["--repo", str(gate_case["repo"]), "--base", gate_case["base"], "--head", gate_case["head"]]
    assert _doctor(["--policy-file", str(policy), *range_args], capsys) == (1, "blocked", [(code, field)])
    change_policy(gate_case, **changes)
    report, calls = run(gate_case)
    assert not calls and report["verdict"] == "BLOCKED" and report["reasons"] == [code]
    pinned = ["--policy", "gate-policy.json", "--policy-sha256", gate_case["pin"], "--repo", str(gate_case["repo"]),
              "--base", gate_case["base"], "--head", gate_case["head"]]
    assert _doctor(pinned, capsys) == (1, "blocked", [(code, field)])


def test_a_refused_path_in_the_range_does_not_hide_the_policy_refusal(gate_case, capsys):
    changes, code, field = CASES["data-suffix"]
    change_policy(gate_case, **changes)
    repo = gate_case["repo"]
    (repo / "src/positions.csv").write_text("Name;Amount\nSYN-1;1\n", encoding="utf-8")
    command(repo, "add", "src/positions.csv")
    command(repo, "commit", "-m", "Synthetic data file")
    gate_case["head"] = command(repo, "rev-parse", "HEAD")
    report, calls = run(gate_case)
    assert not calls and report["reasons"] == [code]
    pinned = ["--policy", "gate-policy.json", "--policy-sha256", gate_case["pin"], "--repo", str(repo),
              "--base", gate_case["base"], "--head", gate_case["head"]]
    assert _doctor(pinned, capsys) == (1, "blocked", [(code, field)])


def test_reviewable_suffixes_and_an_exact_yaml_path_are_accepted():
    document = model_policy()
    document["model_review"].update(text_suffixes=[".py", ".kt"], **_entry("ci/service.yml"))
    check_draft(document)
