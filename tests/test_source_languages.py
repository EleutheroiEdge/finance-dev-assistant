"""A repository's own source languages decide what is reviewable: detection proposes their suffixes, and a gate
policy may state text_suffixes. Data and binary formats stay refused. Synthetic repositories and a fake provider."""

import json

import pytest

from conftest import command
from test_detect_proposal import _repo
from test_model_gate import change_policy, gate_case, run  # noqa: F401 - fixture registration
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration
from test_providers_review import envelope, response
from finassist.detect import detect
from finassist.onboarding import policy_preflight
from finassist.security import TEXT_SUFFIXES
from finassist.source_languages import CODE_SUFFIXES, SOURCE_LANGUAGES

README = "# Synthetic service\n\nA small ledger service.\n"
CSHARP = "namespace Ledger;\n\npublic static class Totals\n{\n    public static int Sum(int a, int b) => a + b;\n}\n"
KOTLIN = "package ledger\n\nfun total(values: List<Int>): Int = values.sum()\n"


def _warning(proposal, code):
    return next((w for w in proposal["warnings"] if w["code"] == code), None)


def test_a_csharp_repository_is_detected_and_its_suffix_proposed(tmp_path):
    proposal = detect(_repo(tmp_path, {"README.md": README, "src/Ledger/Totals.cs": CSHARP}))
    assert proposal["source_detected"] and "src/" in proposal["config"]["allow_paths"]
    expected = sorted(set(TEXT_SUFFIXES) | {".cs"})
    assert proposal["config"]["text_suffixes"] == expected
    assert proposal["gate_policy_draft"]["model_review"]["text_suffixes"] == expected
    assert _warning(proposal, "text_suffixes_proposed") == {"code": "text_suffixes_proposed", "suffixes": [".cs"],
                                                            "text_rules_only": [".cs"]}
    assert _warning(proposal, "no_source_detected") is None
    assert proposal["evidence"]["text_suffixes"][0] == {"value": ".cs", "rule": "source_language", "language": "C#",
                                                        "path": "src/Ledger/Totals.cs"}


def test_kotlin_is_proposed_and_read_as_code(tmp_path):
    proposal = detect(_repo(tmp_path, {"README.md": README, "app/Totals.kt": KOTLIN}))
    assert ".kt" in proposal["config"]["text_suffixes"]
    assert _warning(proposal, "text_suffixes_proposed")["text_rules_only"] == []


def test_a_repository_in_default_languages_gets_the_drafts_it_got_before(tmp_path):
    proposal = detect(_repo(tmp_path, {"README.md": README, "src/ledger/totals.py": "def total(v):\n    return 0\n"}))
    assert "text_suffixes" not in proposal["config"]
    assert "text_suffixes" not in proposal["gate_policy_draft"]["model_review"]
    assert _warning(proposal, "text_suffixes_proposed") is None


def test_vendored_and_hidden_sources_propose_nothing(tmp_path):
    proposal = detect(_repo(tmp_path, {"README.md": README, "src/app.py": "x = 1\n",
                                       "vendor/lib/thing.rb": "puts 1\n", ".tools/run.rb": "puts 2\n"}))
    assert "text_suffixes" not in proposal["config"] and _warning(proposal, "text_suffixes_proposed") is None


def test_every_listed_language_is_a_valid_reviewable_suffix():
    from finassist.config import Config
    from finassist.security import DENIED_SUFFIXES
    Config(text_suffixes=tuple(sorted(set(TEXT_SUFFIXES) | set(SOURCE_LANGUAGES)))).validate()
    assert not set(SOURCE_LANGUAGES) & DENIED_SUFFIXES
    assert CODE_SUFFIXES <= set(SOURCE_LANGUAGES)


def _reviewing_every_file(packet):
    reply = response(packet)
    reply["reviewed_paths"] = [item["path"] for item in packet["files"]]
    return envelope(json.dumps(reply))


def _change(case, files):
    repo = case["repo"]
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8")
    command(repo, "add", "--", *files)
    command(repo, "commit", "-q", "-m", "Synthetic change")
    case["head"] = command(repo, "rev-parse", "HEAD")


def test_a_gate_policy_that_lists_the_suffix_reviews_the_file(gate_case):  # noqa: F811
    change_policy(gate_case, text_suffixes=sorted(set(TEXT_SUFFIXES) | {".cs"}))
    _change(gate_case, {"src/Totals.cs": CSHARP})
    report, calls = run(gate_case, _reviewing_every_file)
    assert report["verdict"] == "PASS" and len(calls) == 1
    assert "src/Totals.cs" in [item["path"] for item in json.loads(json.loads(calls[0].content)["input"])["files"]]


def test_without_the_suffix_the_gate_still_refuses_the_file(gate_case):  # noqa: F811
    change_policy(gate_case)
    _change(gate_case, {"src/Totals.cs": CSHARP})
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["unsupported_file_type"] and not calls
    doctor = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                              gate_case["pin"])
    assert next(row for row in doctor["paths"] if row["path"] == "src/Totals.cs")["code"] == "unsupported_file_type"


def test_a_listed_suffix_gets_the_strict_text_rules(gate_case):  # noqa: F811
    change_policy(gate_case, text_suffixes=sorted(set(TEXT_SUFFIXES) | {".cs"}))
    label = "pass" + "word"
    _change(gate_case, {"src/Login.cs": f'class Login {{ string {label} = "synthetic-literal-value"; }}\n'})
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and not calls


@pytest.mark.parametrize("suffixes", [[".py", ".csv"], [".py", ".PY"], [".py", ".py"], []],
                         ids=["data-format", "upper-case", "repeated", "empty"])
def test_a_gate_policy_cannot_list_a_data_format_or_a_malformed_suffix(gate_case, suffixes):  # noqa: F811
    change_policy(gate_case, text_suffixes=suffixes)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["gate_policy_invalid"] and not calls


def test_init_detect_carries_the_proposed_suffixes_into_the_configuration(tmp_path, capsys, monkeypatch):
    from finassist.cli import main
    repo = _repo(tmp_path, {"README.md": README, "src/Ledger/Totals.cs": CSHARP})
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--detect", "--repo", str(repo)]) == 0
    proposal = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert ".cs" in proposal["config"]["text_suffixes"] and "src/" in proposal["config"]["allow_paths"]
    written = tmp_path / "finassist.json"
    assert main(["init", "--detect", "--repo", str(repo), "--revision", proposal["head"], "--write",
                 "--output", str(written)]) == 0
    saved = json.loads(written.read_text(encoding="utf-8"))
    assert saved["text_suffixes"] == proposal["config"]["text_suffixes"]


def test_init_detect_keeps_a_persons_own_suffixes(tmp_path, capsys, monkeypatch):
    from finassist.cli import main
    repo = _repo(tmp_path, {"README.md": README, "src/Ledger/Totals.cs": CSHARP})
    monkeypatch.chdir(tmp_path)
    own = tmp_path / "own.json"
    own.write_text(json.dumps({"text_suffixes": sorted(set(TEXT_SUFFIXES) | {".tf"})}), encoding="utf-8")
    assert main(["--config", str(own), "init", "--detect", "--repo", str(repo)]) == 0
    suffixes = json.loads(capsys.readouterr().out.splitlines()[-1])["config"]["text_suffixes"]
    assert {".tf", ".cs"} <= set(suffixes)


def test_init_detect_prints_no_suffixes_for_a_default_language_repository(tmp_path, capsys, monkeypatch):
    from finassist.cli import main
    repo = _repo(tmp_path, {"README.md": README, "src/ledger/totals.py": "def total(v):\n    return 0\n"})
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--detect", "--repo", str(repo)]) == 0
    assert "text_suffixes" not in json.loads(capsys.readouterr().out.splitlines()[-1])["config"]
