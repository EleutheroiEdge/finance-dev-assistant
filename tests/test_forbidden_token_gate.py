"""Synthetic end-to-end confidential-number gate refusal tests."""

import hashlib
import json

import pytest

from conftest import command, holds_number
from test_model_gate import gate_case, change_policy, run  # noqa: F401
from test_model_policy import policy_case  # noqa: F401
from test_providers_review import envelope, response
from finassist.ledger import Ledger
from finassist.security import canonical


def candidate(case, text, name="src/cash.py"):
    (case["repo"] / name).write_text(text, encoding="utf-8", newline="")
    command(case["repo"], "add", name)
    command(case["repo"], "commit", "-m", "Synthetic numeric screening case")
    case["head"] = command(case["repo"], "rev-parse", "HEAD")


@pytest.mark.parametrize("text", [
    "value = 6729102.50", "# $6,729,102.500", 'fixture = "6 729 102.50"',
    "# src/6729102.50.py", "total = approx(6729102.50)",
    "# Q3 balance (6,729,102.50)", "loss = -6729102.50",
    "round(6729102.50, 2)", "values = [6729102.50,2]",
    "Rs.6729102.50", "# see ledger.6729102.50.csv",
])
def test_numeric_hash_refuses_content_before_key_or_ledger(request, text, monkeypatch):
    case = request.getfixturevalue("gate_case")
    change_policy(case, forbidden_token_hashes=[hashlib.sha256(b"6729102.5").hexdigest()])
    candidate(case, text)
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    report, calls = run(case)
    assert not calls and report["reasons"] == ["forbidden_token_present"]
    assert not (case["state"] / "audit.sqlite").exists()
    assert not holds_number(canonical(report).decode(), "6729102")


def test_filename_alone_does_not_refuse(request):
    case = request.getfixturevalue("gate_case")
    change_policy(case, forbidden_token_hashes=[hashlib.sha256(b"6729102.5").hexdigest()])
    candidate(case, "# safe synthetic source", "src/6729102.50.py")
    def covered(packet):
        return envelope(json.dumps({"head": packet["head"], "summary": "Synthetic coverage",
            "reviewed_paths": [f["path"] for f in packet["files"]], "findings": []}))

    report, calls = run(case, covered)
    assert report["verdict"] == "PASS" and len(calls) == 1, report


def test_external_file_refuses_and_is_never_in_request(request, tmp_path):
    case = request.getfixturevalue("gate_case")
    path = tmp_path / "numbers.txt"
    path.write_text("6729102.50")
    change_policy(case, forbidden_token_file=str(path))
    report, calls = run(case)
    assert report["verdict"] == "PASS" and len(calls) == 1, report
    assert str(path) not in calls[0].content.decode()
    assert not holds_number(calls[0].content.decode(), "6729102")
    candidate(case, "# 6729102.50")
    report, calls = run(case)
    assert not calls and report["reasons"] == ["forbidden_token_present"]


@pytest.mark.parametrize("claim", ["Fictional value $6,729,102.500", "approx(6729102.50)"])
def test_provider_invented_number_is_removed_after_usage_settlement(request, claim):
    case = request.getfixturevalue("gate_case")
    change_policy(case, forbidden_token_hashes=[hashlib.sha256(b"6729102.5").hexdigest()])

    def echo(packet):
        value = response(packet)
        value["findings"][0]["claim"] = claim
        return envelope(json.dumps(value))

    report, calls = run(case, echo)
    assert len(calls) == 1 and report["reasons"] == ["forbidden_token_present"]
    assert report["findings"] == [] and report["spend"]["actual_usd"] == "0.0003"
    with Ledger(case["state"] / "audit.sqlite") as ledger:
        assert not ledger.open_reservations()
        assert not holds_number(canonical(ledger.events()).decode(), "6729102")
    assert "6,729,102" not in canonical(report).decode()


def test_profile_is_screened_before_key(request, monkeypatch):
    case = request.getfixturevalue("gate_case")
    change_policy(case, forbidden_token_hashes=[hashlib.sha256(b"6729102.5").hexdigest()],
                  profile_text=["Inspect fictional value 6729102.50."])
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    report, calls = run(case)
    assert not calls and report["reasons"] == ["forbidden_token_present"]
    assert not (case["state"] / "audit.sqlite").exists()


def test_later_history_case_refuses_before_first_key_or_reservation(request, monkeypatch):
    from copy import deepcopy
    from finassist.errors import AssistantError
    from test_history_evaluation import execute, model_suite

    case = request.getfixturevalue("gate_case")
    change_policy(case, forbidden_token_hashes=[hashlib.sha256(b"6729102.5").hexdigest()])
    suite = model_suite(case)
    candidate(case, "# 6729102.50")
    bad = deepcopy(suite["cases"][0])
    bad.update(id="forbidden-later-case", head_sha=case["head"])
    suite["cases"].append(bad)
    monkeypatch.setattr("finassist.model_gate.request_shape", lambda *a: pytest.fail("credential preflight reached"))
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        execute(case, suite)
    assert not case["state"].exists()


def test_token_file_change_after_request_preparation_blocks_dispatch(request, tmp_path, monkeypatch):
    import finassist.model_gate as gate

    case = request.getfixturevalue("gate_case")
    path = tmp_path / "numbers.txt"
    path.write_text("6729102.50")
    change_policy(case, forbidden_token_file=str(path))
    original = gate.call_model

    def changed(*args, **kwargs):
        path.write_text("839201.25")
        return original(*args, **kwargs)

    monkeypatch.setattr(gate, "call_model", changed)
    report, calls = run(case)
    assert not calls and report["reasons"] == ["forbidden_token_configuration_changed"]
    assert not (case["state"] / "audit.sqlite").exists()


@pytest.mark.parametrize("name,expected", [("numbers.txt", None), ("6729102.50.txt", "[redacted]"), ("q-6729102.50.txt", "[redacted]")])
def test_private_audit_contains_only_safe_path_and_count(request, tmp_path, name, expected):
    case = request.getfixturevalue("gate_case")
    path = tmp_path / name
    path.write_text("6729102.50")
    change_policy(case, forbidden_token_file=str(path))
    report, calls = run(case)
    assert report["verdict"] == "PASS" and len(calls) == 1
    with Ledger(case["state"] / "audit.sqlite") as ledger:
        events = ledger.events()
        event = next(e["payload"] for e in events if e["payload"]["event"] == "forbidden_token_file_screened")
    assert {k: v for k, v in event.items() if k not in {"event_schema", "recorded_at"}} == {"event": "forbidden_token_file_screened", "file_path": expected or str(path), "line_count": 1}
    assert not holds_number(canonical(events).decode(), "6729102")
    assert str(path) not in canonical(report).decode()


@pytest.mark.parametrize("mode", ["removed", "unchanged-context", "fixture"])
def test_entire_before_after_and_allowed_fixture_are_screened(request, mode, monkeypatch):
    case = request.getfixturevalue("gate_case")
    changes = {"forbidden_token_hashes": [hashlib.sha256(b"6729102.5").hexdigest()]}
    if mode == "fixture":
        changes.update(allow_paths=["src/", "tests/"], fixture_roots=["tests/fixtures/"])
        change_policy(case, **changes)
        from test_policy_text_fixtures import candidate as fixture_candidate
        fixture_candidate(case, "tests/fixtures/numbers.csv", b"symbol,value,count\nSYNTHETIC,6729102.50,100\n")
    else:
        # Put the figure in the base, so deletion and unchanged context must
        # both be screened even though neither adds it to the diff.
        (case["repo"] / "src/numbers.py").write_text("# 6729102.50\nvalue = 1\n")
        command(case["repo"], "add", "src/numbers.py")
        command(case["repo"], "commit", "-m", "Synthetic base context")
        change_policy(case, **changes)
        candidate(case, "value = 2\n" if mode == "removed" else "# 6729102.50\nvalue = 2\n", "src/numbers.py")
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    report, calls = run(case)
    assert not calls and report["reasons"] == ["forbidden_token_present"]
    assert not (case["state"] / "audit.sqlite").exists()


def test_token_file_in_another_checkout_of_same_repository_is_refused(request, tmp_path):
    case = request.getfixturevalue("gate_case")
    sibling = tmp_path / "other-checkout"
    command(case["repo"], "worktree", "add", "--detach", str(sibling), case["base"])
    path = sibling / "numbers.txt"
    path.write_text("6729102.50")
    change_policy(case, forbidden_token_file=str(path))
    report, calls = run(case)
    assert not calls and report["reasons"] == ["forbidden_token_file_invalid"]
    assert not (case["state"] / "audit.sqlite").exists()


def test_deleted_token_file_after_preflight_refuses_without_reservation(request, tmp_path, monkeypatch):
    import finassist.model_gate as gate
    case = request.getfixturevalue("gate_case")
    path = tmp_path / "numbers.txt"
    path.write_text("6729102.50")
    change_policy(case, forbidden_token_file=str(path))
    original = gate.call_model

    def deleted(*args, **kwargs):
        path.unlink()
        return original(*args, **kwargs)

    monkeypatch.setattr(gate, "call_model", deleted)
    report, calls = run(case)
    assert not calls and report["reasons"] == ["forbidden_token_file_invalid"]
    assert not (case["state"] / "audit.sqlite").exists()


def test_history_token_file_in_separate_policy_repository_refused(request, tmp_path, monkeypatch):
    from finassist.errors import AssistantError
    from test_history_evaluation import execute, model_suite, policy_repository
    from test_model_policy import model_policy
    case = request.getfixturevalue("gate_case")
    document = model_policy()
    path = tmp_path / "policies" / "numbers.txt"
    document["model_review"]["forbidden_token_file"] = str(path)
    suite = model_suite(case)
    suite["cases"][0]["policy"] = policy_repository(tmp_path, document=document)
    path.write_text("6729102.50")
    monkeypatch.setattr("finassist.model_gate.request_shape", lambda *a: pytest.fail("credential preflight"))
    with pytest.raises(AssistantError, match="^forbidden_token_file_invalid$"):
        execute(case, suite)
    assert not case["state"].exists()
