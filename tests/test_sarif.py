"""`finassist sarif`: a gate report or scan output becomes a SARIF 2.1.0 log, an edited report is refused."""

import json
import os
import signal

import pytest

from finassist.cli import main
from finassist.errors import AssistantError
from finassist.model_gate import _blank_report, finding_identifier, refused_model_report
from finassist.sarif import from_document, serialize
from finassist.security import canonical, digest

REQUEST = "d" * 64
STATUS = "source-reference-validated-not-reproduced"


def gate_report(findings, verdict="FAIL", reasons=("blocking_findings",)):
    report = _blank_report()
    report.update(verdict=verdict, reasons=list(reasons), base="a" * 40, head="b" * 40, policy_sha256="c" * 64,
                  request_sha256=REQUEST, usage={"input_tokens": 120, "output_tokens": 30},
                  spend={"reserved_usd": "0.10", "actual_usd": "0.02", "scope": "caller-retained-ledger"})
    report["findings"] = [dict(finding, evidence_status=STATUS,
                               id=finding_identifier(REQUEST, index, dict(finding, evidence_status=STATUS)))
                          for index, finding in enumerate(findings)]
    report["report_hash"] = digest(canonical({key: value for key, value in report.items() if key != "report_hash"}))
    return report


FINDINGS = [
    {"severity": "high", "file": "src/cash.py", "line": 2, "claim": "Deposits are subtracted from the balance."},
    {"severity": "low", "file": "docs/notes on cash.md", "line": 1, "claim": "The note says nothing new."},
]


def test_a_gate_report_becomes_a_sarif_log():
    report = gate_report(FINDINGS)
    log = from_document(report)
    assert log["version"] == "2.1.0" and len(log["runs"]) == 1
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "finledgerpoli"
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["model-review/high", "model-review/low"]
    first, second = run["results"]
    assert first["level"] == "error" and second["level"] == "note"
    assert first["message"]["text"] == FINDINGS[0]["claim"]
    location = first["locations"][0]["physicalLocation"]
    assert location == {"artifactLocation": {"uri": "src/cash.py", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 2}}
    assert second["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "docs/notes%20on%20cash.md"
    # The id is bound to its request: trace metadata, never offered as an alert fingerprint.
    assert first["properties"] == {"finledgerpoliFindingId": report["findings"][0]["id"]}
    assert "partialFingerprints" not in first and "fingerprints" not in first
    assert run["properties"]["verdict"] == "FAIL" and run["properties"]["report_hash"] == report["report_hash"]
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert [note["descriptor"]["id"] for note in notes] == ["blocking_findings"]
    assert run["invocations"][0]["executionSuccessful"] is True


def test_a_blocked_report_carries_its_reasons_and_no_results():
    log = from_document(refused_model_report("gate_budget_exceeded"))
    run = log["runs"][0]
    assert run["results"] == [] and run["invocations"][0]["executionSuccessful"] is False
    note = run["invocations"][0]["toolExecutionNotifications"][0]
    assert note["level"] == "error" and note["descriptor"]["id"] == "gate_budget_exceeded"


def test_an_edited_report_is_refused():
    report = gate_report(FINDINGS)
    report["findings"][0]["line"] = 3  # its id and the report hash no longer match
    with pytest.raises(AssistantError) as refused:
        from_document(report)
    assert refused.value.code == "gate_report_invalid"


def test_scan_output_becomes_a_sarif_log():
    scan = {"files": 3, "findings": [{"path": "src/app.py", "code": "sensitive_content"}], "passed": False,
            "qualification": "Supplementary scan; inspect staged bytes and full history before publication."}
    run = from_document(scan)["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["sensitive_content"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
    assert run["properties"] == {"kind": "scan", "files": 3, "passed": False,
                                 "qualification": scan["qualification"]}


@pytest.mark.parametrize("document", [
    {"mode": "something-else"},
    {"files": 1, "findings": "none", "passed": True, "qualification": "x"},
    {"files": 1, "findings": [{"path": "/etc/passwd", "code": "sensitive_content"}], "passed": False,
     "qualification": "x"},
    {"files": 1, "findings": [{"path": "../outside.py", "code": "sensitive_content"}], "passed": False,
     "qualification": "x"},
    {"files": 1, "findings": [{"path": "src\\app.py", "code": "sensitive_content"}], "passed": False,
     "qualification": "x"},
])
def test_anything_else_is_refused(document):
    with pytest.raises(AssistantError) as refused:
        from_document(document)
    assert refused.value.code == "sarif_input_unknown"


def test_the_same_report_gives_the_same_bytes():
    report = gate_report(FINDINGS)
    assert serialize(from_document(report)) == serialize(from_document(json.loads(json.dumps(report))))


def test_the_command_writes_a_new_file_and_never_replaces_one(tmp_path, capsys):
    source = tmp_path / "gate.json"
    source.write_text(json.dumps(gate_report(FINDINGS)), encoding="utf-8")
    target = tmp_path / "gate.sarif"
    assert main(["sarif", str(source), "--output", str(target)]) == 0
    assert json.loads(capsys.readouterr().out) == {"output": str(target), "results": 2}
    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert main(["sarif", str(source), "--output", str(target)]) == 2
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])["code"] == "output_exists"
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert main(["sarif", str(broken), "--output", str(tmp_path / "other.sarif")]) == 2
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])["code"] == "sarif_input_unreadable"
    assert not (tmp_path / "other.sarif").exists()


def test_an_expected_head_converts_only_that_commits_report():
    report = gate_report(FINDINGS)
    assert from_document(report, expect_head="b" * 40)["runs"][0]["properties"]["head"] == "b" * 40
    scan = {"files": 1, "findings": [], "passed": True,
            "qualification": "Supplementary scan; inspect staged bytes and full history before publication."}
    for document, head in [(report, "e" * 40), (report, "b" * 64), (report, "b" * 12), (report, "B" * 40),
                           (report, ""), (report, "b" * 40 + "\n"), (scan, "b" * 40)]:
        with pytest.raises(AssistantError) as refused:
            from_document(document, expect_head=head)
        assert refused.value.code == "sarif_head_mismatch"


def test_the_command_refuses_another_commits_report_and_writes_nothing(tmp_path, capsys):
    source = tmp_path / "gate.json"
    source.write_text(json.dumps(gate_report(FINDINGS)), encoding="utf-8")
    target = tmp_path / "gate.sarif"
    assert main(["sarif", str(source), "--output", str(target), "--expect-head", "e" * 40]) == 2
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])["code"] == "sarif_head_mismatch"
    assert not target.exists()
    assert main(["sarif", str(source), "--output", str(target), "--expect-head", "b" * 40]) == 0
    assert json.loads(capsys.readouterr().out) == {"output": str(target), "results": 2}


QUALIFICATION = "Supplementary scan; inspect staged bytes and full history before publication."


@pytest.mark.parametrize("document", [
    {"files": "3", "findings": [], "passed": True, "qualification": QUALIFICATION},
    {"files": -1, "findings": [], "passed": True, "qualification": QUALIFICATION},
    {"files": {"n": 3}, "findings": [], "passed": True, "qualification": QUALIFICATION},
    {"files": 3, "findings": [], "passed": "true", "qualification": QUALIFICATION},
    {"files": 3, "findings": [], "passed": False, "qualification": QUALIFICATION},
    {"files": 3, "findings": [{"path": "a.py", "code": "sensitive_content"}], "passed": True,
     "qualification": QUALIFICATION},
    {"files": 3, "findings": [], "passed": True, "qualification": {"text": QUALIFICATION}},
    {"files": 3, "findings": [], "passed": True, "qualification": "Something else entirely."},
    {"files": 3, "findings": [{"path": "a.py", "code": "Not A Code"}], "passed": False,
     "qualification": QUALIFICATION},
])
def test_a_scan_output_must_have_scans_whole_shape(document):
    with pytest.raises(AssistantError) as refused:
        from_document(document)
    assert refused.value.code == "sarif_input_unknown"


@pytest.mark.parametrize("raw", [
    '{"files": NaN, "findings": [], "passed": true, "qualification": "%s"}' % QUALIFICATION,
    '{"files": Infinity, "findings": [], "passed": true, "qualification": "%s"}' % QUALIFICATION,
    '{"files": 1, "files": 2, "findings": [], "passed": true, "qualification": "%s"}' % QUALIFICATION,
])
def test_only_strict_json_is_read(tmp_path, capsys, raw):
    source = tmp_path / "scan.json"
    source.write_text(raw, encoding="utf-8")
    assert main(["sarif", str(source), "--output", str(tmp_path / "scan.sarif")]) == 2
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])["code"] == "sarif_input_unreadable"
    assert not (tmp_path / "scan.sarif").exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are POSIX")
def test_a_pipe_is_refused_without_blocking(tmp_path, capsys):
    pipe = tmp_path / "report.json"
    os.mkfifo(pipe)

    def stuck(_signal, _frame):
        raise AssertionError("reading the pipe blocked")

    previous = signal.signal(signal.SIGALRM, stuck)
    signal.alarm(5)
    try:
        assert main(["sarif", str(pipe), "--output", str(tmp_path / "out.sarif")]) == 2
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])["code"] == "sarif_input_unreadable"


def _nested(depth: int) -> str:
    """An object holding arrays nested so that the document is `depth` levels deep."""
    return '{"a": ' + "[" * (depth - 1) + "0" + "]" * (depth - 1) + "}"


# Nesting past the decoder's recursion limit is the documented refusal, not a traceback.
@pytest.mark.parametrize("depth", [65, 1101, 100_000])
def test_deep_nesting_is_unreadable_input_on_every_python(tmp_path, capsys, depth):
    source = tmp_path / "deep.json"
    source.write_text(_nested(depth), encoding="utf-8")
    assert main(["sarif", str(source), "--output", str(tmp_path / "deep.sarif")]) == 2
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])["code"] == "sarif_input_unreadable"
    assert not (tmp_path / "deep.sarif").exists()


def test_nesting_within_the_bound_is_read(tmp_path, capsys):
    source = tmp_path / "shallow.json"
    source.write_text(_nested(64), encoding="utf-8")
    assert main(["sarif", str(source), "--output", str(tmp_path / "shallow.sarif")]) == 2
    assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])["code"] == "sarif_input_unknown"
