"""Local adjudication and Markdown safety with synthetic model-gate reports."""
from copy import deepcopy
import json

import pytest

from finassist.cli import main
from finassist.errors import AssistantError
from finassist.model_gate import refused_model_report
from finassist.report_trace import read_trace_input, score_gate_report, trace_markdown
from finassist.security import canonical
from test_model_gate import run

pytest_plugins = ("test_model_gate", "test_model_policy")


@pytest.fixture
def report(gate_case):
    return run(gate_case)[0]


def judgment(report, outcome="Confirmed", note="Synthetic check reproduced"):
    return {report["findings"][0]["id"]: {"outcome": outcome, "note": note}}


def test_trace_has_claim_identity_location_and_human_disposition(report):
    before = deepcopy(report)
    text = trace_markdown(report, judgment(report))
    assert "| # | Reviewer claim | Trace | Result |" in text
    assert f"| 1 · {report['findings'][0]['id']} | Deposits subtract from cash | src\\/cash\\.py:2 | Confirmed — Synthetic check reproduced |" in text
    assert report["request_sha256"] in text and report["report_hash"] in text
    assert report == before


def test_partial_adjudication_remains_unresolved_and_has_no_accuracy_metric(report):
    result = score_gate_report(report)
    assert result["complete"] is False and result["counts"]["Unresolved"] == 1
    assert "Unresolved" in trace_markdown(report)
    assert "precision" not in result and "recall" not in result
    completed = score_gate_report(report, judgment(report, "Partly right", "Check bound differs"))
    assert completed["complete"] is True and completed["counts"]["Partly right"] == 1


def test_blocked_empty_report_is_never_scored_as_complete():
    report = refused_model_report("provider_key_missing")
    assert score_gate_report(report)["complete"] is False
    assert "empty table is not evidence of a clean review" in trace_markdown(report)


@pytest.mark.parametrize("mapping,reason", [
    ({"f-" + "0" * 64: {"outcome": "Refuted", "note": ""}}, "adjudication_unknown_finding"),
    ([], "adjudications_invalid"),
])
def test_unknown_or_malformed_adjudications_are_rejected(report, mapping, reason):
    with pytest.raises(AssistantError, match="^" + reason + "$"):
        trace_markdown(report, mapping)


@pytest.mark.parametrize("value", [None, {}, {"outcome": "Confirmed"},
                                   {"outcome": "Approved", "note": ""},
                                   {"outcome": "Refuted", "note": "x" * 2001},
                                   {"outcome": "Refuted", "note": "", "authority": True}])
def test_bad_judgments_are_refused(report, value):
    with pytest.raises(AssistantError, match="^adjudications_invalid$"):
        score_gate_report(report, {report["findings"][0]["id"]: value})


def test_model_and_note_markup_are_plain_table_text(report):
    text = trace_markdown(report, judgment(report, "Refuted", "<script>alert(1)</script> | [run](https://example.invalid)\n::warning::`boom`"))
    row = next(line for line in text.splitlines() if line.startswith("| 1 "))
    assert "<script>" not in row and r"\<script\>" in row
    assert "\\|" in row and "\\[run\\]" in row and "\\`boom\\`" in row
    assert "\\:\\:warning\\:\\:" in row


def test_invisible_note_controls_are_refused(report):
    with pytest.raises(AssistantError, match="^trace_text_invalid$"):
        trace_markdown(report, judgment(report, note="hidden\u202econtrol"))


def test_duplicate_json_keys_are_rejected(tmp_path):
    path = tmp_path / "judgments.json"
    path.write_text('{"same": {}, "same": {}}')
    with pytest.raises(AssistantError, match="^trace_input_invalid$"):
        read_trace_input(path)


def test_trace_and_score_cli_are_offline_and_preserve_existing_outputs(report, tmp_path, capsys):
    source, labels, output, scored = (tmp_path / name for name in ("report.json", "labels.json", "trace.md", "score.json"))
    source.write_bytes(canonical(report))
    labels.write_bytes(canonical(judgment(report)))
    assert main(["report", "trace", "--report", str(source), "--adjudications", str(labels), "--output", str(output)]) == 0
    assert "Deposits subtract" not in capsys.readouterr().out
    original = output.read_bytes()
    assert main(["report", "trace", "--report", str(source), "--output", str(output)]) == 2
    assert output.read_bytes() == original
    assert main(["score", "--report", str(source), "--adjudications", str(labels), "--output", str(scored)]) == 0
    assert json.loads(scored.read_bytes())["complete"] is True
    assert main(["score", "--report", str(source), "--labels", str(labels), "--output", str(tmp_path / "wrong.json")]) == 2



def test_claim_markup_is_escaped_after_identity_validation(report):
    from finassist.finding_identity import finding_identifier
    from finassist.security import digest
    report["findings"][0]["claim"] = "<img src=x onerror=alert(1)> | [click](https://example.invalid)"
    finding = report["findings"][0]
    finding["id"] = finding_identifier(report["request_sha256"], 0, finding)
    report["report_hash"] = digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
    text = trace_markdown(report)
    assert r"\<img" in text
    assert "\\|" in text and "\\[click\\]" in text



def test_legacy_trace_derives_ids_without_mutating_archive(report):
    from finassist.security import digest
    legacy = deepcopy(report)
    original_id = legacy["findings"][0].pop("id")
    legacy["schema_version"] = 1
    legacy["report_hash"] = digest(canonical({k: v for k, v in legacy.items() if k != "report_hash"}))
    before = canonical(legacy)
    text = trace_markdown(legacy, {original_id: {"outcome": "Refuted", "note": "Synthetic refutation"}})
    assert "legacy v1 report" in text and original_id in text and "Refuted" in text
    assert canonical(legacy) == before


def test_apostrophes_dollars_mentions_and_references_render_literally():
    from finassist.report_trace import _text
    assert _text("The account's balance") == r"The account\'s balance"
    assert _text("Fee is $x^2$ and range $5-$10") == r"Fee is \$x\^2\$ and range \$5\-\$10"
    assert _text("@octocat @org/team #12 owner/repo#5 GH-7") == (
        r"@&#8203;octocat @&#8203;org\/team #&#8203;12 owner\/repo#&#8203;5 GH&#8203;\-7")


@pytest.mark.parametrize("char", ["\u200b", "\u00ad", "\u200d", "\x07", "\x85", "\u202e"])
def test_invisible_model_claims_remain_traceable_but_operator_notes_refuse(report, char):
    from finassist.finding_identity import finding_identifier
    from finassist.security import digest
    finding = report["findings"][0]
    finding["claim"] = "Synthetic" + char + "claim"
    finding["id"] = finding_identifier(report["request_sha256"], 0, finding)
    report["report_hash"] = digest(canonical({k: v for k, v in report.items() if k != "report_hash"}))
    before = canonical(report)
    assert score_gate_report(report)["counts"]["Unresolved"] == 1
    text = trace_markdown(report)
    assert f"U\\+{ord(char):04X}" in text and char not in text
    assert canonical(report) == before
    with pytest.raises(AssistantError, match="^trace_text_invalid$"):
        score_gate_report(report, judgment(report, note="Operator" + char + "note"))


def test_rendered_cells_preserve_literal_punctuation_and_disable_html():
    import comrak
    from finassist.report_trace import _text
    options = comrak.RenderOptions()
    options.unsafe_ = True
    raw = "The account's balance: $5-$10 <script>x</script> @octocat #12"
    rendered = comrak.render_markdown(_text(raw), render_options=options)
    assert "account's balance: $5-$10" in rendered
    assert "&lt;script&gt;" in rendered and "<script>" not in rendered
    assert "@\u200boctocat" in rendered and "#\u200b12" in rendered
    assert "<a " not in rendered
