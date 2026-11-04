"""Offline finding adjudication and escaped Markdown; never posts a review."""

from pathlib import Path
import re
import string
import unicodedata

from .ci_policy import read_document
from .errors import AssistantError
from .finding_identity import finding_identifier
from .model_gate import validate_model_report
from .security import canonical, digest

OUTCOMES = ("Confirmed", "Partly right", "Refuted")


def read_trace_input(path: Path) -> dict:
    """Bound input bytes and reject duplicate keys, including nested judgments."""
    try:
        return read_document(path, limit=1_000_000)
    except (AssistantError, OSError):
        raise AssistantError("trace_input_invalid") from None


def _text(value: str, *, operator_note: bool = False) -> str:
    if not isinstance(value, str):
        raise AssistantError("trace_text_invalid")
    visible = []
    for char in value:
        hidden = ((unicodedata.category(char).startswith("C") or char in "\u2028\u2029")
                  and char not in "\n\r\t")
        if hidden and operator_note:
            raise AssistantError("trace_text_invalid")
        visible.append(f"[U+{ord(char):04X}]" if hidden else char)
    text = " ".join("".join(visible).split())
    text = re.sub("([" + re.escape(string.punctuation) + "])", r"\\\1", text)
    # Insert generated entities only after escaping, so their syntax survives.
    # This breaks GitHub's rendered-text mention/reference recognition.
    text = re.sub(r"(?i)(GH)(?=\\-[0-9])", r"\1&#8203;", text)
    return text.replace(r"\@", "@&#8203;").replace(r"\#", "#&#8203;")


def _rows(report: dict, adjudications: dict | None) -> list[dict]:
    validate_model_report(report)
    judgments = {} if adjudications is None else adjudications
    if not isinstance(judgments, dict) or len(judgments) > 50:
        raise AssistantError("adjudications_invalid")
    findings = [{**finding, "id": finding_identifier(report["request_sha256"], index, finding)}
                for index, finding in enumerate(report["findings"])]
    if set(judgments) - {finding["id"] for finding in findings}:
        raise AssistantError("adjudication_unknown_finding")
    rows = []
    for finding in findings:
        value = judgments.get(finding["id"])
        if finding["id"] in judgments:
            if (not isinstance(value, dict) or set(value) != {"outcome", "note"}
                    or not isinstance(value["outcome"], str) or value["outcome"] not in OUTCOMES
                    or not isinstance(value["note"], str) or len(value["note"]) > 2000):
                raise AssistantError("adjudications_invalid")
            _text(value["note"], operator_note=True)
        rows.append({**finding, "outcome": value["outcome"] if value is not None else "Unresolved",
                     "note": value["note"] if value is not None else ""})
    return rows


def score_gate_report(report: dict, adjudications: dict | None = None) -> dict:
    rows = _rows(report, adjudications)
    counts = {outcome: sum(row["outcome"] == outcome for row in rows)
              for outcome in (*OUTCOMES, "Unresolved")}
    result = {"schema_version": 1, "kind": "gate-adjudication-score", "report_hash": report["report_hash"],
              "request_sha256": report["request_sha256"], "counts": counts,
              "complete": report["verdict"] != "BLOCKED" and counts["Unresolved"] == 0,
              "adjudications_sha256": digest(canonical({} if adjudications is None else adjudications)),
              "qualification": "Human dispositions of returned findings only; no recall or accuracy claim. "
              "Hashes bind bytes, not judgment truth or identity. Gate verdict and authority are unchanged."}
    return {**result, "score_hash": digest(canonical(result))}


def trace_markdown(report: dict, adjudications: dict | None = None) -> str:
    rows = _rows(report, adjudications)
    lines = ["Advisory finding trace. Human dispositions do not change the gate verdict or grant merge authority.",
             "", "Report: " + report["report_hash"], "Request: " + (report["request_sha256"] or "unavailable"), ""]
    if report["schema_version"] == 1:
        lines.extend(["IDs below are derived from this legacy v1 report; the source artifact is unchanged.", ""])
    if report["verdict"] == "BLOCKED":
        lines.extend(["Review blocked; an empty table is not evidence of a clean review.", ""])
    lines.extend(["| # | Reviewer claim | Trace | Result |", "| --- | --- | --- | --- |"])
    for index, row in enumerate(rows, 1):
        result = row["outcome"] + (" — " + _text(row["note"], operator_note=True) if row["note"] else "")
        lines.append(f"| {index} · {row['id']} | {_text(row['claim'])} | "
                     f"{_text(row['file'])}:{row['line']} | {result} |")
    if not rows:
        lines.extend(["", "No returned findings."])
    return "\n".join(lines) + "\n"
