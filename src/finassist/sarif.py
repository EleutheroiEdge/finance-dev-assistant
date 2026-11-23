"""SARIF 2.1.0 from a model-gate report or the publication scan's output, for code-scanning upload.

Only what the input already holds is written: for a gate finding its severity, file, line, claim and
id, for a scan finding its path and code. A gate report is checked against its schema and its own hash
first: a report whose hash does not match its content is refused. The hash shows that the report is
consistent, not where it came from. The verdict and its reasons travel as tool notifications, because
they name no file. A finding's id is bound to its request, so it is kept as trace metadata and is not
offered as an alert fingerprint; the upload step computes the location fingerprint from the checked-out
source. With an expected head, a gate report for any other commit is refused, and so is scan output, which
names none: the hash cannot show that, and an upload step annotates one commit. Nothing is fetched or sent,
and the output is the same bytes for the same input.
"""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from urllib.parse import quote

from . import __version__
from .errors import AssistantError
from .publication import SCAN_QUALIFICATION
from .security import canonical, regular_path, write_private

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"  # names the format; never fetched
INFORMATION_URI = "https://github.com/EleutheroiEdge/finance-dev-assistant"
_LIMIT = 8_000_000  # bytes read from the input at most
_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SCAN_KEYS = {"files", "findings", "passed", "qualification"}
_CODE = re.compile(r"[a-z][a-z0-9_]{0,80}")
_DEPTH = 64  # nesting no gate report or scan output approaches
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def run_sarif(args) -> int:
    """`finassist sarif INPUT --output FILE [--expect-head SHA]`: stdout `{output, results}`."""
    output = Path(args.output)
    if output.exists() or output.is_symlink():
        raise AssistantError("output_exists")
    sarif = from_document(_read(Path(args.input)), expect_head=getattr(args, "expect_head", None))
    write_private(output, serialize(sarif))
    print(canonical({"output": str(output), "results": len(sarif["runs"][0]["results"])}).decode())
    return 0


def serialize(sarif: dict) -> bytes:
    return json.dumps(sarif, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"


def _read(path: Path) -> dict:
    file = regular_path(path)  # a link is refused as it is everywhere else
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(file, flags)
    except OSError as exc:
        raise AssistantError("sarif_input_unreadable") from exc
    try:
        # Only a regular file is read: a pipe or a device could block or never end before the bound applies.
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AssistantError("sarif_input_unreadable")
        content = os.read(descriptor, _LIMIT + 1)
        while len(content) <= _LIMIT:
            more = os.read(descriptor, _LIMIT + 1 - len(content))
            if not more:
                break
            content += more
    except OSError as exc:
        raise AssistantError("sarif_input_unreadable") from exc
    finally:
        os.close(descriptor)
    if len(content) > _LIMIT:
        raise AssistantError("sarif_input_unreadable")
    # Nesting deep enough to exhaust the decoder is unreadable input. Where the decoder copes, the depth
    # check refuses the same input the same way, so the outcome does not depend on the Python version.
    try:
        document = json.loads(content.decode("utf-8"), parse_constant=_no_constant, object_pairs_hook=_no_duplicates)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise AssistantError("sarif_input_unreadable") from exc
    if _too_deep(document):
        raise AssistantError("sarif_input_unreadable")
    if not isinstance(document, dict):
        raise AssistantError("sarif_input_unknown")
    return document


def _too_deep(document) -> bool:
    """Whether arrays and objects nest more than _DEPTH levels, found without recursion."""
    stack = [(document, 1)]
    while stack:
        value, depth = stack.pop()
        if isinstance(value, (dict, list)):
            if depth > _DEPTH:
                return True
            stack.extend((child, depth + 1) for child in (value.values() if isinstance(value, dict) else value))
    return False


def _no_constant(name: str):
    raise ValueError(f"{name} is not JSON")  # NaN, Infinity and -Infinity


def _no_duplicates(pairs: list) -> dict:
    document = dict(pairs)
    if len(document) != len(pairs):
        raise ValueError("a key appears twice")
    return document


def from_document(document: dict, *, expect_head: str | None = None) -> dict:
    """The SARIF log for a gate report or a scan output; anything else is refused. With `expect_head`, only a
    gate report for exactly that full commit SHA is converted."""
    if expect_head is not None and not (type(expect_head) is str and _SHA.fullmatch(expect_head)):
        raise AssistantError("sarif_head_mismatch")
    mode = document.get("mode")
    if mode in {"model-review", "model-review-not-applicable"}:
        from .model_gate import validate_model_report

        validate_model_report(document)
        if expect_head is not None and document["head"] != expect_head:
            raise AssistantError("sarif_head_mismatch")
        return _not_applicable(document) if mode == "model-review-not-applicable" else _gate(document)
    if set(document) == _SCAN_KEYS:
        _check_scan(document)
        if expect_head is not None:
            raise AssistantError("sarif_head_mismatch")
        return _scan(document)
    raise AssistantError("sarif_input_unknown")


def _check_scan(document: dict) -> None:
    """The whole shape `scan` prints, before anything of it is copied."""
    findings, files, passed = document["findings"], document["files"], document["passed"]
    if (type(files) is not int or files < 0 or type(passed) is not bool or not isinstance(findings, list)
            or document["qualification"] != SCAN_QUALIFICATION or passed != (not findings)):
        raise AssistantError("sarif_input_unknown")
    for finding in findings:
        if (not isinstance(finding, dict) or set(finding) != {"path", "code"} or not isinstance(finding["code"], str)
                or _CODE.fullmatch(finding["code"]) is None or not isinstance(finding["path"], str)
                or not 1 <= len(finding["path"]) <= 4096):
            raise AssistantError("sarif_input_unknown")


def _uri(path: object) -> str:
    if not isinstance(path, str) or not path or "\\" in path:
        raise AssistantError("sarif_input_unknown")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts:
        raise AssistantError("sarif_input_unknown")
    return quote(str(pure), safe="/")


def _location(path: object, line: int | None = None) -> dict:
    physical = {"artifactLocation": {"uri": _uri(path), "uriBaseId": "%SRCROOT%"}}
    if line is not None:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def _gate(report: dict) -> dict:
    results, used = [], {}
    for finding in report["findings"]:
        severity = finding["severity"]
        rule = "model-review/" + severity
        used[rule] = severity
        result = {"ruleId": rule, "level": _LEVELS[severity], "message": {"text": finding["claim"]},
                  "locations": [_location(finding["file"], finding["line"])]}
        if "id" in finding:
            # Bound to its request, so it changes when the request does: trace metadata, not a fingerprint.
            result["properties"] = {"finledgerpoliFindingId": finding["id"]}
        results.append(result)
    rules = [{"id": rule, "name": rule.replace("/", "-"),
              "shortDescription": {"text": f"A {severity} finding of the model review"},
              "defaultConfiguration": {"level": _LEVELS[severity]}} for rule, severity in sorted(used.items())]
    notifications = [{"level": "error" if report["verdict"] == "BLOCKED" else "warning",
                      "message": {"text": f"Gate verdict {report['verdict']}: {code}"}, "descriptor": {"id": code}}
                     for code in report["reasons"]]
    invocation = {"executionSuccessful": report["verdict"] != "BLOCKED", "toolExecutionNotifications": notifications}
    properties = {key: report[key] for key in ("verdict", "reasons", "base", "head", "policy_sha256",
                                                "request_sha256", "report_hash")}
    return _log(rules, results, invocation, {"kind": "model-gate-report", **properties})


def _not_applicable(report: dict) -> dict:
    """No changed file was in the policy's scope, so nothing was reviewed: zero results, and a notification that
    says so, so that an empty log is never read as a clean review."""
    notification = {"level": "note", "descriptor": {"id": "nothing_in_scope"},
                    "message": {"text": "No changed file is in this policy's scope, so nothing was reviewed. "
                                        "NOT_APPLICABLE is not a review or a pass."}}
    invocation = {"executionSuccessful": True, "toolExecutionNotifications": [notification]}
    properties = {key: report[key] for key in ("verdict", "reasons", "base", "head", "policy_sha256",
                                                "scope", "evaluation_sha256", "report_hash")}
    return _log([], [], invocation, {"kind": "model-gate-not-applicable", **properties})


def _scan(document: dict) -> dict:
    results, codes = [], set()
    for finding in document["findings"]:
        codes.add(finding["code"])
        results.append({"ruleId": finding["code"], "level": "error",
                        "message": {"text": f"Publication scan: {finding['code']}"},
                        "locations": [_location(finding["path"])]})
    rules = [{"id": code, "name": code, "shortDescription": {"text": f"Publication scan finding {code}"},
              "defaultConfiguration": {"level": "error"}} for code in sorted(codes)]
    invocation = {"executionSuccessful": True, "toolExecutionNotifications": []}
    return _log(rules, results, invocation, {"kind": "scan", "files": document["files"],
                                             "passed": document["passed"],
                                             "qualification": document["qualification"]})


def _log(rules: list, results: list, invocation: dict, properties: dict) -> dict:
    driver = {"name": "finledgerpoli", "version": __version__, "semanticVersion": __version__,
              "informationUri": INFORMATION_URI, "rules": rules}
    run = {"tool": {"driver": driver}, "results": results, "invocations": [invocation],
           "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "The repository root"}}},
           "properties": properties}
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
