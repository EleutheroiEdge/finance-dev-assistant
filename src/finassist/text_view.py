"""The human view of a doctor report: it renders the JSON report, nothing more.

Only named fields are printed, so a key value or file content can never
appear. Unknown fields are ignored and a missing field never raises.
"""

from __future__ import annotations

import json
import textwrap

_EFFECT = {"sends_more": "more is sent to the provider",
           "spends_more": "a larger spend is allowed",
           "leaves_files_out": "files are left out, so coverage is incomplete",
           "none": "nothing more is sent or spent"}

# Path statuses, in the order a person asks about them.
_STATUS_WORDS = (("included", "included"), ("refused", "refused"), ("withheld", "withheld"),
                 ("omitted", "left out"), ("unchecked", "unchecked"))

_MAX_PATHS = 3  # Example paths shown per blocker; the JSON lists up to twenty.


def doctor_output(report: dict, args) -> str:
    """What `doctor` prints: its JSON report, or with `--format text` this view of it, fitted to the terminal."""
    if getattr(args, "format", "json") != "text":
        from .security import canonical

        return canonical(report).decode()
    import shutil

    return render(report, width=min(max(shutil.get_terminal_size((80, 24)).columns, 60), 120))


def render(report: dict, *, width: int = 80, color: bool = False) -> str:
    """The human view of a doctor report. Never raises on a missing or unknown field."""
    pen = _Pen(width, color)
    if not isinstance(report, dict):
        return "finassist doctor: no report to show\n"
    mode = report.get("mode")
    if mode in ("config-preflight", "gate-preflight"):
        _preflight(report, mode, pen)
    else:
        _health(report, pen)
    return pen.text()


class _Pen:
    # Collects wrapped lines; every line is fitted to the width before it is kept.
    def __init__(self, width, color):
        try:
            self.width = max(40, int(width))
        except (TypeError, ValueError):
            self.width = 80
        self.color = bool(color)
        self.lines = []

    def add(self, text="", indent=0, hang=None):
        if not text:
            self.lines.append("")
            return
        hang = indent if hang is None else hang
        wrapped = textwrap.wrap(str(text), self.width, initial_indent=" " * indent,
                                subsequent_indent=" " * hang,
                                break_long_words=False, break_on_hyphens=False)
        for line in wrapped or [""]:
            self.lines.append(_shorten(line, self.width))

    def paint(self, text, code):
        return f"\x1b[{code}m{text}\x1b[0m" if self.color else text

    def text(self):
        return "\n".join(self.lines).rstrip() + "\n"


def _shorten(text, width):
    # Fit one line to the width, shortening a long token in the middle with '...'.
    if len(text) <= width:
        return text
    if width < 8:
        return text[:width]
    keep = width - 3
    left = (keep + 1) // 2
    return text[:left] + "..." + text[len(text) - (keep - left):]


def _list(report, key):
    value = report.get(key)
    return value if isinstance(value, list) else []


def _num(value):
    return f"{value:,}" if isinstance(value, (int, float)) and not isinstance(value, bool) else str(value)


def _count(number, word):
    return f"{number} {word}" + ("s" if number != 1 else "")


def _health(report, pen):
    # The installation checks (Git, folders, key variables) are in the environment section; its blockers set the
    # exit status, so they set the verdict here too.
    environment = report.get("environment") if isinstance(report.get("environment"), dict) else {}
    blockers = [b for b in _list(environment, "blockers") if isinstance(b, dict)]
    warnings = [w for w in _list(report, "config_warnings") + _list(environment, "warnings") if isinstance(w, dict)]
    pen.add(pen.paint("finassist doctor - installation health", "1"))
    if blockers:
        status = pen.paint("BLOCKED - " + _count(len(blockers), "blocker"), "31")
    else:
        status = pen.paint(_count(len(warnings), "warning") if warnings else "healthy", "33" if warnings else "32")
    pen.add("Status: " + status)
    pen.add()
    pen.add(f"finassist {report.get('version', '?')} on Python {report.get('python', '?')}"
            f" ({report.get('platform', '?')})")
    pen.add("Provider: " + "; ".join([
        str(report.get("provider", "?")),
        "model configured" if report.get("model_configured") else "no model configured",
        "network enabled" if report.get("network_enabled") else "network disabled"]))
    key = report.get("key_present")
    pen.add("Provider key: " + ("present" if key else "not set" if key is not None
                                else "no key variable configured"))
    recipes = ", ".join(str(r) for r in _list(report, "recipes")) or "none"
    pen.add(f"Configuration: {report.get('config_source', '?')}; profile: {report.get('profile', '?')}"
            f"; recipes: {recipes}")
    found = [name for name in ("docker", "podman") if report.get(name + "_binary_present")]
    pen.add("Containers: " + (", ".join(found) + " found" if found else "no docker or podman binary found"))
    updates = report.get("updates")
    latest = updates.get("latest") if isinstance(updates, dict) else None
    pen.add("Updates: " + (f"latest release is {latest}" if latest else "not checked"))
    deprecated = _list(report, "deprecated_config_options")
    if deprecated:
        pen.add("Deprecated configuration options: " + ", ".join(str(d) for d in deprecated))
    if blockers:
        pen.add()
        _blockers(blockers, {}, pen)
    if warnings:
        pen.add()
        _warnings(warnings, pen)
    if blockers:
        # The health report's own next step assumes an installation that works.
        pen.add()
        pen.add("Next step: fix every blocker listed, then run finassist doctor again.", hang=2)
    else:
        _next_step(report.get("next_step"), pen)


def _preflight(report, mode, pen):
    name = "configuration preflight" if mode == "config-preflight" else "gate preflight"
    blockers = [b for b in _list(report, "blockers") if isinstance(b, dict)]
    warnings = [w for w in _list(report, "warnings") if isinstance(w, dict)]
    pen.add(pen.paint(f"finassist doctor - {name}", "1"))
    ready = report.get("status") == "ready"
    count = f"{len(blockers)} blocker" + ("s" if len(blockers) != 1 else "")
    verdict = pen.paint("READY" if ready else f"BLOCKED - {count}", "32" if ready else "31")
    pen.add("Verdict: " + verdict)
    _range_line(report, pen)
    policy = report.get("policy")
    if isinstance(policy, dict):
        bits = [str(policy.get("path", "?")), f"from {policy.get('source', '?')}"]
        if isinstance(policy.get("sha256"), str) and policy["sha256"]:
            bits.append("sha256 " + _shorten(policy["sha256"], 16))
        if policy.get("pin"):
            bits.append(f"pin {policy['pin']}")
        pen.add("Policy: " + "; ".join(bits))
    _provider(report.get("provider"), pen)
    for label, key in (("Packet", "packet"), ("Request", "request")):
        entry = report.get(key)
        if isinstance(entry, dict) and isinstance(entry.get("bytes"), int):
            line = f"{label}: {_num(entry['bytes'])}"
            if isinstance(entry.get("limit"), int):
                line += f" of {_num(entry['limit'])}"
            line += " bytes"
            if entry.get("reserved_usd") is not None:
                line += f"; reserves ${entry['reserved_usd']}"
            pen.add(line)
    if (report.get("network_used") is False and report.get("key_value_read") is False
            and report.get("ledger_opened") is False):
        pen.add("This run used no network, read no key value and opened no ledger.")
    if blockers:
        pen.add()
        remedies = {}
        for remedy in _list(report, "remedies"):
            if isinstance(remedy, dict) and isinstance(remedy.get("options"), list):
                remedies.setdefault(str(remedy.get("code")), []).extend(remedy["options"])
        _blockers(blockers, remedies, pen)
    if warnings:
        pen.add()
        _warnings(warnings, pen)
    _next_step(report.get("next_step"), pen)


def _range_line(report, pen):
    base, head = report.get("base"), report.get("head")
    if not (base or head):
        return
    line = f"Range: {_commit(base)}..{_commit(head)}"
    paths = [p for p in _list(report, "paths") if isinstance(p, dict)]
    counts = {word: sum(row.get("status") == status for row in paths) for status, word in _STATUS_WORDS}
    line += "".join(f"; {n} {word}" for _status, word in _STATUS_WORDS if (n := counts[word]))
    if report.get("coverage_complete") is True:
        line += "; coverage complete"
    elif report.get("coverage_complete") is False:
        line += "; coverage incomplete"
    pen.add(line, hang=2)


def _commit(value):
    # A full object name is shown by its first twelve characters, as Git abbreviates; a branch name in full.
    if isinstance(value, str) and len(value) in (40, 64) and all(c in "0123456789abcdef" for c in value):
        return value[:12]
    return str(value) if value else "?"


def _provider(provider, pen):
    if not isinstance(provider, dict):
        return
    bits = [str(provider.get("provider", "?"))]
    for key, yes, no in (("model_configured", "model configured", "no model configured"),
                         ("network_enabled", "network enabled", "network disabled"),
                         ("prices_configured", "prices set", "prices missing")):
        if provider.get(key) is not None:
            bits.append(yes if provider[key] else no)
    if provider.get("allowed_host"):
        bits.append(f"allowed host {provider['allowed_host']}")
    pen.add("Provider: " + "; ".join(bits))
    if provider.get("key_variable"):
        state = provider.get("key_state")
        if state not in ("missing", "empty", "set"):  # An older report: the variable exists or not.
            state = "set" if provider.get("key_variable_set") else "missing"
        pen.add(f"Key variable {provider['key_variable']}: "
                + {"missing": "not set", "empty": "set but empty", "set": "set"}[state])


def _blockers(blockers, remedies, pen):
    pen.add(pen.paint("Blockers", "1"))
    for index, blocker in enumerate(blockers, 1):
        if index > 1:
            pen.add()
        _entry(blocker, index, remedies.get(str(blocker.get("code")), []), pen)


def _entry(entry, index, remedies, pen):
    pen.add(f"{index}. {entry.get('code', 'unknown_code')}")
    _details(entry, pen)
    hint = entry.get("hint")
    if isinstance(hint, str) and hint:
        pen.add("Fix: " + hint, indent=2, hang=4)
    if remedies:
        pen.add("Remedies:", indent=2)
        for i, option in enumerate(o for o in remedies if isinstance(o, dict)):
            _option(option, chr(ord("a") + i) if i < 26 else str(i), pen)


def _details(entry, pen):
    # The known detail fields, in a fixed order. Every other field stays in the JSON.
    paths = [str(p) for p in _list(entry, "paths") if isinstance(p, str)]
    count = entry.get("count")
    if paths:
        label = f"{count} file" + ("s" if count != 1 else "") if isinstance(count, int) else "files"
        extra = f" (and {count - _MAX_PATHS} more)" if isinstance(count, int) and count > _MAX_PATHS else ""
        pen.add(f"{label}: " + ", ".join(paths[:_MAX_PATHS]) + extra, indent=2, hang=4)
    elif isinstance(count, int):
        pen.add(f"{count} file" + ("s" if count != 1 else ""), indent=2)
    for key, label in (("files", ""), ("bytes", "size ")):
        if isinstance(entry.get(key), int):
            line = f"{label}{_num(entry[key])} {key}"
            if isinstance(entry.get("limit"), int):
                line += f"; limit {_num(entry['limit'])}" + (" bytes" if key == "bytes" else "")
            pen.add(line, indent=2)
            break
    if isinstance(entry.get("variable"), str):
        state = entry.get("state")
        if state not in ("missing", "empty", "set"):  # A report without the state: the code says it.
            state = {"provider_key_empty": "empty", "provider_key_missing": "missing"}.get(entry.get("code"))
        line = f"key variable {entry['variable']}" + {"missing": " is not set", "empty": " is set but empty",
                                                      "set": " is set"}.get(state, "")
        if isinstance(entry.get("host"), str):
            line += f"; configured for {entry['host']}"
        pen.add(line, indent=2)
    names = [str(name) for name in _list(entry, "variables") if isinstance(name, str)]
    if names:
        pen.add("variables: " + ", ".join(names), indent=2, hang=4)
    if isinstance(entry.get("missing"), list) and entry["missing"]:
        pen.add("missing: " + ", ".join(str(m) for m in entry["missing"]), indent=2)
    if entry.get("reserved_usd") is not None:
        line = f"reserves ${entry['reserved_usd']}"
        if entry.get("limit_usd") is not None:
            line += f"; limit ${entry['limit_usd']}"
        pen.add(line, indent=2)
    for key, template in (("field", "field {}"), ("kind", "check failed with {}"), ("feature", "Git feature {}"),
                          ("path_role", "the {} folder")):
        if isinstance(entry.get(key), str):
            pen.add(template.format(entry[key]), indent=2)


def _option(option, letter, pen):
    changes = [c for c in _list(option, "changes") if isinstance(c, dict)]
    if not changes:
        return
    document = {"configuration": "the configuration",
                "gate policy": "the gate policy"}.get(option.get("document"), str(option.get("document")))
    pen.add(f"{letter}) In {document}, " + "; ".join(_change(c) for c in changes) + ".",
            indent=2, hang=5)
    effect = _EFFECT.get(option.get("effect"))
    if effect:
        pen.add("Effect: " + effect + ".", indent=5, hang=8)


def _change(change):
    setting = str(change.get("setting", "?"))
    pointer = change.get("pointer")
    if isinstance(pointer, str) and pointer.startswith("/") and pointer.count("/") > 1:
        # Where the setting lives, when that is not the document's top level: model_review.max_request_bytes.
        setting = ".".join(part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/"))
    if "value" in change:
        return f"set {setting} to {json.dumps(change['value'], ensure_ascii=True)}"
    if "at_least" in change:
        amount = change["at_least"]
        return f"set {setting} to at least ${amount}" if setting.endswith("_usd") \
            else f"set {setting} to at least {_num(amount)}"
    if isinstance(change.get("add"), list):
        names = ", ".join(json.dumps(str(p), ensure_ascii=True) for p in change["add"])
        return f"add {names} to {setting}"
    if change.get("needs_value"):
        return f"give {setting} a value"
    return f"change {setting}"


def _warnings(warnings, pen):
    pen.add(pen.paint("Warnings", "1"))
    for index, warning in enumerate(warnings, 1):
        _entry(warning, index, [], pen)


def _next_step(step, pen):
    if isinstance(step, str) and step:
        pen.add()
        pen.add("Next step: " + step, hang=2)
    elif isinstance(step, dict):
        commands = _list(step, "commands")
        if not commands and isinstance(step.get("command"), list):
            commands = [step["command"]]
        if commands:
            pen.add()
            pen.add("Next steps:" if len(commands) > 1 else "Next step:")
            for argv in commands:
                _command(argv, pen)


def _command(argv, pen):
    line = "  "
    for word in [str(word) for word in argv]:
        if line.strip() and len(line) + 1 + len(word) > pen.width:
            pen.lines.append(_shorten(line, pen.width))
            line = "      " + word
        else:
            line = line + (" " if line.strip() else "") + word
    pen.lines.append(_shorten(line, pen.width))
