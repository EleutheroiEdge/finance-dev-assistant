"""Every code the package raises or reports has a fixed hint, and `explain` reads them offline."""

import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

from finassist import error_hints
from finassist.cli import main
from finassist.guides import GUIDES

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "finassist"


def _modules() -> dict[str, ast.Module]:
    return {path.name: ast.parse(path.read_text(encoding="utf-8")) for path in sorted(SOURCE.glob("*.py"))}


def _name(call: ast.Call) -> str | None:
    return call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", None)


def _strings(node) -> list[str]:
    """Every literal code an expression can produce, or [] when any branch isn't a literal.

    A conditional counts only when both branches are literals: a half-literal one could
    emit a code nothing collected.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        body, orelse = _strings(node.body), _strings(node.orelse)
        return body + orelse if body and orelse else []
    return []


def _code_tables(tree) -> dict[str, list[str]]:
    """Module-level dictionaries whose values are all literal strings, such as find_tool's codes."""
    tables = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Dict) and node.value.values
                and all(_strings(value) for value in node.value.values)):
            tables[node.targets[0].id] = [code for value in node.value.values for code in _strings(value)]
    return tables


def _error_classes(modules) -> set[str]:
    """AssistantError and every class derived from it, at any depth."""
    bases = {node.name: {getattr(base, "id", getattr(base, "attr", "")) for base in node.bases}
             for tree in modules.values() for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
    found = {"AssistantError"}
    while grown := {name for name, parents in bases.items() if parents & found} - found:
        found |= grown
    return found


def _fixed_codes(modules, errors) -> dict[str, list[str]]:
    """Error classes whose constructor passes its own literal code to the base class."""
    fixed = {}
    for tree in modules.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in errors:
                for call in ast.walk(node):
                    if (isinstance(call, ast.Call) and _name(call) == "__init__" and call.args
                            and isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call)
                            and _name(call.func.value) == "super" and _strings(call.args[0])):
                        fixed[node.name] = _strings(call.args[0])
    return fixed


def _helpers(modules, errors) -> tuple[dict[tuple[str, str], int], set[int]]:
    """Functions that raise with their own parameter as the code: that parameter's index,
    and the raising calls inside them (their codes come from the callers)."""
    found, raises = {}, set()
    for module, tree in modules.items():
        for function in ast.walk(tree):
            if isinstance(function, ast.FunctionDef):
                params = [arg.arg for arg in function.args.args]
                for call in ast.walk(function):
                    if (isinstance(call, ast.Call) and _name(call) in errors and call.args
                            and isinstance(call.args[0], ast.Name) and call.args[0].id in params):
                        found[module, function.name] = params.index(call.args[0].id)
                        raises.add(id(call))
    return found, raises


# Sites that pass on a code chosen elsewhere. Each re-emits a caught exception's code,
# which is collected where it is raised, or builds a record from its own parameter. A new
# site whose code can't be read statically fails until it is listed here with its provenance.
PASSED_ON = {
    ("auditing.py", "{code}", "code"): "command_audit records the code of the error it is unwinding",
    ("cli.py", "{code}", "exc.code"): "main prints a caught AssistantError",
    ("dashboard.py", "{code}", "None"): "health reports no error for a valid configuration",
    ("detect.py", "{code}", "code"): "the detector's warn() builds records from its own parameter",
    ("dashboard.py", "{code}", "exc.code"): "the API returns a caught AssistantError",
    ("error_hints.py", "{code}", "code"): "explain repeats a code it found in the hint table",
    ("onboarding.py", "block", "exc.code"): "failed() reports a caught AssistantError",
    ("onboarding.py", "block_path", "row['code']"): "_classify rows carry caught AssistantError codes",
    ("onboarding.py", "{code}", "code"): "block() and warn() build records from their own parameter",
    ("onboarding.py", "{code}", "exc.code"): "_classify records a caught AssistantError",
}
EMITTERS = {"block", "warn", "block_path"}


def _looped_literals(function, name: str) -> list[str] | None:
    """Codes for a loop variable fed from a list of literal tuples, such as
    `for code, path in changes:` after `changes.append(("some_code", path))`. None when any
    appended or listed tuple has a non-literal in that position, or nothing feeds the loop."""
    found = None
    for loop in ast.walk(function):
        if not (isinstance(loop, ast.For) and isinstance(loop.target, ast.Tuple) and isinstance(loop.iter, ast.Name)):
            continue
        positions = [index for index, element in enumerate(loop.target.elts)
                     if isinstance(element, ast.Name) and element.id == name]
        if not positions:
            continue
        values = []
        for node in ast.walk(function):
            items = []
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "append"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == loop.iter.id and node.args):
                items.append(node.args[0])
            elif (isinstance(node, ast.Assign) and isinstance(node.value, ast.List)
                  and any(isinstance(target, ast.Name) and target.id == loop.iter.id for target in node.targets)):
                items.extend(node.value.elts)
            for item in items:
                fits = isinstance(item, ast.Tuple) and len(item.elts) > positions[0]
                literal = _strings(item.elts[positions[0]]) if fits else []
                if not literal:
                    return None
                values.extend(literal)
        found = (found or []) + values
    return found or None


def collect(modules=None) -> tuple[set[str], set[tuple[str, str, str]]]:
    """Codes raised or reported by the package, and every site whose code can't be accounted for.

    It fails closed: an emitter, helper, record or error constructor whose code isn't a
    literal, a literal code table, a loop over literal tuples or a listed PASSED_ON site is
    reported as unaccounted rather than silently skipped.
    """
    modules = _modules() if modules is None else modules
    errors = _error_classes(modules)
    helpers, helper_raises = _helpers(modules, errors)
    fixed = _fixed_codes(modules, errors)
    codes, unaccounted = set(), set()

    def account(module, kind, value, function):
        if _strings(value):
            codes.update(_strings(value))
            return
        if isinstance(value, ast.Name) and function is not None:
            looped = _looped_literals(function, value.id)
            if looped:
                codes.update(looped)
                return
        if (module, kind, ast.unparse(value)) not in PASSED_ON:
            unaccounted.add((module, kind, ast.unparse(value)))

    for module, tree in modules.items():
        local = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
        tables = _code_tables(tree)
        enclosing = {}
        for function in ast.walk(tree):
            if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(function):
                    enclosing[id(child)] = function  # ast.walk visits outer functions first
        for node in ast.walk(tree):
            function = enclosing.get(id(node))
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if isinstance(key, ast.Constant) and key.value == "code":
                        account(module, "{code}", value, function)
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name, first = _name(node), node.args[0]
            if name in fixed:
                codes.update(fixed[name])
            elif name in errors:
                if (isinstance(first, ast.Subscript) and isinstance(first.value, ast.Name)
                        and first.value.id in tables):
                    codes.update(tables[first.value.id])
                elif id(node) not in helper_raises:
                    account(module, name, first, function)
            elif (name in EMITTERS and isinstance(node.func, ast.Attribute)
                  and isinstance(node.func.value, ast.Name) and node.func.value.id == "self"):
                account(module, name, first, function)
            else:
                owners = [key for key in helpers if key[1] == name]
                if name in local:
                    owners = [key for key in owners if key[0] == module]
                if len(owners) == 1 and len(node.args) > helpers[owners[0]]:
                    account(module, "helper " + name, node.args[helpers[owners[0]]], function)
    return codes, unaccounted


def _literal_args(tree, function: str, index: int) -> set[str]:
    return {value for call in ast.walk(tree) if isinstance(call, ast.Call) and _name(call) == function
            and len(call.args) > index for value in _strings(call.args[index])}


def test_error_classes_include_every_subclass():
    assert {"AssistantError", "ConfigCompatibilityError", "OperationOutcomeUnknown"} <= _error_classes(_modules())


def test_every_raised_or_reported_code_has_a_hint():
    codes, _unreadable = collect()
    assert len(codes) > 450
    assert sorted(codes - set(error_hints.hints())) == []


def test_a_code_that_is_no_longer_used_stays_explained_as_retired():
    # Codes are an interface: a script may still key on an old one. Like rustc's
    # error index, an unused code keeps its entry, marked retired, and is never reused.
    codes, _unreadable = collect()
    table = error_hints.hints()
    assert sorted(code for code in set(table) - codes if "retired" not in table[code]) == []
    assert sorted(code for code in codes if "retired" in table.get(code, {})) == []


def test_every_code_is_a_literal_that_can_be_found_in_the_source():
    _codes, unaccounted = collect()
    assert unaccounted == set()


def test_every_passed_on_site_still_exists():
    modules = _modules()
    for module, _kind, expression in PASSED_ON:
        assert any(ast.unparse(node) == expression for node in ast.walk(modules[module])), (module, expression)


def _mutated(module: str, old: str, new: str) -> dict:
    modules = _modules()
    text = (SOURCE / module).read_text(encoding="utf-8")
    assert text.count(old) == 1, (module, old)
    modules[module] = ast.parse(text.replace(old, new))
    return modules


def test_a_new_code_in_a_tuple_list_is_collected():
    # The reviewer's case: a new code routed through the preflight's list of rule changes.
    codes, unaccounted = collect(_mutated("onboarding.py", '("gate_ignore_change_requires_review", name)',
                                          '("synthetic_unhinted_code", name)'))
    assert "synthetic_unhinted_code" in codes and unaccounted == set()
    assert "synthetic_unhinted_code" not in error_hints.hints()


@pytest.mark.parametrize("module, old, new", [
    ("onboarding.py", 'self.block("empty_review_scope")', "self.block(chosen)"),
    ("onboarding.py", '("gate_ignore_change_requires_review", name)', "(chosen, name)"),
    ("health.py", '{"code": "config_file_not_loaded",', '{"code": chosen,'),
    ("review.py", 'raise AssistantError("empty_model_context")', "raise AssistantError(chosen)"),
    # The reviewer's case: one literal branch must not account for the other.
    ("onboarding.py", 'self.block("empty_review_scope")',
     'self.block("empty_review_scope" if selected else "synthetic_" + "unhinted_code")'),
])
def test_an_unaccounted_code_site_fails_closed(module, old, new):
    _codes, unaccounted = collect(_mutated(module, old, new))
    assert any(site[0] == module for site in unaccounted), unaccounted


def test_code_tables_cover_every_caller():
    from finassist.platform_support import _MISSING
    from finassist.triage_contract import _INVALID
    from finassist.triage_metrics import _DUPLICATE, _IDENTITY

    modules = _modules()
    tools = set().union(*(_literal_args(tree, "find_tool", 0) for tree in modules.values()))
    assert tools and tools <= set(_MISSING)
    assert _literal_args(modules["triage_contract.py"], "_validate", 1) == set(_INVALID)
    assert _literal_args(modules["triage_metrics.py"], "_index", 1) == set(_IDENTITY) == set(_DUPLICATE)
    assert {"docker_executable_missing", "triage_gold_duplicate"} <= set(error_hints.hints())


def test_hint_entries_are_short_plain_and_point_at_real_docs():
    table = error_hints.hints()
    for code, entry in table.items():
        for field in ("summary", "fix"):
            text = entry[field]
            assert text == text.strip() and text.endswith((".", ")")), (code, field)
            assert not re.search(r"(?:^|[\s(`])(?:/home/|/Users/|/mnt/|~/|[A-Za-z]:\\)", text), (code, field)
            assert "  " not in text, (code, field)
        assert all(other in table for other in entry.get("see", [])), code
        if "docs" in entry:
            assert (ROOT / "docs" / entry["docs"]).is_file(), code


@pytest.mark.parametrize("entry", [
    {"summary": "Caf\xe9 is not ASCII.", "fix": "Fix it."},
    {"summary": "x" * 161, "fix": "Fix it."},
    {"summary": "Fine.", "fix": "Fix it.", "extra": "field"},
    {"summary": "Fine."},
    {"summary": "Fine.", "fix": "Fix it.", "see": ["sample_code"]},
    {"summary": "Fine.", "fix": "Fix it.", "docs": "../SECURITY.md"},
    {"summary": "Fine.", "fix": "Fix\u200bit."},
    {"summary": "Fine.", "fix": "Fix\tit."},
    {"summary": "Fine.", "fix": "Fix it.", "see": ["a", "b", "c", "d"]},
])
def test_a_malformed_entry_is_rejected(entry):
    assert not error_hints._valid("sample_code", entry)


@pytest.mark.parametrize("code", ["Sample_code", "sample-code", "1sample", "", "s" * 81, "sample\u212acode"])
def test_a_malformed_code_is_rejected(code):
    assert not error_hints._valid(code, {"summary": "Fine.", "fix": "Fix it."})


def test_a_code_repeated_across_areas_is_rejected(monkeypatch):
    class Resource:
        def joinpath(self, _path):
            return self

        def read_text(self, encoding):
            assert encoding == "utf-8"
            return '{"sample_code": {"summary": "Fine.", "fix": "Fix it."}}'

    error_hints.hints.cache_clear()
    monkeypatch.setattr(error_hints, "files", lambda _package: Resource())
    try:
        with pytest.raises(ValueError, match="invalid or repeated"):
            error_hints.hints()
    finally:
        error_hints.hints.cache_clear()


def test_a_repeated_key_inside_one_table_is_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        json.loads('{"a": 1, "a": 2}', object_pairs_hook=error_hints._unique)


def _error(capsys) -> dict:
    return json.loads(capsys.readouterr().err)


def test_an_error_record_carries_the_hint_for_its_code(capsys):
    assert main(["explain"]) == 2
    record = _error(capsys)
    assert record["code"] == "explain_code_or_list_required"
    assert record["hint"] == error_hints.hints()["explain_code_or_list_required"]["fix"]


def test_a_handled_input_error_also_carries_a_hint(capsys, tmp_path):
    damaged = tmp_path / "finassist.json"
    damaged.write_bytes(b"\xff\xfe not utf-8")
    assert main(["--config", str(damaged), "doctor"]) == 2
    record = _error(capsys)
    assert record["hint"] == error_hints.hints()[record["code"]]["fix"]


def test_a_damaged_hint_table_never_hides_the_original_error(monkeypatch, capsys):
    def damaged():
        raise ValueError("damaged")

    monkeypatch.setattr(error_hints, "hints", damaged)
    assert main(["explain"]) == 2
    assert _error(capsys) == {"status": "error", "code": "explain_code_or_list_required"}
    assert main(["explain", "network_not_approved"]) == 2
    assert _error(capsys) == {"status": "error", "code": "error_hints_unavailable"}


def test_a_detail_cannot_replace_the_hint():
    from finassist.errors import AssistantError

    assert "hint" not in AssistantError("sample_code", {"hint": "forged", "limit": 1}).public_details


def test_explain_prints_the_entry_as_json(capsys):
    assert main(["explain", "file_limit_exceeded"]) == 0
    result = json.loads(capsys.readouterr().out)
    entry = error_hints.hints()["file_limit_exceeded"]
    assert result["code"] == "file_limit_exceeded"
    assert (result["summary"], result["fix"], result["area"]) == (entry["summary"], entry["fix"], entry["area"])


def test_explain_text_names_the_offline_guide_when_one_exists(capsys):
    table = error_hints.hints()
    code = next(code for code, entry in sorted(table.items())
                if "docs/" + entry.get("docs", "") in {source for _t, source, _r in GUIDES.values()})
    assert main(["explain", code, "--format", "text"]) == 0
    text = capsys.readouterr().out
    assert text.startswith(code + "  [") and "How to fix: " + table[code]["fix"] in text
    topic = re.search(r"offline: finassist guide ([a-z-]+)\)", text).group(1)
    assert topic in GUIDES
    assert main(["guide", topic]) == 0


@pytest.mark.parametrize("argument, code", [
    ("FILE_LIMIT_EXCEEDED", "file_limit_exceeded"), ("file-limit-exceeded", "file_limit_exceeded"),
    ("  file_limit_exceeded\n", "file_limit_exceeded"), ('"file_limit_exceeded"', "file_limit_exceeded"),
    ('{"status":"error","code":"file_limit_exceeded","limit":48000,"bytes":51200}', "file_limit_exceeded"),
    ("\uff46\uff49\uff4c\uff45_limit_exceeded", "file_limit_exceeded"),  # full-width letters, as many input methods type them
    ("networ\u212a_not_approved", "network_not_approved"),  # the Kelvin sign folds to "k"
])
def test_explain_accepts_the_forms_a_user_pastes(argument, code, capsys):
    assert main(["explain", argument]) == 0
    assert json.loads(capsys.readouterr().out)["code"] == code


def test_an_unknown_code_suggests_close_ones(capsys):
    assert main(["explain", "file_limit_exceded"]) == 2
    record = _error(capsys)
    assert record["code"] == "unknown_error_code" and "file_limit_exceeded" in record["suggestions"]


@pytest.mark.parametrize("argument", [
    "file_limit_\u0435xceeded",  # Cyrillic look-alike: not folded, so not a code
    "file_limit_\u200bexceeded",  # zero-width space
    "\u202efile_limit_exceeded",  # right-to-left override
    "file_limit_exceeded\U0001f600",  # outside the Basic Multilingual Plane
    "fichier_trop_grand_\xe9t\xe9",  # accented Latin
    "\u30d5\u30a1\u30a4\u30eb",  # Japanese
    "{not json", '{"code": 7}', "[1]", "%s%n", "\x00",
])
def test_explain_refuses_look_alikes_and_never_echoes_the_input(argument, capsys):
    assert main(["explain", argument]) == 2
    captured = capsys.readouterr()
    record = json.loads(captured.err)
    assert record["code"] == "unknown_error_code"
    assert argument.strip() not in captured.err + captured.out or not argument.strip()
    assert captured.err.isascii()


def test_list_covers_every_code_and_filters_by_area(capsys):
    assert main(["explain", "--list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["count"] == len(error_hints.hints()) == len(listed["codes"])
    assert main(["explain", "--list", "--area", "gates", "--format", "text"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines and all("  [gates]  " in line for line in lines)


@pytest.mark.parametrize("argv, code", [
    (["explain", "file_limit_exceeded", "--list"], "explain_code_or_list_required"),
    (["explain", ""], "explain_code_or_list_required"),
    (["explain", "file_limit_exceeded", "--area", "gates"], "explain_area_requires_list"),
])
def test_explain_option_conflicts_are_refused(argv, code, capsys):
    assert main(argv) == 2
    assert _error(capsys)["code"] == code


@pytest.mark.parametrize("environment", [
    {"LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0"},
    {"PYTHONIOENCODING": "ascii"},
    {"PYTHONIOENCODING": "cp1252", "LANG": "fr_FR.ISO-8859-1"},
    {"LC_ALL": "tr_TR.UTF-8", "LANG": "tr_TR.UTF-8"},
])
def test_explain_output_is_ascii_under_any_locale(environment):
    env = {key: value for key, value in os.environ.items() if key not in {"PYTHONUTF8", "PYTHONIOENCODING"}}
    env.update({"PYTHONPATH": str(ROOT / "src"), **environment})
    for argv, expected in ((["explain", "network_not_approved", "--format", "text"], 0),
                           (["explain", "--list", "--format", "text"], 0), (["explain", "zz_nothing"], 2)):
        completed = subprocess.run([sys.executable, "-m", "finassist", *argv], env=env, capture_output=True,
                                   timeout=60, check=False)
        assert completed.returncode == expected, completed.stderr
        assert completed.stdout.isascii() and completed.stderr.isascii()
        assert completed.stdout or completed.stderr


def _table_row(code: str, entry: dict) -> str:
    return f"| `{code}` | {entry['summary']} | {entry['fix']} |"


def test_the_troubleshooting_table_is_the_same_text_explain_prints():
    # To refresh a row, copy the code's summary and fix from `finassist explain CODE`.
    text = (ROOT / "docs" / "troubleshooting.md").read_text(encoding="utf-8")
    table = text.split("<!-- hint-table:start -->\n", 1)[1].split("<!-- hint-table:end -->", 1)[0]
    rows = [line for line in table.splitlines() if line.startswith("| `")]
    hints = error_hints.hints()
    assert len(rows) >= 30 and len({row.split("`")[1] for row in rows}) == len(rows)
    for row in rows:
        code = row.split("`")[1]
        assert code in hints and row == _table_row(code, hints[code]), code
    assert GUIDES["troubleshooting"][1] == "docs/troubleshooting.md"


def test_hint_text_never_breaks_a_table_row():
    assert [code for code, entry in error_hints.hints().items() if "|" in entry["summary"] + entry["fix"]] == []


PASTED_ARGUMENT = "--synthetic-private-value"


@pytest.mark.parametrize("argv", [
    ["explain", PASTED_ARGUMENT],
    ["explain", "-x" + PASTED_ARGUMENT],
    ["explain", "file_limit_exceeded", PASTED_ARGUMENT],
    ["explain", "--format", PASTED_ARGUMENT, "file_limit_exceeded"],
    ["explain", "--area", PASTED_ARGUMENT, "--list"],
    ["--config", "unused.json", "explain", PASTED_ARGUMENT],
    ["--conf", "unused.json", "explain", PASTED_ARGUMENT],
    ["--config=unused.json", "explain", PASTED_ARGUMENT],
    ["--typo", "explain", PASTED_ARGUMENT],                     # an unknown root option first
    ["--config=unused.json", "--typo", "explain", PASTED_ARGUMENT],
    ["--conf=unused.json", "--typo", "explain", PASTED_ARGUMENT],
    ["-q", "explain", PASTED_ARGUMENT],
])
def test_an_unreadable_explain_invocation_is_refused_without_echoing_it(argv, capsys):
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.err)["code"] == "explain_arguments_invalid"
    assert "synthetic-private-value" not in captured.err + captured.out


def test_global_options_still_reach_explain(capsys):
    assert main(["--config", "unused.json", "explain", "file_limit_exceeded"]) == 0
    assert json.loads(capsys.readouterr().out)["code"] == "file_limit_exceeded"
    assert main(["explain", "--", "file_limit_exceeded"]) == 0
    assert json.loads(capsys.readouterr().out)["code"] == "file_limit_exceeded"


def test_explain_help_still_prints(capsys):
    with pytest.raises(SystemExit) as raised:
        main(["explain", "--help"])
    assert raised.value.code == 0 and "finassist explain" in capsys.readouterr().out


def test_other_commands_keep_argparse_errors(capsys):
    with pytest.raises(SystemExit):
        main(["demo", "--no-such-option"])
    assert "--no-such-option" in capsys.readouterr().err  # Ordinary option names, not pasted text.


class _Resource:
    def __init__(self, text):
        self.text = text

    def joinpath(self, _path):
        return self

    def read_text(self, encoding):
        assert encoding == "utf-8"
        return self.text


def test_a_deeply_nested_hint_table_is_damage_not_a_crash(monkeypatch, capsys):
    error_hints.hints.cache_clear()
    monkeypatch.setattr(error_hints, "files", lambda _package: _Resource("[" * 10_000 + "]" * 10_000))
    try:
        assert error_hints.error_fields("file_limit_exceeded") == {}
        assert main(["explain", "file_limit_exceeded"]) == 2
        assert json.loads(capsys.readouterr().err) == {"status": "error", "code": "error_hints_unavailable"}
        assert main(["explain"]) == 2
        assert json.loads(capsys.readouterr().err) == {"status": "error", "code": "explain_code_or_list_required"}
    finally:
        error_hints.hints.cache_clear()


def test_a_retired_entry_loads_lists_and_explains(monkeypatch, capsys):
    table = {"sample_retired_code": {"summary": "An old refusal.", "fix": "Nothing to do.", "retired": "0.8.0"}}
    texts = {area: "{}" for area in error_hints.AREAS}
    texts["setup"] = json.dumps(table)

    class Areas:
        def joinpath(self, path):
            return _Resource(texts[path.removeprefix("resources/hints-").removesuffix(".json")])

    error_hints.hints.cache_clear()
    monkeypatch.setattr(error_hints, "files", lambda _package: Areas())
    try:
        assert main(["explain", "sample_retired_code", "--format", "text"]) == 0
        assert "Retired in 0.8.0" in capsys.readouterr().out
        assert main(["explain", "sample_retired_code"]) == 0
        assert json.loads(capsys.readouterr().out)["retired"] == "0.8.0"
        assert main(["explain", "--list"]) == 0
        assert json.loads(capsys.readouterr().out)["codes"][0]["retired"] == "0.8.0"
    finally:
        error_hints.hints.cache_clear()


@pytest.mark.parametrize("retired", ["0.8", "v0.8.0", "0.8.0-rc1", 8, "", "01.2.3", None, False, ["0.8.0"]])
def test_a_malformed_retired_marker_is_rejected(retired):
    assert not error_hints._valid("sample_code", {"summary": "Fine.", "fix": "Fix it.", "retired": retired})


def test_a_conditional_code_needs_both_branches_literal():
    assert _strings(ast.parse('"a_code" if flag else "b_code"', mode="eval").body) == ["a_code", "b_code"]
    assert _strings(ast.parse('"a_code" if flag else prefix + "x"', mode="eval").body) == []
    assert _strings(ast.parse('prefix if flag else "b_code"', mode="eval").body) == []


def test_an_unknown_option_before_another_command_keeps_argparse_errors(capsys):
    with pytest.raises(SystemExit):
        main(["--typo", "demo"])
    assert "--typo" in capsys.readouterr().err  # No explain argument here, so argparse may name it.
