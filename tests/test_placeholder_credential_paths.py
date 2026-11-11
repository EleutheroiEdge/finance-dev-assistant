"""placeholder_credential_paths: where the operator says so, a credential-named value is a placeholder.

Synthetic values only. Credential words are written as markers and spelled out at run time, as in
credential_cases.py, so this file holds no credential-shaped text of its own.
"""
from dataclasses import replace
import json

import pytest

from conftest import command
from credential_cases import spell
from finassist.cli import main
from finassist.config import Config, config_hash, load_config
from finassist.errors import AssistantError
from finassist.patching import patch_paths
from finassist.security import check_context_document, check_output_document, check_text, holds_placeholders
from test_forbidden_token_gate import candidate
from test_model_gate import change_policy, run
from test_providers_review import envelope

pytest_plugins = ("test_model_gate", "test_model_policy")

TESTS = ("tests/",)
FIXTURE = spell('@pw@ = "@V@"\n')
ACCOUNT = "account_" + "number"
TOKEN = "ghp_" + "a" * 36


def refuses(text, path, placeholders=TESTS):
    with pytest.raises(AssistantError, match="^sensitive_content$") as refusal:
        check_text(spell(text), source_path=path, placeholders=placeholders)
    return refusal.value


# --- Which files ------------------------------------------------------------

@pytest.mark.parametrize("entries,path,expected", [
    (("tests/",), "tests/test_login.py", True),
    (("tests/",), "tests/unit/fixtures/users.yml", True),
    (("tests/",), "src/tests/test_login.py", False),
    (("tests/",), "tests", False),
    (("tests",), "tests/test_login.py", False),                 # no slash: an exact path
    (("src/app/login.test.ts",), "src/app/login.test.ts", True),
    (("src/app/login.test.ts",), "src/app/login.test.tsx", False),
    (("*.test.ts",), "src/app/login.test.ts", True),            # a star also stands for slashes
    (("*.test.ts",), "src/app/login.ts", False),
    (("*/__tests__/*",), "src/app/__tests__/login.ts", True),
    (("*/__tests__/*",), "__tests__/login.ts", False),          # nothing stands before the first slash
    (("e2e/*.spec.*",), "e2e/flows/login.spec.ts", True),
    (("*.TEST.ts",), "src/app/login.test.ts", False),           # by case, as paths are everywhere else
    ((), "tests/test_login.py", False),
    (("tests/", "*.spec.ts"), "web/login.spec.ts", True),
])
def test_an_entry_is_a_prefix_an_exact_path_or_a_pattern(entries, path, expected):
    assert holds_placeholders(path, entries) is expected
    assert replace(Config(), placeholder_credential_paths=entries).validate().placeholder(path) is expected
    assert holds_placeholders(None, entries) is False


# --- What changes under them, and what does not -----------------------------

@pytest.mark.parametrize("path,text", [
    ("tests/test_login.py", '@pw@ = "@V@"\n'),
    ("tests/test_login.py", 'client.login(@pw@="@V@")\n'),
    ("tests/test_login.py", '# @pw@: @W@\n'),
    ("tests/test_login.py", 'DSN = "host=db @pw@=@W@"\n'),
    ("tests/fixtures/users.yml", "  @pw@: @W@\n"),
    ("tests/fixtures/settings.json", '{"@ak@": "@V@"}\n'),
    ("tests/login.test.ts", 'const @pw@ = "@V@";\n'),
    ("tests/broken.py", 'def f(:\n@pw@ = "@V@"\n'),             # Python that does not parse is text
])
def test_a_credential_named_value_is_not_refused_under_a_listed_path(path, text):
    refuses(text, path, placeholders=())
    refuses(text, "src/" + path)
    check_text(spell(text), source_path=path, placeholders=TESTS)


@pytest.mark.parametrize("path,text,rule", [
    ("tests/test_login.py", "token = '" + TOKEN + "'\n", "github_token"),
    ("tests/fixtures/users.yml", "key: |\n  -----BEGIN " + "PRIVATE KEY-----\n", "private_key_block"),
    ("tests/test_login.py", ACCOUNT + " = 12345678\n", "account_label"),
    ("tests/fixtures/users.yml", ACCOUNT + ": 12345678\n", "account_label"),
    ("tests/test_login.py", "# " + ACCOUNT + ": 12345678\n", "account_label"),
    ("tests/test_login.py", "aws = '" + "AKIA" + "ABCDEFGHIJKLMNOP" + "'\n", "aws_access_key_id"),
])
def test_known_formats_and_account_numbers_are_refused_there_as_everywhere(path, text, rule):
    assert refuses(text, path).local_details["rule"] == rule


def test_the_projects_own_patterns_are_refused_there_too():
    with pytest.raises(AssistantError, match="^project_content_blocked$"):
        check_text(FIXTURE + "codename bluebird\n", source_path="tests/test_login.py", placeholders=TESTS,
                   extra_patterns=("bluebird",))


def test_text_read_without_a_path_is_never_a_placeholder():
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text(FIXTURE, placeholders=("*.py", "tests/"))


# --- The setting ------------------------------------------------------------

def test_the_default_is_empty_and_leaves_the_configuration_hash_as_it_was():
    assert Config().placeholder_credential_paths == ()
    assert config_hash(load_config(content=b'{"placeholder_credential_paths": []}')) == config_hash(Config())
    assert config_hash(replace(Config(), placeholder_credential_paths=TESTS).validate()) != config_hash(Config())
    loaded = load_config(content=b'{"placeholder_credential_paths": ["tests/", "*.spec.ts"]}')
    assert loaded.placeholder_credential_paths == ("tests/", "*.spec.ts")  # a tuple, as every list setting is
    assert load_config(content=b"{}") == Config()


@pytest.mark.parametrize("entries", [
    ["tests/", "tests/"],                # twice
    ["*"], ["**"], ["*/*"], ["*.p"],     # a pattern that could match every file, or nearly
    ["*.py"], ["**/*.py"], ["*/*.yaml"], ["*.*"], ["a*.ts"],  # or every file of a language
    ["tests//"], ["*/fixtures/"], ["*//fixtures/*"],      # an entry that fits no path
    ["*/.git/*"], ["*/../tests/*"], ["/*tests/"],         # a pattern gets the checks an exact entry gets
    ["tests/?.py"], ["tests/[ab].py"],   # only a star is a pattern
    ["tests/* .py"], ["tests/" + chr(0x202E) + "*"],  # characters a pattern may not hold
    ["../tests/"], ["/tests/"], [""], [".git/"],
    ["t%d/" % number for number in range(65)],
])
def test_an_entry_that_is_not_a_safe_prefix_path_or_pattern_is_refused(entries):
    with pytest.raises(AssistantError, match="^invalid_placeholder_credential_paths$"):
        load_config(content=json.dumps({"placeholder_credential_paths": entries}).encode())


@pytest.mark.parametrize("entry", ["tests/", "test/", "e2e/", "*/tests/*", "*/test/*", "*/__tests__/*", "*/fixtures/*",
                                   "*.test.*", "*.spec.*", "*_test.go", "*/test_*.py", "*/conftest.py", "*test*"])
def test_the_patterns_a_test_tree_needs_are_accepted(entry):
    assert load_config(content=json.dumps({"placeholder_credential_paths": [entry]}).encode()).placeholder_credential_paths == (entry,)


def test_a_private_path_is_refused_as_a_pattern_as_it_is_as_an_exact_entry():
    for entry in (".git/config", "*/.git/config"):
        with pytest.raises(AssistantError, match="^invalid_placeholder_credential_paths$"):
            load_config(content=json.dumps({"placeholder_credential_paths": [entry]}).encode())


def test_the_name_of_a_related_definition_is_never_placeholder_text():
    from finassist.related import verify_related

    def block(symbol, line):
        return {"rule_version": 1, "budget_bytes": 24_000, "skipped": [], "skipped_count": 0, "snippets": [{
            "path": "tests/helper.py", "symbol": symbol, "relation": "caller",
            "reference": {"path": "src/app.py", "symbol": "main"}, "lines": [[1, line]], "sha256": "0" * 64}]}

    config = replace(Config(), related_context="related", placeholder_credential_paths=TESTS).validate()
    strict = replace(Config(), related_context="related").validate()
    private = lambda path: False  # noqa: E731
    verify_related(block("helper", spell('@pw@ = "@V@"')), ["src/app.py"], config, private)  # a line of the file
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        verify_related(block("helper", spell('@pw@ = "@V@"')), ["src/app.py"], strict, private)
    for settings in (config, strict):
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            verify_related(block(spell('@pw@ = "@V@"'), "def helper():"), ["src/app.py"], settings, private)


def test_the_setting_is_a_list_of_strings():
    for value in ("tests/", [1], {"tests/": True}):
        with pytest.raises(AssistantError):
            load_config(content=json.dumps({"placeholder_credential_paths": value}).encode())


# --- A packet, and what a model may write back ------------------------------

def test_a_packet_with_a_fixture_is_accepted_only_with_the_setting():
    packet = {"head": "0" * 40, "files": [{"path": "tests/test_login.py", "before": None, "after": FIXTURE}]}
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_context_document(packet)
    check_context_document(packet, placeholders=TESTS)


def test_a_model_may_repeat_a_placeholder_exactly_and_nothing_else_under_its_label():
    files = [{"path": "tests/test_login.py", "before": None, "after": FIXTURE}]
    quote = {"summary": "x", "findings": [{"claim": spell("The fixture sets `@pw@ = \"@V@\"` once.")}]}
    check_output_document(quote, files, placeholders=TESTS)
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(quote, files)  # without the setting the source itself is refused
    other = {"summary": "x", "findings": [{"claim": spell('@pw@ = "@V@x"')}]}
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(other, files, placeholders=TESTS)
    elsewhere = [{"path": "src/login.py", "before": None, "after": "x = 1\n"}]
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(quote, elsewhere, placeholders=TESTS)


# --- Both routes ------------------------------------------------------------

def one_file_patch(path, body, lines=1):
    return "diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n@@ -1,%d +1,%d @@\n%s" % (path, path, path, path, lines, lines, spell(body))


def test_a_proposed_patch_cannot_bring_a_new_labelled_value_into_a_listed_file():
    """Codex P107-1: the patch's own post-image is screened as source and lends no quote there."""
    config = replace(Config(), placeholder_credential_paths=TESTS).validate()
    script, settings = "tests/test_login.py", "tests/fixtures/users.yml"
    supplied = [{"path": script, "before": "x = 1\n", "after": "x = 2\n"}]
    for added in ('@pw@ = "@V@"', "@pw@ = settings.TEST_DATABASE_@PW@"):  # a literal, and a reference too
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            patch_paths(one_file_patch(script, "-x = 2\n+" + added + "\n"), config, source_files=supplied)
    with pytest.raises(AssistantError, match="^sensitive_content$"):  # an unquoted value in a settings file
        patch_paths(one_file_patch(settings, "-retries: 2\n+@pw@: @W@\n"), config,
                    source_files=[{"path": settings, "before": None, "after": "retries: 2\n"}])
    # Outside the list nothing changes: there the post-image has passed the label rules, so a reference in it may stand.
    elsewhere = [{"path": "src/settings.py", "before": None, "after": "x = 2\n"}]
    assert patch_paths(one_file_patch("src/settings.py", "-x = 2\n+@pw@ = settings.DATABASE_@PW@\n"), config,
                       source_files=elsewhere) == ["src/settings.py"]
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        patch_paths(one_file_patch("src/settings.py", '-x = 2\n+@pw@ = "@V@"\n'), config, source_files=elsewhere)


def test_a_proposed_patch_may_keep_or_move_a_placeholder_that_the_supplied_file_holds():
    config = replace(Config(), placeholder_credential_paths=TESTS).validate()
    path = "tests/test_login.py"
    supplied = [{"path": path, "before": None, "after": spell('@pw@ = "@V@"\nx = 2\n')}]
    kept = one_file_patch(path, ' @pw@ = "@V@"\n-x = 2\n+x = 3\n', lines=2)
    moved = one_file_patch(path, '-@pw@ = "@V@"\n x = 2\n+@pw@ = "@V@"\n', lines=2)
    changed = one_file_patch(path, '-@pw@ = "@V@"\n+@pw@ = "@V@x"\n x = 2\n', lines=2)
    assert patch_paths(kept, config, source_files=supplied) == [path]
    assert patch_paths(moved, config, source_files=supplied) == [path]
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        patch_paths(changed, config, source_files=supplied)
    with pytest.raises(AssistantError, match="^sensitive_content$"):  # and without the setting the file itself is refused
        patch_paths(kept, Config(), source_files=supplied)


def test_plan_refuses_a_fixture_and_reviews_it_with_the_setting(repository, tmp_path, capsys):
    repo, base, _head = repository
    (repo / "tests").mkdir(exist_ok=True)
    (repo / "tests/test_login.py").write_text(FIXTURE, encoding="utf-8", newline="\n")
    command(repo, "add", "tests/test_login.py")
    command(repo, "commit", "-q", "-m", "Synthetic fixture")
    head = command(repo, "rev-parse", "HEAD")
    for entries, status in (([], "blocked"), (["tests/"], "ready")):
        config = tmp_path / ("config-%d.json" % len(entries))
        config.write_text(json.dumps({"schema_version": 1, "placeholder_credential_paths": entries}), encoding="utf-8")
        main(["--config", str(config), "doctor", "--repo", str(repo), "--base", base, "--head", head])
        report = json.loads(capsys.readouterr().out)
        row = next(row for row in report["paths"] if row["path"] == "tests/test_login.py")
        if entries:
            assert row == {"path": "tests/test_login.py", "status": "included", "credential_labels": "not_screened"}
            assert {"code": "credential_labels_not_screened", "count": 1} in [
                {key: warning[key] for key in ("code", "count")} for warning in report["warnings"]]
            assert not [item for item in report["blockers"] if item["code"] == "sensitive_content"]
        else:
            assert row["status"] == "refused" and row["rule"] == "credential_label" and row["lines"] == [1]
            assert not [warning for warning in report["warnings"] if warning["code"] == "credential_labels_not_screened"]
        assert status in ("blocked", "ready")


def test_a_gate_refuses_a_fixture_when_its_policy_does_not_list_the_path(gate_case):
    change_policy(gate_case, allow_paths=["src/", "tests/"])
    (gate_case["repo"] / "tests").mkdir(exist_ok=True)
    candidate(gate_case, FIXTURE, name="tests/test_login.py")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls


def test_a_gate_reviews_a_fixture_when_its_policy_lists_the_path(gate_case):
    change_policy(gate_case, allow_paths=["src/", "tests/"], placeholder_credential_paths=["tests/"])
    (gate_case["repo"] / "tests").mkdir(exist_ok=True)
    candidate(gate_case, FIXTURE, name="tests/test_login.py")
    received = []

    def handler(packet):
        received.extend(file["after"] for file in packet["files"])
        return envelope(json.dumps({"head": packet["head"], "summary": spell('`@pw@ = "@V@"` is a fixture value.'),
                                    "reviewed_paths": [file["path"] for file in packet["files"]], "findings": []}))

    report, calls = run(gate_case, handler)
    assert report["verdict"] == "PASS" and len(calls) == 1
    assert any(FIXTURE in text for text in received)


def test_a_gate_with_the_setting_still_stops_a_known_format_in_a_fixture(gate_case):
    change_policy(gate_case, allow_paths=["src/", "tests/"], placeholder_credential_paths=["tests/"])
    (gate_case["repo"] / "tests").mkdir(exist_ok=True)
    candidate(gate_case, "token = '" + TOKEN + "'\n", name="tests/test_login.py")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
