"""The credential screen tells a reference from a value (#96, release gate B5).

Synthetic values only. Credential words are written as markers and spelled out at run time, as
in credential_cases.py, so this file holds no credential-shaped text of its own.
"""
import json

import pytest

from credential_cases import KNOWN_FALSE_REFUSALS, KNOWN_MISSES, MUST_PASS, MUST_REFUSE, spell
from finassist.errors import AssistantError
from finassist.security import check_context_document, check_output_document, check_text
from test_forbidden_token_gate import candidate
from test_model_gate import run
from test_providers_review import envelope

pytest_plugins = ("test_model_gate", "test_model_policy")

ACCOUNT = "account_" + "number"
GATE_LANGUAGES = {"ts": "TypeScript", "js": "TypeScript", "mjs": "TypeScript", "cjs": "TypeScript", "go": "Go",
                  "sql": "SQL", "yml": "YAML", "yaml": "YAML"}


# A line of the set that begins with space is one line of a block, and is read inside one.
SCRIPT_BLOCK = "export const settings = {\n%s\n};\n"
BLOCKS = {"ts": SCRIPT_BLOCK, "js": SCRIPT_BLOCK, "mjs": SCRIPT_BLOCK, "cjs": SCRIPT_BLOCK,
          "go": "func load() Config {\n\treturn Config{\n%s\n\t}\n}\n", "sql": "UPDATE users SET\n%s\n",
          "java": "class Settings {\n%s\n}\n", "kt": "class Settings {\n%s\n}\n", "kts": "publishing {\n%s\n}\n"}


def path_for(suffix):
    return "src/sample." + suffix


def in_file(suffix, text):
    block = BLOCKS.get(suffix)
    return block % text if block and text[:1] in (" ", "\t") else text


def passes(suffix, text):
    check_text(spell(in_file(suffix, text)), source_path=path_for(suffix))


def refuses(suffix, text, *, bare=False):
    with pytest.raises(AssistantError, match="^sensitive_content$") as refusal:
        check_text(spell(text if bare else in_file(suffix, text)), source_path=path_for(suffix))
    return refusal.value


def case_id(case):
    return "%s:%s" % (case[0], case[1][:48].replace("\n", " "))


# --- The labelled set -------------------------------------------------------

@pytest.mark.parametrize("case", MUST_PASS, ids=case_id)
def test_a_field_given_a_reference_is_not_refused(case):
    passes(*case)


@pytest.mark.parametrize("case", MUST_REFUSE, ids=case_id)
def test_a_field_given_a_literal_is_refused(case):
    refuses(*case)
    refuses(*case, bare=True)  # and on its own, outside any block


@pytest.mark.parametrize("case", KNOWN_FALSE_REFUSALS, ids=case_id)
def test_known_false_refusals_are_still_refused(case):
    suffix, text, reason = case
    assert reason
    refuses(suffix, text)


@pytest.mark.parametrize("case", KNOWN_MISSES, ids=case_id)
def test_known_misses_still_pass(case):
    suffix, text, reason = case
    assert reason
    passes(suffix, text)


def test_the_set_is_as_large_as_the_release_gate_asks():
    counts = {}
    for suffix, _text in MUST_PASS:
        language = GATE_LANGUAGES.get(suffix)
        if language:
            counts[language] = counts.get(language, 0) + 1
    assert sum(counts.values()) >= 200, counts
    assert all(counts[language] >= 35 for language in ("TypeScript", "Go", "SQL", "YAML")), counts
    assert len(MUST_REFUSE) >= 60
    assert len({case[:2] for case in MUST_PASS + MUST_REFUSE}) == len(MUST_PASS + MUST_REFUSE)  # no line twice


def test_the_set_tells_the_two_readings_apart():
    """Many of the lines that pass are refused when the same text is read without its path."""
    strict = 0
    for _suffix, text in MUST_PASS:
        try:
            check_text(spell(text))
        except AssistantError:
            strict += 1
    assert strict >= 110, strict


@pytest.mark.parametrize("suffix", sorted({suffix for suffix, _text in MUST_PASS}))
def test_one_file_of_references_passes_and_any_literal_added_to_it_is_refused(suffix):
    whole = "".join(in_file(suffix, text) + "\n" for case_suffix, text in MUST_PASS if case_suffix == suffix)
    check_text(spell(whole), source_path=path_for(suffix))
    for case_suffix, text in MUST_REFUSE:
        if case_suffix == suffix:
            refuses(suffix, whole + in_file(suffix, text) + "\n", bare=True)
            refuses(suffix, in_file(suffix, text) + "\n" + whole, bare=True)


# --- What decides it --------------------------------------------------------

@pytest.mark.parametrize("suffix,text", [
    ("ts", "  @pw@: process.env.DB_@PW@,"),
    ("go", "\t\t@Pw@: cfg.Database.@Pw@,"),
    ("sql", "UPDATE users SET @pw@ = new_@pw@_hash WHERE id = user_id;"),
    ("yml", '    @pw@: "${DATABASE_@PW@}"'),
])
def test_the_same_words_read_without_a_path_keep_the_strict_rules(suffix, text):
    passes(suffix, text)
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text(spell(text))  # a name, a setting, or what a model wrote


@pytest.mark.parametrize("suffix", ["yml", "json", "toml", "sh", "md", "txt", "tsx", "jsx", "html", "rb", "php", "rs"])
def test_an_unquoted_value_is_a_literal_where_strings_need_no_quotes_or_the_language_is_not_read(suffix):
    refuses(suffix, "@pw@: process.env.DB_@PW@_VALUE")
    refuses(suffix, "@pw@ = hashed@Pw@Value")


@pytest.mark.parametrize("value", [
    "${DB_@PW@}", "${{ secrets.DB_@PW@ }}", "{{ db_@pw@_value }}", "$(DATABASE_@PW@)", "${DB_@PW@:-}",
    "${var.database_@pw@}", "${ssm:/service/database}", "  ${DB_@PW@}  ", "${values[0].credential}",
])
def test_one_expansion_in_quotes_is_a_reference_in_any_file(value):
    for suffix in ("yml", "json", "sh", "md", "ts", "txt"):
        passes(suffix, '@pw@: "%s"' % value)
    passes("py", '@pw@ = "%s"\n' % value)
    passes("py", '"""\n@pw@: "%s"\n"""\n' % value)


@pytest.mark.parametrize("value", ["$DB_@PW@", "$db_@pw@_value", "$(cat /run/secrets/db)", "$TRINGCHEESE99",
                                   "$(pa55w0rd!XX)"])
def test_a_dollar_without_braces_is_a_reference_only_in_a_shell_scripts_double_quotes(value):
    for suffix in ("sh", "bash", "zsh", "ksh"):
        passes(suffix, '@PW@="%s"' % value)
        refuses(suffix, "@PW@='%s'" % value)  # In single quotes the shell keeps the text as it is.
    for suffix in ("yml", "json", "ts", "txt"):
        refuses(suffix, '@pw@: "%s"' % value)  # Elsewhere a password can be spelled so.
    refuses("py", '@pw@ = "%s"\n' % value)


@pytest.mark.parametrize("value", [
    "${DB_@PW@:-@W@}", "${DB_@PW@-@W@}", "${DB_@PW@:=@W@}", "${DB_@PW@:+@W@}", "${DB_@PW@:?@W@}",
    "${DB_@PW@}@W@", "@W@${DB_@PW@}", "${A_NAME}${B_NAME}", "$DB_@PW@ @W@", "{{ a }}{{ b }} tail",
    "$(echo one)$(echo two)", "{DB_@PW@_VALUE}", "%DB_@PW@_VALUE%", "<DB_@PW@_VALUE>",
])
def test_an_expansion_with_a_default_or_with_anything_beside_it_is_a_literal(value):
    for suffix in ("yml", "json", "sh", "ts"):
        refuses(suffix, '@pw@: "%s"' % value)
    refuses("py", '@pw@ = "%s"\n' % value)


def test_a_key_of_a_mapping_under_a_label_is_not_its_value():
    passes("yml", "inputs:\n  @ght@:\n    description: 'Token for the API'\n    required: true\n")
    passes("yaml", "  @pw@:\n    existing-credential:\n      name: database\n")
    # Only in YAML, only on a later line, and only when the words are a key.
    refuses("txt", "@ght@:\n    description: x\n")
    refuses("yml", "  @ght@: description:\n")
    refuses("yml", "  @pw@:\n    @W@\n")
    refuses("yml", "  @pw@:\n    description:@W@\n")
    refuses("yml", "  @pw@:\n    description: x\n  other_@pw@: @W@\n")


# --- What a refusal says locally --------------------------------------------

def test_a_refusal_names_the_rule_and_the_lines_and_never_the_value():
    refusal = refuses("ts", "const a = 1;\n  @pw@: \"@V@\",\nconst b = 2;\n  @aK@: '@V@',\n")
    assert refusal.local_details == {"rule": "credential_label", "lines": [2, 4]}
    assert refusal.public_details == {} and spell("@V@") not in json.dumps(refusal.local_details)


def test_a_refusal_in_python_names_lines_from_the_code_and_from_its_text():
    refusal = refuses("py", 'import os\n@pw@ = "@V@"\n\n# @aK@: @W@\n' + ACCOUNT + " = 12345678\n")
    assert refusal.local_details == {"rule": "credential_label", "lines": [2, 4]}
    refusal = refuses("py", "x = 1\n" + ACCOUNT + " = 12345678\n")
    assert refusal.local_details == {"rule": "account_label", "lines": [2]}
    refusal = refuses("py", 'x = 1\ny = """\nfirst\n@pw@: @W@\n"""\n')
    assert refusal.local_details == {"rule": "credential_label", "lines": [4]}


def test_a_known_format_is_named_too():
    refusal = refuses("md", "one\ntwo\ntoken " + "ghp_" + "a" * 36 + "\n")
    assert refusal.local_details == {"rule": "github_token", "lines": [3]}
    refusal = refuses("py", "one = 1\nkey = '" + "AKIA" + "ABCDEFGHIJKLMNOP" + "'\n")
    assert refusal.local_details == {"rule": "aws_access_key_id", "lines": [2]}


def test_many_refused_lines_are_counted_not_listed():
    refusal = refuses("yml", "".join("k%d_@pw@: @W@\n" % number for number in range(30)))
    assert refusal.local_details["lines"] == list(range(1, 21)) and refusal.local_details["more_lines"] is True


def test_text_read_without_a_path_names_the_rule_only():
    with pytest.raises(AssistantError, match="^sensitive_content$") as refusal:
        check_text(spell("@pw@: @W@"))
    assert refusal.value.local_details == {"rule": "credential_label"}


# --- What a model may write back --------------------------------------------

def source(path, text):
    return [{"path": path, "before": None, "after": spell(text)}]


def output(text):
    return {"summary": "Synthetic review", "findings": [{"claim": spell(text)}]}


SCRIPT = "export const settings = {\n  @pw@: process.env.DB_@PW@,\n  retries: 3,\n};\n"


@pytest.mark.parametrize("quote", [
    "The field `@pw@: process.env.DB_@PW@` is read once at start.",
    "@pw@: process.env.DB_@PW@",
    "Line 2:\n  @pw@: process.env.DB_@PW@,\nis fine.",
    "+  @pw@: process.env.DB_@PW@,",
    "`@pw@: process.env.DB_@PW@` (unchanged).",
    "`@pw@: process.env.DB_@PW@`: read once at start.",
    "Did you mean `@pw@: process.env.DB_@PW@`?",
    "- `@pw@: process.env.DB_@PW@`\n- `retries: 3` is new",
    "It reads `@pw@: process.env.DB_@PW@`\nIf it is unset, startup fails.",
    "```\nexport const settings = {\n  @pw@: process.env.DB_@PW@,\n  retries: 3,\n};\n```",
])
def test_a_model_may_repeat_a_reference_from_the_source_it_was_sent(quote):
    check_output_document(output(quote), source("src/settings.ts", SCRIPT))
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(output(quote), source("src/settings.ts", "export const settings = {};\n"))


@pytest.mark.parametrize("text", [
    "@pw@: process.env.DB_@PW@_OTHER",                 # another value
    "@pw@: process.env.DB_@PW@ || \"@V@\"",             # the reference, then a literal on its line
    "@pw@: process.env.DB_@PW@ ?? '@V@'",
    "@pw@: process.env.DB_@PW@\n  || \"@V@\"",          # the literal on the next line
    "@pw@: process.env.DB_@PW@\n\n  + \"@V@\"",
    "@pw@: process.env.DB_@PW@ ||\n  \"@V@\"",
    "@pw@: process.env.DB_@PW@ || `@V@`",              # or in backticks
    "@pw@: process.env.DB_@PW@\n  ?? `@V@`",
    "@pw@: process.env.DB_@PW@ ?\n  process.env.OTHER : `@V@`",
    "@pw@: process.env.DB_@PW@\n  : `@V@`",
    "`@pw@: process.env.DB_@PW@` || `@V@`",            # or after the code span that held the quote
    "@pw@: process.env.DB_@PW@` || `@V@`",             # a closing mark with no opening one
    "@pw@: process.env.DB_@PW@(`@V@`)",
    "@pw@: process.env.DB_@PW@ [`@V@`]",
    "@pw@: process.env.DB_@PW@ /* note */ || `@V@`",   # or behind a comment
    "@pw@: process.env.DB_@PW@\n/* note */ || \"@V@\"",
    "@pw@: process.env.DB_@PW@\n// note\n  || \"@V@\"",
    "@pw@: process.env.DB_@PW@ as string || `@V@`",    # or behind a word
    "`@pw@: process.env.DB_@PW@` as string || `@V@`",
    "`@pw@: process.env.DB_@PW@` ? `other` : `@V@`",
    "`@pw@: process.env.DB_@PW@`\n|| `@V@`",
    "@pw@: process.env.DB_@PW@ || 123456789012345",    # or as a number
    "@pw@: process.env.DB_@PW@ /* note */ || 123456789012345",
    # A whole program: the next line begins with an operator that is in no list.
    "export const settings = {\n  @pw@: process.env.DB_@PW@\n    | 0 || \"@V@\"\n};",
    "export const settings = {\n  @pw@: process.env.DB_@PW@\n    & 0 || \"@V@\"\n};",
    "export const settings = {\n  @pw@: process.env.DB_@PW@\n    - 0 || \"@V@\"\n};",
    "@pw@: process.env.DB_@PW@\n  in registry || \"@V@\"",
    "@pw@: process.env.DB_@PW@\n  123456789012345",
    "@pw@: process.env.DB_@PW@ = \"@V@\"",
    "@pw@: process.env.DB_@PW@ = hunter_@W@",
    "@pw@: \"@V@\"",
    "@pw@ = process.env.DB_@PW@",                      # another separator is another text
    "db_@pw@: process.env.DB_@PW@",                    # and so is another label
    "{\"@pw@\": \"@V@\"}",
])
def test_a_model_may_not_give_the_label_another_value(text):
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(output(text), source("src/settings.ts", SCRIPT))


@pytest.mark.parametrize("text", [
    "@pw@: process.env.DB_@PW@ is read once at start.",
    "see @pw@: process.env.DB_@PW@ (unchanged)",
    "@pw@: process.env.DB_@PW@ })",
    "@pw@: process.env.DB_@PW@\n\n- retries is new",   # a bullet could be a minus sign
    "@pw@: process.env.DB_@PW@\n* retries is new",
])
def test_a_quote_outside_a_code_span_must_end_its_line(text):
    """Refused though nothing is added: what follows a bare quote on its line cannot be told from code."""
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(output(text), source("src/settings.ts", SCRIPT))
    check_output_document(output("export const settings = { @pw@: process.env.DB_@PW@ };"),
                          source("src/settings.ts", "export const settings = { @pw@: process.env.DB_@PW@ };\n"))


def test_a_quote_that_ends_with_an_operator_is_not_over():
    carried = "export const settings = {\n  @pw@: process.env.DB_@PW@+\n    suffixValue,\n};\n"
    files = source("src/settings.ts", carried)
    for text in ("@pw@: process.env.DB_@PW@+\n\"@V@\"", "  @pw@: process.env.DB_@PW@+\n    `@V@`,",
                 "`@pw@: process.env.DB_@PW@+` `@V@`", "  @pw@: process.env.DB_@PW@+\n    suffixValue,"):
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_output_document(output(text), files)
    with pytest.raises(AssistantError, match="^sensitive_content$"):  # a number after the code span that held the quote
        check_output_document(output("`@pw@: process.env.DB_@PW@` | 0 || 123456789012345"), source("src/settings.ts", SCRIPT))


def test_a_line_of_code_may_end_with_the_quote_when_the_next_line_begins_something_new():
    last = "export const settings = {\n  retries: 3,\n  @pw@: process.env.DB_@PW@\n};\n"
    for text in ("```ts\n" + last + "```", "  @pw@: process.env.DB_@PW@\n};", "@pw@: process.env.DB_@PW@\nretries: 3",
                 "@pw@: process.env.DB_@PW@\n// read once\n}", "@pw@: process.env.DB_@PW@\n\"retries\": 3",
                 "@pw@: process.env.DB_@PW@"):
        check_output_document(output(text), source("src/settings.ts", last))
    python = "@pw@ = settings.DATABASE_@PW@\nif not @pw@:\n    raise SystemExit(2)\n"
    check_output_document(output("```python\n" + python + "```"), source("src/app.py", python))
    patch = {"patch": spell("--- a/src/settings.ts\n+++ b/src/settings.ts\n@@ -1,4 +1,4 @@\n export const settings = {\n"
                            "-  retries: 3,\n+  retries: 5,\n   @pw@: process.env.DB_@PW@\n };\n")}
    check_output_document(patch, source("src/settings.ts", last), diff=True)


def test_a_model_may_repeat_what_follows_a_reference_on_its_source_line_and_nothing_else():
    line = "  @pw@: process.env.DB_@PW@ || readVault(databaseName),"
    files = source("src/settings.ts", "export const settings = {\n" + line + "\n};\n")
    for quote in (line, line.strip().rstrip(","), "`" + line.strip().rstrip(",") + "` falls back to the vault.",
                  "`@pw@: process.env.DB_@PW@` is read first."):
        check_output_document(output(quote), files)
    for text in ("  @pw@: process.env.DB_@PW@ || readVault(otherName),",
                 "  @pw@: process.env.DB_@PW@ || readVault(databaseName) || `@V@`,",
                 "  @pw@: process.env.DB_@PW@ || readVault(databaseName)\n    || `@V@`,",
                 "  @pw@: process.env.DB_@PW@ || `@V@`,"):
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_output_document(output(text), files)


def test_a_structured_reply_cannot_spell_a_credential_across_two_fields():
    document = {"summary": "x", "findings": [{spell("@pw@"): spell("@V@")}]}
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(document, source("src/settings.ts", SCRIPT))


def test_a_reference_in_python_and_an_expansion_in_yaml_may_be_repeated_too():
    files = (source("src/settings.py", "@pw@ = get_@pw@_from_vault()\n")
             + source("deploy/compose.yml", 'services:\n  db:\n    environment:\n      @pw@: "${DB_@PW@}"\n'))
    check_output_document(output("`@pw@ = get_@pw@_from_vault()` and `@pw@: \"${DB_@PW@}\"` both read it."), files)
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(output('@pw@: "${DB_@PW@:-@W@}"'), files)


@pytest.mark.parametrize("line", ["-@pw@: process.env.DB_@PW@", "-  @pw@: process.env.DB_@PW@,",
                                  " @pw@: process.env.DB_@PW@", "+@pw@: process.env.DB_@PW@"])
def test_a_patch_may_carry_the_reference_on_a_removed_or_kept_line(line):
    patch = {"patch": spell("--- a/src/settings.ts\n+++ b/src/settings.ts\n@@ -1,4 +1,4 @@\n" + line + "\n")}
    check_output_document(patch, source("src/settings.ts", SCRIPT), diff=True)
    if line.startswith("-@"):  # Outside a patch the dash is part of the label, so it is another text.
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_output_document(patch, source("src/settings.ts", SCRIPT))


def test_a_packet_of_references_is_accepted_and_one_literal_refuses_it():
    packet = {"head": "0" * 40, "files": [
        {"path": "src/settings.ts", "before": None, "after": spell(SCRIPT)},
        {"path": "db/rotate.sql", "before": None, "after": spell("UPDATE users SET @pw@ = new_@pw@_hash WHERE id = $1;\n")},
    ]}
    check_context_document(packet)
    packet["files"][1]["after"] = spell("UPDATE users SET @pw@ = '@V@' WHERE id = $1;\n")
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_context_document(packet)


# --- Through the gate -------------------------------------------------------

def test_a_gate_reviews_a_script_that_reads_its_credentials_from_the_environment(gate_case):
    candidate(gate_case, spell(SCRIPT), name="src/settings.ts")
    received = []

    def handler(packet):
        received.extend(file["after"] for file in packet["files"])
        return envelope(json.dumps({"head": packet["head"], "summary": spell("`@pw@: process.env.DB_@PW@` is unchanged."),
                                    "reviewed_paths": [file["path"] for file in packet["files"]], "findings": []}))

    report, calls = run(gate_case, handler)
    assert report["verdict"] == "PASS" and len(calls) == 1
    assert spell(SCRIPT) in received


def test_a_gate_still_stops_a_script_with_a_literal_before_any_request(gate_case):
    candidate(gate_case, spell('export const settings = {\n  @pw@: process.env.DB_@PW@ || "@V@",\n};\n'),
              name="src/settings.ts")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
