"""The credential screen tells a reference from a value (#96, release gate B5).

Synthetic values only. Credential words are written as markers and spelled out at run time, as
in credential_cases.py, so this file holds no credential-shaped text of its own.
"""
import json
import subprocess
import sys

import pytest

from credential_cases import KNOWN_FALSE_REFUSALS, KNOWN_MISSES, MUST_PASS, MUST_REFUSE, spell
from finassist.errors import AssistantError
from finassist.code_text import _WORD_OPERATORS
from finassist.security import _leaves_open, check_context_document, check_output_document, check_text
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
    "`@pw@: process.env.DB_@PW@` is unchanged,\nand the old code read `settings || {}` first, and `mode || \"fast\"` stays.",
    "`@pw@: process.env.DB_@PW@` is unchanged; a table follows.\n\n| field | note |\n| --- | --- |\n| `retries` | now 5 |",
    # What prose is made of may follow a code span.
    "| `@pw@: process.env.DB_@PW@` | read from the environment |",
    "1. `@pw@: process.env.DB_@PW@`\n2. `retries: 3` is new",
    "* `@pw@: process.env.DB_@PW@`\n* `retries: 3` is new",
    "**`@pw@: process.env.DB_@PW@`** is unchanged.",
    "(`@pw@: process.env.DB_@PW@`), as before.",
    "`@pw@: process.env.DB_@PW@`\n> quoted from the guide",
    "`@pw@: process.env.DB_@PW@` - read once at start.",
    "`@pw@: process.env.DB_@PW@` " + chr(0x2014) + " read once at start.",
    "`@pw@: process.env.DB_@PW@` (line 2) is unchanged.",
    "`@pw@: process.env.DB_@PW@`... and so on.",
    "`@pw@: process.env.DB_@PW@`, `retries: 3` and `src/settings/loader.ts` are unchanged.",
    # A comma, a semicolon or a closing bracket that nothing opened ends the clause, and what follows is free.
    "`@pw@: process.env.DB_@PW@` is unchanged, as `src/settings/loader.ts` shows.",
    "`@pw@: process.env.DB_@PW@` is fine,\nbut the default in `host || \"db.internal.example\"` is not.",
    "`@pw@: process.env.DB_@PW@` is read once;\nlater the name + `-suffix-long-enough` is built.",
    "(as in `@pw@: process.env.DB_@PW@`) and so the fallback || `src/settings/loader.ts` is unused.",
    "`@pw@: process.env.DB_@PW@`) || `@V@`",
    "Is `@pw@: process.env.DB_@PW@` used?\nYes, and `src/settings/loader.ts` reads it.",
    # Plain prose of any kind may stand before the clause ends: no list says which sign may come first.
    "`@pw@: process.env.DB_@PW@` *is* read once at startup.",
    "`@pw@: process.env.DB_@PW@` @owner please check this.",
    "`@pw@: process.env.DB_@PW@` is 100% unchanged.",
    "`@pw@: process.env.DB_@PW@` | read from the environment |",
    "`@pw@: process.env.DB_@PW@`[^1] is unchanged.",
    "`@pw@: process.env.DB_@PW@`**note** it is unchanged.",
    "`@pw@: process.env.DB_@PW@` is unchanged. Nothing else moves. The loader still runs first.",
    "`@pw@: process.env.DB_@PW@` || fallbackName is how the old code read it.",
    "`@pw@: process.env.DB_@PW@` + 12345678901 is still a short number.",
    "`@pw@: process.env.DB_@PW@` || .1234567890 is one too.",
    "`@pw@: process.env.DB_@PW@` costs $5 to $10 a month and $name stays.",
    # A code span too short to be a credential is plain, as short strings are in source.
    "`@pw@: process.env.DB_@PW@` is set before `retries` and `mode`.",
    "`@pw@: process.env.DB_@PW@` as string || `Zq7Lm2` + `Xp9Rt4Vw8`",
    "`@pw@: process.env.DB_@PW@` is set before `retries` `mode`.",
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
    # After a code span, on the next line or later: each has a same-line twin above or below.
    "`@pw@: process.env.DB_@PW@` | 0 || `@V@`",
    "`@pw@: process.env.DB_@PW@`\n | 0 || `@V@`",
    "`@pw@: process.env.DB_@PW@`\n | 0 || 123456789012345",
    "`@pw@: process.env.DB_@PW@`\n | 0\n || `@V@`",
    "`@pw@: process.env.DB_@PW@`\n\n | 0 ||\n \"@V@\"",
    "`@pw@: process.env.DB_@PW@`\n\n|| \"@V@\"",
    "`@pw@: process.env.DB_@PW@` is the field.\n\nLater: fallback ?? '@V@'",
    # After a code span, anything that can hold a literal before the clause ends. These hold none, and are the cost.
    "`@pw@: process.env.DB_@PW@` is read in `src/settings/loader.ts`.",
    "`@pw@: process.env.DB_@PW@` or the value from `src/settings/loader.ts`.",
    "Did you mean `@pw@: process.env.DB_@PW@`? See `src/settings/loader.ts` for the caller.",
    "`@pw@: process.env.DB_@PW@` is unchanged.\nThe old code read `settings || {}` first.",
    "`@pw@: process.env.DB_@PW@` is unchanged.\n\n```ts\nhost: process.env.DB_HOST || \"db.internal.example\",\n```",
    "See `@pw@: process.env.DB_@PW@`:\n\n```ts\nconst retries = 3;\n```",
    "`@pw@: process.env.DB_@PW@`\n\n## Next\n\nText.",
    "`@pw@: process.env.DB_@PW@` is unchanged.\n\n| field | note |\n| --- | --- |\n| `retries` | now 5 |",
    "`@pw@: process.env.DB_@PW@` is unchanged. See src/settings/loader.ts for the caller.",
    "`@pw@: process.env.DB_@PW@` is unchanged. It doesn't matter here.",
    "`@pw@: process.env.DB_@PW@` is read when a < b holds.",
    # Third review, finding 1: behind a word, any sign at all before a literal.
    "`@pw@: process.env.DB_@PW@` as string | `@V@`",
    "`@pw@: process.env.DB_@PW@` as string & `@V@`",
    "`@pw@: process.env.DB_@PW@` as string ^ `@V@`",
    "`@pw@: process.env.DB_@PW@` as string * `@V@`",
    "`@pw@: process.env.DB_@PW@` as string - `@V@`",
    "`@pw@: process.env.DB_@PW@` as string % `@V@`",
    "`@pw@: process.env.DB_@PW@` as string >> `@V@`",
    "`@pw@: process.env.DB_@PW@` as string ** `@V@`",
    "`@pw@: process.env.DB_@PW@` as number | 123456789012345",
    "`@pw@: process.env.DB_@PW@` as number - 123456789012345",
    "`@pw@: process.env.DB_@PW@` as number < 123456789012345",
    "`@pw@: process.env.DB_@PW@` as number | .123456789012345",
    "`@pw@: process.env.DB_@PW@` as string . padEnd(20, `@V@`)",
    "`@pw@: process.env.DB_@PW@` as any [`@V@`]",
    "`@pw@: process.env.DB_@PW@` as any (`@V@`)",
    "`@pw@: process.env.DB_@PW@` as any { value: `@V@` }",
    "`@pw@: process.env.DB_@PW@` as any String.raw`@V@`",
    "`@pw@: process.env.DB_@PW@` as string in `@V@`",
    "`@pw@: process.env.DB_@PW@` or `@V@`",
    "`@pw@: process.env.DB_@PW@` orElse `@V@`",
    # Finding 2: a comma, a semicolon or a bracket inside a comment ends nothing.
    "`@pw@: process.env.DB_@PW@` as string /* , */ || `@V@`",
    "`@pw@: process.env.DB_@PW@` as string /* ; */ || `@V@`",
    "`@pw@: process.env.DB_@PW@` as string /* ) */ || `@V@`",
    "`@pw@: process.env.DB_@PW@` as string /* , */ || 123456789012345",
    "`@pw@: process.env.DB_@PW@` as string // note;\n|| \"@V@\"",
    "`@pw@: process.env.DB_@PW@` as string -- note,\n|| '@V@'",
    "`@pw@: process.env.DB_@PW@` as string # note,\n|| \"@V@\"",
    "`@pw@: process.env.DB_@PW@` as string || /,/.source + `@V@`",
    # Codex at f569288: a string of SQL in dollar tags holds no quote mark, and a point is part of a number.
    "`@pw@: process.env.DB_@PW@` || $$@V@$$",
    "`@pw@: process.env.DB_@PW@` || $tag$@V@$tag$",
    "`@pw@: process.env.DB_@PW@` || $q1$@V@$q1$",
    "`@pw@: process.env.DB_@PW@` as string $$ , $$ || `@V@`",
    "`@pw@: process.env.DB_@PW@` || .12345678901",
    "`@pw@: process.env.DB_@PW@` || 123456789012",
    # Short spans side by side are one string, as strings that stand side by side are in source.
    "`@pw@: process.env.DB_@PW@` || `Zq7Lm2Xp9R` `t4Vw8`",
    "`@pw@: process.env.DB_@PW@` || `Zq7Lm2Xp9R`\n`t4Vw8`",
    "`@pw@: process.env.DB_@PW@` || `Zq7Lm2``Xp9Rt4Vw8`",
    "`@pw@: process.env.DB_@PW@` || `Zq7L` `m2Xp` `9Rt4` `Vw8`",
    # Finding 3: an escape, a dollar or a brace makes a short span something else.
    "`@pw@: process.env.DB_@PW@` as string ||\n\"aa\\\" || \\\"bbbbbbbb\"",
    "`@pw@: process.env.DB_@PW@` as string || `aa\\` || \\`bbbbbbbb`",
    "`@pw@: process.env.DB_@PW@` as string || `${\"@V@\"}`",
    # After a code span, whatever is not prose. No list of operators decides.
    "`@pw@: process.env.DB_@PW@`\n ? \"@V@\" : other",
    "`@pw@: process.env.DB_@PW@` ?: `@V@`",
    "`@pw@: process.env.DB_@PW@`\n? other : `@V@`",
    "`@pw@: process.env.DB_@PW@`\n.concat(`@V@`)",
    "`@pw@: process.env.DB_@PW@`.padEnd(20, `@V@`)",
    "`@pw@: process.env.DB_@PW@`\n[`@V@`]",
    "`@pw@: process.env.DB_@PW@`\n(`@V@`)",
    "`@pw@: process.env.DB_@PW@` (`@V@`)",
    "`@pw@: process.env.DB_@PW@` (first, `@V@`)",
    "`@pw@: process.env.DB_@PW@` (123456789012345)",
    "`@pw@: process.env.DB_@PW@`\n`@V@`",
    "`@pw@: process.env.DB_@PW@` `@V@`",
    "`@pw@: process.env.DB_@PW@``@V@`",
    "`@pw@: process.env.DB_@PW@`\n & `@V@`",
    "`@pw@: process.env.DB_@PW@` ^ `@V@`",
    "`@pw@: process.env.DB_@PW@` % `@V@`",
    "`@pw@: process.env.DB_@PW@` < `@V@`",
    "`@pw@: process.env.DB_@PW@` / `@V@`",
    "`@pw@: process.env.DB_@PW@`: `@V@`",
    "`@pw@: process.env.DB_@PW@`!.concat(`@V@`)",
    "`@pw@: process.env.DB_@PW@`** + `@V@`",
    # Behind a word, a dash or a bar, the operator and the literal are found wherever they stand.
    "`@pw@: process.env.DB_@PW@` as string ?: `@V@`",
    "`@pw@: process.env.DB_@PW@` as string ? `@V@` : other",
    "`@pw@: process.env.DB_@PW@` as string ? other : `@V@`",
    "`@pw@: process.env.DB_@PW@`\n - 0 ?: `@V@`",
    "`@pw@: process.env.DB_@PW@`\n | 0 || 0xDEADBEEFCAFEBABE1234",
    "`@pw@: process.env.DB_@PW@`\n | 0 || 123_456_789_012_345",
    "`@pw@: process.env.DB_@PW@`? `@V@` : other",
    # The literal one call deeper, in a bracket, or behind type arguments with a comma.
    "`@pw@: process.env.DB_@PW@` as string || derive(`@V@`)",
    "`@pw@: process.env.DB_@PW@` as string\n ?? pick(first, `@V@`)",
    "`@pw@: process.env.DB_@PW@` as string || [first, `@V@`][1]",
    "`@pw@: process.env.DB_@PW@` in registry ? derive(`@V@`) : other",
    "`@pw@: process.env.DB_@PW@` in registry ? other : derive(first, `@V@`)",
    "`@pw@: process.env.DB_@PW@` as Map<string, string> || `@V@`",
    "`@pw@: process.env.DB_@PW@` as Map<() => void, string> || `@V@`",
    "`@pw@: process.env.DB_@PW@` as string || 123456789012345",
    "`@pw@: process.env.DB_@PW@` as string + derive(\n`@V@`)",
    # A bar is a table's only in a table row, and a row may not join a literal either.
    "| `@pw@: process.env.DB_@PW@` | 0 || derive(`@V@`) |",
    "`@pw@: process.env.DB_@PW@` | `@V@`",
    "`@pw@: process.env.DB_@PW@`\n| 0 | `@V@`",
    # A block or another span right after the span, with no word, colon or full stop between.
    "`@pw@: process.env.DB_@PW@`\n```ts\nconst retries = 3;\n```",
    "`@pw@: process.env.DB_@PW@` (unchanged) || `@V@`",
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


def test_in_a_patch_the_mark_of_a_line_is_not_part_of_its_text():
    files = source("src/settings.ts", SCRIPT)
    head = "--- a/README.md\n+++ b/README.md\n@@ -1,3 +1,3 @@\n"
    # A removed bullet reads "-- old" with its mark, which would be two dashes. The mark is not text.
    body = "-see `@pw@: process.env.DB_@PW@`\n-- an old bullet\n+- a new bullet\n"
    check_output_document({"patch": spell(head + body)}, files, diff=True)
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(output(body), files)  # Outside a patch the same lines hold two dashes.
    for body in ("-see `@pw@: process.env.DB_@PW@` + `@V@`\n", "-see `@pw@: process.env.DB_@PW@`\n+ || `@V@`\n",
                 "-see `@pw@: process.env.DB_@PW@`\n+\"@V@\"\n"):
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_output_document({"patch": spell(head + body)}, files, diff=True)


def test_a_quote_that_ends_with_an_operator_is_not_over():
    carried = "export const settings = {\n  @pw@: process.env.DB_@PW@+\n    suffixValue,\n};\n"
    files = source("src/settings.ts", carried)
    for text in ("@pw@: process.env.DB_@PW@+\n\"@V@\"", "  @pw@: process.env.DB_@PW@+\n    `@V@`,",
                 "`@pw@: process.env.DB_@PW@+` `@V@`", "  @pw@: process.env.DB_@PW@+\n    suffixValue,"):
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_output_document(output(text), files)
    with pytest.raises(AssistantError, match="^sensitive_content$"):  # a number after the code span that held the quote
        check_output_document(output("`@pw@: process.env.DB_@PW@` | 0 || 123456789012345"), source("src/settings.ts", SCRIPT))


def test_a_clause_after_a_code_span_that_has_no_end_in_reach_is_refused():
    files = source("src/settings.ts", SCRIPT)
    words = "and so on " * 500
    check_output_document(output("`@pw@: process.env.DB_@PW@` is read, " + words + "|| `@V@`"), files)  # the comma ends it
    check_output_document(output("`@pw@: process.env.DB_@PW@` is read " + "and so on " * 300), files)  # the reply ends it
    for text in ("`@pw@: process.env.DB_@PW@` is read " + words + "|| `@V@`",       # the literal is out of reach
                 "`@pw@: process.env.DB_@PW@` is read " + words + ", the end",       # and so is the comma
                 "`@pw@: process.env.DB_@PW@` is read " + "( " * 500 + "the end"):   # too many parts
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_output_document(output(text), files)


@pytest.mark.parametrize("literal,refused", [
    ("$$@V@$$", True), ("$tag$@V@$tag$", True), ("'@V@'", True),
    (".12345678901", True), (".1234567890", False), ("123456789012", True), ("12345678901", False),
])
def test_a_literal_after_a_quote_is_refused_in_a_reply_exactly_where_it_is_refused_in_source(literal, refused):
    """Codex at f569288, in SQL: the dollar-quoted forms, and both sides of the length a number needs."""
    written = "SELECT @pw@ = settings_@pw@;\n"
    files = source("src/settings.sql", written)
    check_text(spell(written), source_path="src/settings.sql")
    as_source = "SELECT @pw@ = settings_@pw@ || " + literal + ";\n"
    as_reply = output("`@pw@ = settings_@pw@` || " + literal)
    if refused:
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_text(spell(as_source), source_path="src/settings.sql")
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_output_document(as_reply, files)
    else:
        check_text(spell(as_source), source_path="src/settings.sql")
        check_output_document(as_reply, files)


def test_short_strings_side_by_side_are_refused_in_source_and_in_a_reply_alike():
    block = "export const settings = {\n  @pw@: process.env.DB_@PW@%s,\n};\n"
    files = source("src/settings.ts", block % "")
    for after, refused in ((' || "Zq7Lm2Xp9R" "t4Vw8"', True), (' || "Zq7Lm2" + "Xp9Rt4Vw8"', False)):
        reply = output("`@pw@: process.env.DB_@PW@`" + after.replace('"', "`"))
        if refused:
            with pytest.raises(AssistantError, match="^sensitive_content$"):
                check_text(spell(block % after), source_path="src/settings.ts")
            with pytest.raises(AssistantError, match="^sensitive_content$"):
                check_output_document(reply, files)
        else:
            check_text(spell(block % after), source_path="src/settings.ts")
            check_output_document(reply, files)


def test_a_word_that_carries_an_expression_on_in_source_does_so_in_a_reply():
    assert {"else", "extends", "in", "instanceof"} <= _WORD_OPERATORS
    for word in sorted(_WORD_OPERATORS | {"or", "and", "not"}):
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_output_document(output("@pw@: process.env.DB_@PW@\n  " + word + " \"@V@\""), source("src/settings.ts", SCRIPT))
    check_output_document(output("@pw@: process.env.DB_@PW@\n  elsewhere: \"@V@\""), source("src/settings.ts", SCRIPT))


@pytest.mark.parametrize("quote,expected", [
    ("k: call(a, b)", False), ("k: call(a,", True), ("k: list[0", True), ("k: {", True), ("k: a })", False),
    ('k: call("(")', False), ('k: call("a', True), ("k: call('it\\'s (')", False), ("k: `a ${b} (`", False),
    ("k: `a", True), ("k: call(a) // don't", True), ("k: call(a)[0].b", False),
])
def test_what_a_quote_leaves_open(quote, expected):
    assert _leaves_open(quote) is expected


@pytest.mark.parametrize("suffix,written,with_literal", [
    ("ts", "export const settings = {\n  @pw@: resolveFromSettings(lookup(),\n    other()),\n};\n",
     "export const settings = {\n  @pw@: resolveFromSettings(lookup(),\n    \"@V@\"),\n};\n"),
    ("ts", "export const settings = {\n  @pw@: resolveFromSettings(lookup(),\n    other()),\n};\n",
     "export const settings = {\n  @pw@: resolveFromSettings(lookup(),\n    `@V@`),\n};\n"),
    ("go", "func load() Config {\n\treturn Config{\n\t\t@Pw@: resolveFromSettings(lookup(),\n\t\t\tother()),\n\t}\n}\n",
     "func load() Config {\n\treturn Config{\n\t\t@Pw@: resolveFromSettings(lookup(),\n\t\t\t\"@V@\"),\n\t}\n}\n"),
    ("py", "import os\n@pw@ = os.environ.get(\"DB_@PW@\",\n    None)\n", "import os\n@pw@ = os.environ.get(\"DB_@PW@\",\n    \"@V@\")\n"),
    ("kt", "class Settings {\n  val @pw@ = settingsFromVault.value\n  val retries = 3\n}\n",
     "class Settings {\n  val @pw@ = settingsFromVault.value\n    else \"@V@\"\n}\n"),
])
def test_a_reply_is_refused_where_the_same_text_is_refused_as_source(suffix, written, with_literal):
    """The expression goes on over the line in a bracket the quote left open, or behind a word."""
    path = "src/settings." + suffix
    files = source(path, written)
    check_text(spell(written), source_path=path)
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text(spell(with_literal), source_path=path)
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(output(with_literal.rstrip("\n")), files)
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document(output("```\n" + with_literal + "```"), files)
    patch = "--- a/%s\n+++ b/%s\n@@ -1,4 +1,4 @@\n" % (path, path) + "".join("+" + line + "\n" for line in with_literal.rstrip("\n").split("\n"))
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_output_document({"patch": spell(patch)}, files, diff=True)


def test_a_quote_that_leaves_a_bracket_open_is_refused_though_nothing_is_added():
    """The cost: the first line of a call that goes on over the next cannot be repeated."""
    written = "export const settings = {\n  @pw@: resolveFromSettings(lookup(),\n    other()),\n};\n"
    files = source("src/settings.ts", written)
    for text in ("```ts\n" + written + "```", "`@pw@: resolveFromSettings(lookup(),` starts the call."):
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_output_document(output(text), files)
    check_output_document(output("`@pw@: resolveFromSettings` is called with two values."), files)


@pytest.mark.alone
def test_a_reply_made_of_quotes_is_screened_in_bounded_time():
    # Timed inside the child, as in test_code_text.py; the subprocess timeout stops a hang.
    code = """
from time import perf_counter
from finassist.security import check_output_document
from finassist.errors import AssistantError
label = "pass" + "word"
bare = label + ": process.env.DB_" + label.upper()
span = "`" + bare + "`"
files = [{"path": "src/settings.ts", "before": None, "after": "export const settings = {\\n  " + bare + ",\\n};\\n"}]
replies = [
    (span + " is read. ") * 6000,                        # one long line of code spans
    (span + "? and ") * 6000,
    (span + " is read. ") * 6000 + "? x " * 120000,       # question marks after them, and no colon
    (span + " is read +" + " " * 400) * 1500,             # long blank runs after an operator
    (span + " is read ( ") * 6000,                        # brackets that never close, so no clause ends
    (bare + "\\n") * 6000,                                # every line a quote, and each is blank to the others
    (bare + ",\\n// note\\n") * 6000,
    (span + ")" * 300 + " ") * 1000,
]
start = perf_counter()
for text in replies:
    for diff in (False, True):
        document = {"patch": text} if diff else {"summary": "x", "findings": [{"claim": text}]}
        try:
            check_output_document(document, files, diff=diff)
        except AssistantError as exc:
            assert exc.code == "sensitive_content"
print(perf_counter() - start)
"""
    completed = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=600)
    # About two seconds on a fast machine when each reply is read once and a clause has a reach. Read to its
    # end again for every quote, the third reply alone takes minutes. The limit leaves room for a slow runner.
    assert float(completed.stdout.strip()) < 120.0


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


@pytest.mark.parametrize("summary", [
    "`@pw@: process.env.DB_@PW@` as string /* ; */ || `@V@`",   # Codex at 6ecc1f6: punctuation inside a comment
    "`@pw@: process.env.DB_@PW@` as string /* , */ || `@V@`",
    "`@pw@: process.env.DB_@PW@` as string /* ) */ || `@V@`",
    "`@pw@: process.env.DB_@PW@` as string // ;\n|| `@V@`",
    "`@pw@: process.env.DB_@PW@` as string | `@V@`",            # a sign no list named
    "`@pw@: process.env.DB_@PW@` || $$@V@$$",                   # Codex at f569288: a string in dollar tags
    "`@pw@: process.env.DB_@PW@` || $tag$@V@$tag$",
    "`@pw@: process.env.DB_@PW@` || .12345678901",              # and a number of 12 characters with its point
    "`@pw@: process.env.DB_@PW@`\n | 0 || `@V@`",               # Codex at b2d2de6
    "`@pw@: process.env.DB_@PW@` || `@V@`",
])
def test_a_gate_blocks_a_reply_that_joins_a_literal_to_a_quoted_reference(gate_case, summary):
    """Through the whole route, with the one request made. The literal was in no file the model was sent."""
    candidate(gate_case, spell(SCRIPT), name="src/settings.ts")

    def handler(packet):
        assert spell("@V@") not in json.dumps(packet)
        return envelope(json.dumps({"head": packet["head"], "summary": spell(summary),
                                    "reviewed_paths": [file["path"] for file in packet["files"]], "findings": []}))

    report, calls = run(gate_case, handler)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and len(calls) == 1
    assert spell("@V@") not in json.dumps(report)


def test_a_gate_still_stops_a_script_with_a_literal_before_any_request(gate_case):
    candidate(gate_case, spell('export const settings = {\n  @pw@: process.env.DB_@PW@ || "@V@",\n};\n'),
              name="src/settings.ts")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls
