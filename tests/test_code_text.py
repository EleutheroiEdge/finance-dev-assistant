"""Telling code from text in a source file (#96): what is read, and what is left unclear.

Synthetic text only. No string here pairs a credential label with a value.
"""
import random
import subprocess
import sys

import pytest

from finassist.code_text import (COMMENT, STRING, LANGUAGES, code_text, is_expansion, nested_yaml_key,
                                 yaml_block_scalars)
from finassist.errors import AssistantError
from finassist.security import check_text

TICK = "`"
LABEL = "pass" + "word"


def read(text, suffix):
    code = code_text(text, "src/sample." + suffix)
    return None if code is None else [(kind, text[start:end]) for start, end, kind in code.spans()]


def assigned(text, suffix):
    """What `literal_assigned` says about the expression that starts at the @, which is then taken out."""
    start = text.index("@")
    text = text[:start] + text[start + 1:]
    code = code_text(text, "src/sample." + suffix)
    assert code is not None, "the text must read cleanly"
    return code.literal_assigned(start, 12)


# --- Strings and comments ---------------------------------------------------

def test_a_script_has_line_strings_block_strings_and_two_kinds_of_comment():
    text = "const a = 'one'; // two\nconst b = \"three\"; /* four\n five */ const c = " + TICK + "six\nseven" + TICK + ";\n"
    assert read(text, "ts") == [
        (STRING, "'one'"), (COMMENT, "// two"), (STRING, '"three"'), (COMMENT, "/* four\n five */"),
        (STRING, TICK + "six\nseven" + TICK)]


def test_code_inside_a_template_is_code_and_its_text_is_not():
    text = "x = " + TICK + "a ${b + '}' + " + TICK + "c ${d} e" + TICK + "} f" + TICK + ";"
    assert read(text, "ts") == [
        (STRING, TICK + "a "), (STRING, "'}'"), (STRING, TICK + "c "), (STRING, " e" + TICK), (STRING, " f" + TICK)]
    code = code_text(text, "x.ts")
    assert code.in_code(text.index("b +")) and code.in_code(text.index("d}"))
    assert not code.in_code(text.index("a $")) and not code.in_code(text.index(" e")) and not code.in_code(text.index(" f"))


def test_a_brace_inside_a_template_expression_does_not_end_it():
    text = "x = " + TICK + "a ${ {k: {m: 1}}.k.m } b" + TICK + ";"
    assert read(text, "js") == [(STRING, TICK + "a "), (STRING, " b" + TICK)]


def test_an_escaped_quote_does_not_end_a_string():
    assert read('a = "x \\" y"; b = \'z \\\' w\';', "ts") == [(STRING, '"x \\" y"'), (STRING, "'z \\' w'")]
    assert read("a = " + TICK + "x \\" + TICK + " \\${ y" + TICK + ";", "ts") == [(STRING, TICK + "x \\" + TICK + " \\${ y" + TICK)]


def test_go_raw_strings_take_no_escapes_and_no_interpolation():
    text = "a := " + TICK + "x \\ ${y}\n z" + TICK + "\nb := 'q'\nc := \"w\" // note\n"
    assert read(text, "go") == [(STRING, TICK + "x \\ ${y}\n z" + TICK), (STRING, "'q'"), (STRING, '"w"'), (COMMENT, "// note")]


def test_java_and_kotlin_text_blocks():
    block = '"""\n  one "two" three\n  """'
    assert read("String a = " + block + ";", "java") == [(STRING, block)]
    assert read("val a = " + block, "kt") == [(STRING, block)]
    assert read('String a = """\n x \\""" y\n """;', "java") == [(STRING, '"""\n x \\""" y\n """')]
    assert read('val a = """ C:\\ """', "kt") == [(STRING, '""" C:\\ """')]


def test_sql_strings_span_lines_and_double_their_quotes():
    text = "SELECT 'a''b', \"Col\" -- note\nFROM t /* c */ WHERE x = 'line\nbreak';"
    assert read(text, "sql") == [
        (STRING, "'a'"), (STRING, "'b'"), (STRING, '"Col"'), (COMMENT, "-- note"), (COMMENT, "/* c */"),
        (STRING, "'line\nbreak'")]


@pytest.mark.parametrize("text,expected", [
    # After an operator, an opening bracket or a word such as return, a slash starts a regular expression.
    ('x = /a"b/.test(y); z = "s";', ['/a"b/', '"s"']),
    ("f(/it's/g, 'q')", ["/it's/g", "'q'"]),
    ("return /['\"]/;", ["/['\"]/"]),
    ("x = [/a/, /b\\/c\"/i];", ["/a/", "/b\\/c\"/i"]),
    ("x = /[/\"]+/;", ["/[/\"]+/"]),                      # a slash inside a class does not end it
    ("x = /* why */ /a'b/;", ["/* why */", "/a'b/"]),
    ("y => /a\"b/", ["/a\"b/"]),
    ("}\n/a'b/.test(x)", ["/a'b/"]),
    ("/^it's/.test(x)", ["/^it's/"]),
    # After a name, a number, a string or a closing bracket it divides.
    ('a = b / c / d; e = "s";', ['"s"']),
    ('a = (b) / c; e = "s";', ['"s"']),
    ('a = 4 / 2; e = "s";', ['"s"']),
    ('a = b[0] / c; e = "s";', ['"s"']),
    ('a = "s" / 2; e = "t" / 3;', ['"s"', '"t"']),
    ('a = myreturn / 2; e = "s" / 3;', ['"s"']),
    # An escaped slash before a bracket is part of a regular expression, not a tag.
    ('tidy = s.replace(/<br\\s*\\/>/g, "x");', ["/<br\\s*\\/>/g", '"x"']),
    # Neither is a bracket inside one, or one that is the whole of it.
    ('safe = s.replace(/</g, "&lt;").replace(/>/g, "&gt;");', ["/</g", '"&lt;"', "/>/g", '"&gt;"']),
    ("tag = /<[^/>]+>/.exec(s);", ["/<[^/>]+>/"]),
    ("open = /^\\</.test(s);", ["/^\\</"]),
])
def test_a_regular_expression_in_a_script_is_text(text, expected):
    assert [piece for _kind, piece in read(text, "ts")] == expected


def test_where_a_regular_expression_must_start_and_has_no_end_in_reach_the_file_is_unclear():
    long = "x" * 1100
    for text in ('a = b +\n  / c; e = "s";',                  # no partner on its line
                 "const matcher = /" + long + "/;",            # a partner past the reach
                 "const matcher = /" + long + " label/;",
                 "f(/[unfinished class/);"):
        assert code_text(text, "x.ts") is None, text[:40]
    assert read("const matcher = /" + "x" * 900 + "/;", "ts") == [(STRING, "/" + "x" * 900 + "/")]
    assert code_text("a = b / " + long + " / c;", "x.ts") is not None  # two division signs, however far apart


def test_a_tag_is_seen_even_where_its_slash_looks_like_a_regular_expression():
    for text in ("const a = <b>text</b>;", "const a = <Input />;", "const a = <Input {...p} />; const b = <Input {...q} />;",
                 "return (<A {...p} />);", "x = cond ? <a>it</a> : <b>that</b>;", "<p>{a} / {b}</p>",
                 "const row = <td>{used} / {total}<br /></td>;", "const a = y = /x <Input />;",
                 "return <A {...p} />/<B {...q} />;"):
        assert code_text(text, "src/page.js") is None, text
    assert code_text("a = b < c / d;", "x.ts") is not None  # a comparison and a division are not a tag


def test_data_in_a_sql_file_is_text():
    rows = "COPY t (a, b) FROM stdin;\n1\tit's a row\n2\tuser=app\n\\.\nSELECT 1;\n"
    assert read(rows, "sql") == [(STRING, "\n1\tit's a row\n2\tuser=app\n\\.")]
    assert read("\\set name value\n  \\connect db\nSELECT 1;\n", "sql") == [(STRING, "\\set name value"), (STRING, "  \\connect db")]
    assert read("SELECT $$it's text$$, $tag$more $$ text$tag$;", "sql") == [(STRING, "$$it's text$$"), (STRING, "$tag$more $$ text$tag$")]
    assert code_text("COPY t FROM stdin;\n1\tunfinished\n", "x.sql") is None
    assert code_text("SELECT $$unfinished", "x.sql") is None
    # A tag is spelled like a name: digits after the first character, and letters of any script.
    tags = "SELECT $q1$it's text$q1$, $tag_2$more$tag_2$, $" + chr(0xE9) + "t" + chr(0xE9) + "$text$" + chr(0xE9) + "t" + chr(0xE9) + "$;"
    assert [piece[:5] for _kind, piece in read(tags, "sql")] == ["$q1$i", "$tag_", "$" + chr(0xE9) + "t" + chr(0xE9) + "$"]
    assert read("SELECT a FROM t WHERE b = $1 AND c = $2;", "sql") == []  # parameters are not tags


def test_a_dollar_quoted_body_after_as_or_do_is_code():
    body = "CREATE FUNCTION f() RETURNS text AS $$\nBEGIN\n  RETURN 'x'; -- note\nEND;\n$$ LANGUAGE plpgsql;\n"
    assert read(body, "sql") == [(STRING, "'x'"), (COMMENT, "-- note")]
    block = "DO $do$ BEGIN PERFORM f($q$text$q$); END $do$;"
    assert read(block, "sql") == [(STRING, "$q$text$q$")]
    assert code_text("CREATE FUNCTION f() RETURNS void AS $$ BEGIN END;", "x.sql") is None  # the body never ends
    # A dollar-quoted string is text wherever a value is expected, also inside a body.
    assert read("SELECT a AS b, $$text$$;", "sql") == [(STRING, "$$text$$")]


def test_a_comment_mark_inside_a_string_is_text_and_a_quote_inside_a_comment_is_not_a_string():
    assert read('a = "// not a comment"; // it\'s one', "ts") == [(STRING, '"// not a comment"'), (COMMENT, "// it's one")]
    assert read("a = '-- not a comment' -- it's one", "sql") == [(STRING, "'-- not a comment'"), (COMMENT, "-- it's one")]


@pytest.mark.parametrize("suffix,text", [
    ("ts", "const a = 'unfinished\nconst b = 1;"),
    ("ts", 'const a = "unfinished \\\n continued";'),
    ("ts", "const a = " + TICK + "unfinished"),
    ("ts", "const a = " + TICK + "x ${ y " + TICK),
    ("ts", "/* unfinished"),
    ("ts", "it's prose, not code"),
    ("js", "const a = <b>text</b>;"),
    ("js", "const a = <Input />;"),
    ("ts", "const a = 1;" + chr(0)),
    ("go", "a := " + TICK + "unfinished"),
    ("go", "a := 'x"),
    ("java", 'String a = """ unfinished'),
    ("kt", 'val a = "unfinished'),
    ("sql", "SELECT 'unfinished"),
    ("sql", "SELECT 'it\\'s'"),
    ("sql", 'SELECT "a\\"b"'),
    ("sql", "/* unfinished"),
])
def test_a_file_that_does_not_read_cleanly_is_unclear(suffix, text):
    assert code_text(text, "src/sample." + suffix) is None


@pytest.mark.parametrize("suffix", ["py", "tsx", "jsx", "yml", "json", "md", "sh", "rs", "rb", "php", "cs", "txt", ""])
def test_other_languages_are_not_read(suffix):
    assert code_text("a = 1\n", "src/sample." + suffix if suffix else "Makefile") is None
    assert code_text("a = 1\n", None) is None


def test_the_suffix_is_read_without_case():
    assert code_text("a = 1;", "SRC/Sample.TS") is not None and ".ts" in LANGUAGES


# --- Where an expression ends, and what it holds ----------------------------

LONG = '"' + "x" * 12 + '"'
SHORT = '"' + "x" * 11 + '"'


@pytest.mark.parametrize("suffix,text,expected", [
    # No string, or only a short one. The expression starts at the @.
    ("ts", "k: @config.b.c,", False),
    ("ts", "k: @getValue(a, b),", False),
    ("ts", "k: @config.value || " + SHORT + ",", False),
    # The end: a comma, a semicolon, a closing bracket it did not open, or the end of a line.
    ("ts", "k: @config.value, other: " + LONG, False),
    ("ts", "k = @config.value; other = " + LONG, False),
    ("ts", "f({ k: @config.value }, " + LONG + ")", False),
    ("ts", "k = @config.value\nother = " + LONG, False),
    ("go", "k = @config.Value\nother = " + LONG, False),
    # What carries it over a line: an operator at the end, or at the start of the next.
    ("ts", "k = @config.value ||\n  " + LONG, True),
    ("ts", "k = @config.value\n  ?? " + LONG, True),
    ("ts", "k = @config.value // why\n  // more\n  || " + LONG, True),
    ("ts", "k = @flag ?\n a :\n " + LONG, True),
    ("ts", "k = @config\n  .get(" + LONG + ")\n  ?.trim()", False),
    ("ts", "k = @config.value\n  .trim()\n  .concat(" + LONG + ")", True),
    # Inside its own brackets a line break ends nothing.
    ("ts", "k = @getValue(\n  a,\n  " + LONG + ",\n)", True),
    ("ts", "k = @getValue(\n  " + LONG + ",\n)", False),
    # A call or an index whose name says it looks something up: the first string is the name of the value.
    ("ts", "k = @getValue(" + LONG + ")", False),
    ("ts", "k = @process.env[" + LONG + "]", False),
    ("ts", "k = @config.get<T>(" + LONG + ")", False),
    ("ts", "k = @config.get?.(" + LONG + ")", False),
    ("ts", "k = @requireEnv(" + LONG + ")", False),
    ("ts", "k = @headers[" + LONG + "]", False),
    ("ts", "k = @getValue(" + TICK + "xxxxxx/${a}/yyyyyy" + TICK + ")", False),
    ("go", "k = @os.Getenv(" + LONG + ")", False),
    ("go", "k = @viper.GetString(" + LONG + ")", False),
    ("go", "k = @mustValue(" + LONG + ")", False),
    ("java", "String k = @System.getenv(" + LONG + ");", False),
    ("sql", "SET k = @current_setting('xxxxxxxxxxxx')", False),
    # A later argument of a lookup is what the field gets when the lookup finds nothing.
    ("ts", "k = @getValue(a, " + LONG + ")", True),
    ("ts", "k = @getValue(" + LONG + ", " + LONG + ")", True),
    ("java", "String k = @props.getProperty(" + LONG + ", " + LONG + ");", True),
    # A call that hashes, encodes or wraps is handed the value itself, and so is an index into anything else.
    ("ts", "k = @hashValue(" + LONG + ")", True),
    ("ts", "k = @encoder.encode(" + LONG + ")", True),
    ("ts", "k = @String(" + LONG + ")", True),
    ("ts", "k = @store[" + LONG + "]", True),
    ("ts", "k = @build(a)(" + LONG + ")", True),
    ("ts", "k = @target(" + LONG + ")", True),        # "get" inside another word is not the word
    ("ts", "k = @budgetFor(" + LONG + ")", True),
    ("go", "k = @base64.StdEncoding.EncodeToString([]byte(" + LONG + "))", True),
    ("sql", "SET k = @pgp_sym_encrypt('xxxxxxxxxxxx', public_key)", True),
    # An operand is a value.
    ("ts", "k = @config.value || " + LONG, True),
    ("ts", "k = @config.value ?? " + LONG, True),
    ("ts", "k = @config.value + " + LONG, True),
    ("ts", "k = @flag ? a : " + LONG, True),
    ("ts", "k = @flag ? " + LONG + " : a", True),
    ("ts", "k = @config.value || (" + LONG + ")", True),
    ("ts", "k = @config.value || [" + LONG + "]", True),
    ("ts", "k = @config.value || " + TICK + "x" * 12 + TICK, True),
    ("ts", "k = @config.value || " + TICK + "xxxxxx${a}yyyyyy" + TICK, True),
    ("ts", "k = @config.value || " + TICK + "xxxxx${a}yyyyyy" + TICK, False),
    ("ts", "k = @config.value || 'xxxxxx' 'yyyyyy'", True),
    # A call that supplies a default takes its value as the first argument, whatever else its name says.
    ("ts", "k = @getValue(a).orElse(" + LONG + ")", True),
    ("ts", "k = @schema.default(" + LONG + ")", True),
    ("ts", "k = @getValue(a).getOrElse(" + LONG + ")", True),
    ("ts", "k = @getValue(a).unwrap_or(" + LONG + ")", True),
    # A lookup is told by its name, and every word of the name has to be a lookup word.
    ("ts", "k = @getSecretValue(" + LONG + ")", False),
    ("ts", "k = @vault.readSecret(" + LONG + ")", False),
    ("sql", "SELECT @current_setting(" + LONG.replace('"', "'") + ")", False),
    ("ts", "k = @getPasswordHash(" + LONG + ")", True),
    ("ts", "k = @Builder.withConfig(" + LONG + ").build()", True),
    ("ts", "k = @loadSeedFixture(" + LONG + ")", True),
    ("go", "k = @get_value_digest(" + LONG + ")", True),
    # Type arguments stand between a name and its bracket, and a comma inside them is not an end.
    ("ts", "k = @derive<A, B>(" + LONG + ")", True),
    ("kt", "val k = @derive<A, B>(" + LONG + ")", True),
    ("java", "String k = @Maker.<A, B>derive(" + LONG + ");", True),
    ("ts", "k = @config.get<Map<string, string>>(" + LONG + ")", False),
    ("ts", "k = @config.get<() => string>(" + LONG + ")", False),
    ("go", "k = @settings.Get[string](" + LONG + ")", False),
    ("go", "k = @handlers[0](" + LONG + ")", True),
    ("ts", "k = @count < limit ? a : b, other: " + LONG, True),   # a comparison is read on, never short
    # A line ends the expression only when it ends with an operand and the next code begins something new.
    ("ts", "k = @config.value\n  - 0 || " + LONG, True),
    ("ts", "k = @config.value\n  | 0 || " + LONG, True),
    ("ts", "k = @config.value\n  % 2 || " + LONG, True),
    ("ts", "k = @config.value /\n  2 || " + LONG, True),
    ("ts", "k = @config.value <\n  2 || " + LONG, True),
    ("ts", "k = @config.value\n  instanceof Object || " + LONG, True),
    ("ts", "k = @config.value\n  as string || " + LONG, True),
    ("ts", "k = @config.value\n  (" + LONG + ")", True),
    ("ts", "k = @config.value\n  [" + LONG + "]", True),
    ("ts", "k = @config.value\n" + LONG, True),
    ("ts", "k = @config.value\nother = " + LONG, False),
    ("ts", "k = @config.value!\nother = " + LONG, False),
    ("ts", "k = @config.value\n\n// a note\nother = " + LONG, False),
    ("ts", "k = { a: @config.value\n}\nother = " + LONG, False),
    ("ts", "if (ok) k = @config.value\nelse k = " + LONG, True),   # read on: the other branch has its own label
    ("go", "k = @config.Value\nother := " + LONG, False),
    ("kt", "val k = @config.value\n    ?: " + LONG, True),
    ("ts", "k = @config.value instanceof\n  Object || " + LONG, True),
    ("ts", "k = @config.value in\n  registry || " + LONG, True),
    ("ts", "k = @typeof\n  config.value || " + LONG, True),
    ("ts", "k = @config.value // instanceof\nother = " + LONG, False),   # a word in a comment is not code
    ("kt", "val k = @compute()\n{ " + LONG + " }", True),
    # A name longer than the reader keeps is not a lookup by its end alone.
    ("ts", "k = @" + "x" * 90 + "GetValue(" + LONG + ")", True),
    ("ts", "k = @" + "x" * 40 + "GetValue(" + LONG + ")", True),
    ("ts", "k = @getValue(" + LONG + ")", False),
    # Type arguments are counted as they are read, however long they are.
    ("ts", "k = @derive<T" + "x" * 90 + ", B>(" + LONG + ")", True),
    ("ts", "k = @derive<(a: A) => B, C>(" + LONG + ")", True),
    ("kt", "val k = @derive<(A) -> B, C>(" + LONG + ")", True),
    ("ts", "k = @derive<A>(first, " + LONG + ")", True),
    # The text of an error is not a value, at any place in the call.
    ("ts", "k = @config.value ?? fail(" + LONG + ")", False),
    ("ts", "k = @config.value ?? raise(new Error(" + LONG + "))", False),
    ("go", "k = @config.Value(log.Fatalf(" + LONG + ", name))", False),
    ("kt", "val k = @System.getenv(" + LONG + ") ?: error(" + LONG + ")", False),
    ("kt", "val k = @System.getenv(" + LONG + ") ?: " + LONG, True),
    ("java", "String k = @Objects.requireNonNull(System.getenv(" + LONG + "), " + LONG + ");", False),
    # A field of an object passed as an argument belongs to that object, not to the label.
    ("ts", "k = @createClient({ url: " + LONG + " })", False),
    ("ts", "k = @createClient(a, { url: " + LONG + " })", False),
    ("ts", "k = @flag || { value: " + LONG + " }.value", True),
    ("ts", "k = @createClient({ url: a, list: [" + LONG + "] })", True),
    ("ts", "k = @createClient({ inner: { url: " + LONG + " } })", True),
    ("ts", "k = @getValue(" + TICK + "${cond ? a : " + LONG + "}" + TICK + ")", True),
    ("go", "k = @Options{URL: " + LONG + "}", True),
    # SQL: a word after a complete value starts a new clause.
    ("sql", "SET k = @new_value WHERE note = 'xxxxxxxxxxxx'", False),
    ("sql", "SET k = @new_value || 'xxxxxxxxxxxx'", True),
    ("sql", "SET k = @crypt_value(a, 'xxxxxxxxxxxx')", True),
    ("sql", "SET k = @new_value ||\n  suffix AND note = 'xxxxxxxxxxxx'", False),
])
def test_what_an_expression_holds(suffix, text, expected):
    assert assigned(text, suffix) is expected


def test_an_expression_with_no_end_in_reach_is_unclear():
    text = "k = @getValue(" + "a, " * 2000 + LONG + ")\n" + "x = 1;\n" * 50
    assert assigned(text, "ts") is None
    assert assigned("k = @getValue(" + "a, " * 20, "ts") is False  # It ends with the file.
    assert assigned("k = @getValue(" + "a, " * 20 + LONG, "ts") is True


def test_slashes_before_a_position_on_its_line():
    text = "a = b / c; MARK\n// x / y\nd = /re/.test(e) && MARK2\nq = 1 /* a/b/c */ + MARK3"
    code = code_text(text, "x.ts")
    assert code.odd_slashes_before(text.index("MARK")) is True
    assert code.odd_slashes_before(text.index("MARK2")) is False
    assert code.odd_slashes_before(text.index("MARK3")) is False
    assert code_text("a = b / c -- MARK", "x.sql").odd_slashes_before(10) is False  # no such literals in SQL


@pytest.mark.parametrize("suffix,text,expected", [
    # A label and a bare value alone on a line, outside every bracket: a settings file reads the same.
    ("ts", "LABEL: value", False),
    ("ts", "LABEL = value;", False),
    ("ts", "  LABEL: value,", False),
    ("ts", "- LABEL: value", False),
    ("ts", "// const x\nLABEL = value", False),
    ("ts", '"LABEL": value', False),
    ("ts", "x = { a: 1 };\nLABEL: value", False),
    ("ts", "/* { */ LABEL: value", False),
    ("ts", "s = '{';\nLABEL: value", False),
    ("go", "LABEL = value", False),
    # Brackets that do not balance say nothing about where a label is.
    ("ts", "x = {\n  LABEL: value", False),
    ("ts", "}\nx = {\n  LABEL: value\n}", False),
    ("go", "func f() {\n\tif a {\n\t}\n\tLABEL = value\n", False),
    ("sql", "LABEL = value", False),
    ("sql", "UPDATE t SET a = 1;\nLABEL = value", False),
    ("sql", "-- UPDATE t SET\nLABEL = value", False),
    ("sql", "x = 'UPDATE t SET'\nLABEL = value", False),
    # Code in front of it on its line, or a bracket open around it.
    ("ts", "const LABEL = value;", True),
    ("ts", "this.LABEL = value;", True),
    ("ts", "x = {\n  LABEL: value\n}", True),
    ("ts", 'x = {\n  "LABEL": value\n}', True),
    ("ts", "f(\n  LABEL = value\n)", True),
    ("go", "func f() {\n\tLABEL = value\n}", True),
    ("go", "var LABEL = value", True),
    ("kt", "class A {\n  LABEL = value\n}", True),
    # In SQL, a keyword earlier in its statement.
    ("sql", "UPDATE t SET\n  a = 1,\n  LABEL = value", True),
    ("sql", "WHERE (\n  LABEL = value)", True),
    ("sql", ", LABEL = value", True),
])
def test_what_shows_that_a_label_is_part_of_a_program(suffix, text, expected):
    code = code_text(text, "src/sample." + suffix)
    assert code.written_as_code(text.index("LABEL")) is expected


# --- Expansions and nested keys ---------------------------------------------

@pytest.mark.parametrize("value", ["${NAME}", "${{ secrets.NAME }}", "{{ name | filter }}", "$(NAME)", "$(group.NAME)",
                                   "${var.name}", "${ssm:/path/to-it}", "${list[0].name}", "  ${NAME}  ", "${NAME:-}"])
def test_one_expansion(value):
    assert is_expansion(value) and is_expansion(value, in_shell=True)


@pytest.mark.parametrize("value", ["$(echo word)", "$(printf %s word)", "$(/bin/echo -n word)", "$(cat <<<word)",
                                   "$(cat ${FILE:-/run/word})", "$(true && printf word)"])
def test_a_command_that_prints_its_own_words_is_not_an_expansion(value):
    assert not is_expansion(value, in_shell=True) and not is_expansion(value)


@pytest.mark.parametrize("value", ["$NAME", "$name", "$Name_2", "$(cat file)", "$(vault kv get -field=value kv/x)"])
def test_a_dollar_without_braces_is_an_expansion_only_in_a_shell_scripts_double_quotes(value):
    assert is_expansion(value, in_shell=True) and not is_expansion(value)


@pytest.mark.parametrize("value", ["", "NAME", "${NAME:-word}", "${NAME-word}", "${NAME:=word}", "${NAME}x", "x${NAME}",
                                   "${A}${B}", "$(a)$(b)", "{{ a }}{{ b }}", "{NAME}", "$", "${}", "${NAME\n}", "$(a\nb)",
                                   "{{ a\nb }}", "${{ a }} }}", "${NAME:?word}", "${NAME:+word}", "$1", "${1}", "$NAME tail",
                                   "$(a) tail", "${NAME:- }"])
def test_not_one_expansion(value):
    assert not is_expansion(value) and not is_expansion(value, in_shell=True)


def test_a_nested_key_is_only_a_key_on_a_later_line_of_a_yaml_file():
    text = "label:\n  nested-key:\n    x: 1\n"
    start, end = text.index("nested"), text.index("nested") + len("nested-key:")
    assert nested_yaml_key(text, "a.yml", 5, start, end) and nested_yaml_key(text, "a/B.YAML", 5, start, end)
    assert not nested_yaml_key(text, "a.txt", 5, start, end) and not nested_yaml_key(text, None, 5, start, end)
    same_line = "label: nested-key:\n"
    assert not nested_yaml_key(same_line, "a.yml", 5, 7, 18)
    glued = "label:\n  nested-key:value\n"
    assert not nested_yaml_key(glued, "a.yml", 5, 9, 20)
    assert not nested_yaml_key(text, "a.yml", 5, start, end - 1)  # no colon: a scalar


def scalar_texts(text):
    starts, ends = yaml_block_scalars(text)
    return [text[start:end] for start, end in zip(starts, ends, strict=True)]


def test_lines_inside_a_yaml_block_scalar_are_text():
    assert scalar_texts("a: |\n  one\n\n  two\nb: 1\n") == ["  one\n\n  two\n"]
    assert scalar_texts("a: >-\n  one\nb: |+\n  two\n") == ["  one\n", "  two\n"]
    assert scalar_texts("a: |2 # why\n    one\nb: 1\n") == ["    one\n"]
    # In a list item the key's own column is what the text has to pass.
    assert scalar_texts("steps:\n  - run: |\n      one\n    name: x\n") == ["      one\n"]
    assert scalar_texts("steps:\n  - |\n    one\n  - two\n") == ["    one\n"]
    # A bar that is not an indicator opens nothing.
    assert scalar_texts("a: b |\n  c: 1\n# d: |\n  e: 1\nf: 'x |'\n") == []
    assert scalar_texts("a: |\n  never ends") == ["  never ends"]
    text = "deploy:\n  script: |\n    label:\n      nested-key:\n  other:\n    label:\n      nested-key:\n"
    first = text.index("nested-key:")
    second = text.index("nested-key:", first + 1)
    assert not nested_yaml_key(text, "a.yml", text.index("label:") + 5, first, first + 11)
    assert nested_yaml_key(text, "a.yml", text.index("label:", first) + 5, second, second + 11)


def test_a_block_scalar_behind_a_tag_or_an_anchor_is_found():
    for opener in ("script: !!str |", "script: &setup |", "script: !custom &both >-", "- !!str |", "- &item |2"):
        text = opener + "\n    line one\n    label:\n      word:\nafter: 1\n"
        starts, ends = yaml_block_scalars(text)
        assert (starts, ends) == ([len(opener) + 1], [text.index("after:")]), opener
    assert yaml_block_scalars("script: a & b |\n  x\n") == ([], [])  # an ampersand in a value is not an anchor


def test_a_block_comment_can_hold_another_where_the_language_says_so():
    text = "a /* one /* two */ three */ b 'x'"
    assert read(text, "sql") == [(COMMENT, "/* one /* two */ three */"), (STRING, "'x'")]
    assert read(text.replace("'", '"'), "kt") == [(COMMENT, "/* one /* two */ three */"), (STRING, '"x"')]
    assert read("a /* one /* two */ b 'x'".replace("'", '"'), "ts") == [(COMMENT, "/* one /* two */"), (STRING, '"x"')]
    assert code_text(text, "x.ts") is None  # There the comment ends at the first mark, and what is left is not code.
    assert code_text("a /* one /* two */ b", "x.sql") is None and code_text("a /* one /* two */ b", "x.kt") is None


# --- Hostile text -----------------------------------------------------------

PIECES = [LABEL + ": ", LABEL + " = ", "api_" + "key: ", "valueOfSomething", "process.env.NAME_OF_IT", "fetchValue(", ")", "(",
          "[", "]", "{", "}", "${", "$", TICK, '"', "'", '"""', "\\", "//", "/*", "*/", "--", "/", "<", ">", "</", "/>",
          "\n", "\r\n", " ", ",", ";", "||", "??", "?", ":", "+", ".", "=", "x" * 13, "0", "9" * 12, chr(0), chr(0x202E),
          "WHERE ", "é", "a"]


@pytest.mark.parametrize("seed", range(6))
def test_random_text_is_read_or_left_unclear_and_never_raises(seed):
    generator = random.Random(20261111 + seed)
    for _ in range(300):
        text = "".join(generator.choice(PIECES) for _ in range(generator.randrange(1, 60)))
        for suffix in ("ts", "js", "go", "java", "kt", "sql", "yml", "py", "md"):
            path = "src/sample." + suffix
            code = code_text(text, path)
            if code is not None:
                spans = code.spans()
                assert all(0 <= start <= end <= len(text) for start, end, _kind in spans)
                assert all(first[1] <= second[0] for first, second in zip(spans, spans[1:], strict=False))
                for position in range(0, len(text), 7):
                    if code.in_code(position):
                        assert code.literal_assigned(position, 12) in (True, False, None)
                        assert code.odd_slashes_before(position) in (True, False)
            try:
                check_text(text, source_path=path)
            except AssistantError as refusal:
                assert refusal.code in {"sensitive_content", "binary_input", "hidden_characters"}


def test_reading_with_a_path_never_accepts_what_a_quoted_literal_or_a_number_holds():
    """Whatever surrounds it, a quoted literal or a number under a credential label is refused."""
    generator = random.Random(20261111)
    literals = [LABEL + ': "' + "Zq7" * 5 + '"', LABEL + " = '" + "Zq7" * 5 + "'", LABEL + ": " + "9" * 12]
    safe = [piece for piece in PIECES if piece not in {'"', "'", '"""', "\\", chr(0)} and LABEL not in piece and "key" not in piece]
    for _ in range(400):
        before = "".join(generator.choice(safe) for _ in range(generator.randrange(0, 30)))
        after = "".join(generator.choice(safe) for _ in range(generator.randrange(0, 30)))
        for literal in literals:
            for suffix in ("ts", "go", "sql", "java", "kt", "yml"):
                with pytest.raises(AssistantError, match="^sensitive_content$"):
                    check_text(before + "\n" + literal + "\n" + after, source_path="src/sample." + suffix)


@pytest.mark.alone
def test_hostile_code_is_screened_in_bounded_time():
    # Timed inside the child, as in test_secret_scan_performance.py; the subprocess timeout stops a hang.
    code = """
from time import perf_counter
from finassist.security import check_text
from finassist.errors import AssistantError
label = "pass" + "word"
texts = [
    (label + ": valueOfSomething(" + "(" * 1900 + ")" * 1900 + "),\\n") * 100,       # deep, balanced, excused
    (label + ": valueOfSomething(" + "a, " * 1300 + "),\\n") * 100,                  # long argument lists
    (label + ": valueOfSomething\\n" + "\\n" * 1500 + "/**/" * 500 + "\\n") * 60,      # blank lines, then comments
    "x = 1 / 2; " * 30000 + (label + ": valueOfSomething; ") * 3000,               # one long line
    (label + ": valueOfSomething, ") * 20000,                                      # many short ones
    "`${" * 20000,                                                                 # nested templates, never closed
    "`${`" * 10000 + "`}`" * 10000,
    "(/[aaaaaaaaaa " * 28000 + "\\nconst x = {" + label + ": valueOfSomething};\\n",   # a slash before an unfinished class
    "/*c*/ " * 33000 + "/ " * 100000 + "\\nconst x = {" + label + ": valueOfSomething};\\n",
    "const x = {" + ("a / b, " + label + ": valueOfSomething, ") * 13000 + "};",     # one long line
    "const x = {" + (label + ": valueOfSomething, ") * 20000 + "};",
    "SELECT 1;\\n" + (label + " = valueOfSomething AND ") * 16000,
]
start = perf_counter()
for text in texts:
    for path in ("src/a.ts", "src/a.sql"):
        try:
            check_text(text, source_path=path)
        except AssistantError as exc:
            assert exc.code == "sensitive_content"
print(perf_counter() - start)
"""
    completed = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=600)
    # About a second and a half on a fast machine and ten times that on a slow hosted runner. The limit is
    # for a quadratic reading, which takes minutes on either.
    assert float(completed.stdout.strip()) < 60.0
