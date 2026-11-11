"""Telling code from text in a source file (#96): what is read, and what is left unclear.

Synthetic text only. No string here pairs a credential label with a value.
"""
import random
import subprocess
import sys

import pytest

from finassist.code_text import COMMENT, STRING, LANGUAGES, code_text, is_expansion, nested_yaml_key
from finassist.errors import AssistantError
from finassist.security import check_text

TICK = "`"
LABEL = "pass" + "word"


def read(text, suffix):
    code = code_text(text, "src/sample." + suffix)
    return None if code is None else [(kind, text[start:end]) for start, end, kind in code.spans()]


def assigned(text, suffix, marker="VALUE"):
    """What `literal_assigned` says about the expression that starts at the marker."""
    code = code_text(text, "src/sample." + suffix)
    assert code is not None, "the text must read cleanly"
    return code.literal_assigned(text.index(marker), 12)


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
    # A slash with no partner on its line divides after all.
    ('a = b +\n  / c; e = "s";', ['"s"']),
    # An escaped slash before a bracket is part of a regular expression, not a tag.
    ('tidy = s.replace(/<br\\s*\\/>/g, "x");', ["/<br\\s*\\/>/g", '"x"']),
    # Neither is a bracket inside one, or one that is the whole of it.
    ('safe = s.replace(/</g, "&lt;").replace(/>/g, "&gt;");', ["/</g", '"&lt;"', "/>/g", '"&gt;"']),
    ("tag = /<[^/>]+>/.exec(s);", ["/<[^/>]+>/"]),
    ("open = /^\\</.test(s);", ["/^\\</"]),
])
def test_a_regular_expression_in_a_script_is_text(text, expected):
    assert [piece for _kind, piece in read(text, "ts")] == expected


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
    # No string, or only a short one.
    ("ts", "k: VALUE.b.c,", False),
    ("ts", "k: VALUE(a, b),", False),
    ("ts", "k: VALUE || " + SHORT + ",", False),
    # The end: a comma, a semicolon, a closing bracket it did not open, or the end of a line.
    ("ts", "k: VALUE, other: " + LONG, False),
    ("ts", "k = VALUE; other = " + LONG, False),
    ("ts", "f({ k: VALUE }, " + LONG + ")", False),
    ("ts", "k = VALUE\nother = " + LONG, False),
    ("go", "k = VALUE\nother = " + LONG, False),
    # What carries it over a line: an operator at the end, or at the start of the next.
    ("ts", "k = VALUE ||\n  " + LONG, True),
    ("ts", "k = VALUE\n  ?? " + LONG, True),
    ("ts", "k = VALUE // why\n  // more\n  || " + LONG, True),
    ("ts", "k = VALUE ?\n a :\n " + LONG, True),
    ("ts", "k = VALUE\n  .trim()\n  .concat(" + LONG + ")", False),
    # Inside its own brackets a line break ends nothing.
    ("ts", "k = VALUE(\n  a,\n  " + LONG + ",\n)", True),
    ("ts", "k = VALUE(\n  " + LONG + ",\n)", False),
    # The first argument of a call and a key name a source; later arguments and operands are values.
    ("ts", "k = VALUE(" + LONG + ")", False),
    ("ts", "k = VALUE[" + LONG + "]", False),
    ("ts", "k = VALUE<T>(" + LONG + ")", False),
    ("ts", "k = VALUE?.(" + LONG + ")", False),
    ("ts", "k = VALUE(a)(" + LONG + ")", False),
    ("ts", "k = VALUE(a, " + LONG + ")", True),
    ("ts", "k = VALUE || " + LONG, True),
    ("ts", "k = VALUE ?? " + LONG, True),
    ("ts", "k = VALUE + " + LONG, True),
    ("ts", "k = VALUE ? a : " + LONG, True),
    ("ts", "k = VALUE ? " + LONG + " : a", True),
    ("ts", "k = VALUE || (" + LONG + ")", True),
    ("ts", "k = VALUE || [" + LONG + "]", True),
    ("ts", "k = VALUE || " + TICK + "x" * 12 + TICK, True),
    ("ts", "k = VALUE || " + TICK + "xxxxxx${a}yyyyyy" + TICK, True),
    ("ts", "k = VALUE || " + TICK + "xxxxx${a}yyyyyy" + TICK, False),
    ("ts", "k = VALUE(" + TICK + "xxxxxx/${a}/yyyyyy" + TICK + ")", False),
    ("ts", "k = VALUE || 'xxxxxx' 'yyyyyy'", True),
    # A call that supplies a default takes its value as the first argument.
    ("ts", "k = VALUE(a).orElse(" + LONG + ")", True),
    ("ts", "k = VALUE.default(" + LONG + ")", True),
    ("ts", "k = VALUE(a).getOrElse(" + LONG + ")", True),
    ("ts", "k = VALUE(a).unwrap_or(" + LONG + ")", True),
    ("ts", "k = VALUE(a).setDefault(" + LONG + ")", False),
    ("ts", "k = VALUE ?? fail(" + LONG + ")", False),
    # Another field's value, inside braces the expression opened.
    ("ts", "k = VALUE({ url: " + LONG + " })", False),
    ("ts", "k = VALUE({ url: a, list: [" + LONG + "] })", True),
    ("ts", "k = VALUE(" + TICK + "${cond ? a : " + LONG + "}" + TICK + ")", True),
    ("go", "k = VALUE{URL: " + LONG + "}", False),
    # SQL: a word after a complete value starts a new clause.
    ("sql", "SET k = VALUE WHERE note = 'xxxxxxxxxxxx'", False),
    ("sql", "SET k = VALUE || 'xxxxxxxxxxxx'", True),
    ("sql", "SET k = VALUE(a, 'xxxxxxxxxxxx')", True),
    ("sql", "SET k = VALUE('xxxxxxxxxxxx')", False),
    ("sql", "SET k = VALUE ||\n  suffix AND note = 'xxxxxxxxxxxx'", False),
    ("kt", "val k = VALUE(" + LONG + ") ?: " + LONG, True),
    ("kt", "val k = VALUE(" + LONG + ") ?: error(" + LONG + ")", False),
    ("java", "String k = VALUE(" + LONG + ", " + LONG + ");", True),
])
def test_what_an_expression_holds(suffix, text, expected):
    assert assigned(text, suffix) is expected


def test_an_expression_with_no_end_in_reach_is_unclear():
    text = "k = VALUE(" + "a, " * 2000 + LONG + ")\n" + "x = 1;\n" * 50
    assert assigned(text, "ts") is None
    assert assigned("k = VALUE(" + "a, " * 20, "ts") is False  # It ends with the file.
    assert assigned("k = VALUE(" + "a, " * 20 + LONG, "ts") is True


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

@pytest.mark.parametrize("value", ["${NAME}", "$NAME", "${{ secrets.NAME }}", "{{ name | filter }}", "$(cat file)",
                                   "${var.name}", "${ssm:/path/to-it}", "${list[0].name}", "  ${NAME}  "])
def test_one_expansion(value):
    assert is_expansion(value)


@pytest.mark.parametrize("value", ["", "NAME", "$name", "$uperWord12", "$Name", "${NAME:-word}", "${NAME-word}", "${NAME:=word}", "${NAME}x", "x${NAME}",
                                   "${A}${B}", "$(a)$(b)", "{{ a }}{{ b }}", "{NAME}", "$", "${}", "${NAME\n}", "$(a\nb)",
                                   "{{ a\nb }}", "${{ a }} }}", "${NAME:?word}", "${NAME:+word}", "$1", "${1}"])
def test_not_one_expansion(value):
    assert not is_expansion(value)


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
                assert refusal.code in {"sensitive_content", "binary_input"}


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
]
start = perf_counter()
for text in texts:
    for path in ("src/a.ts", "src/a.go", "src/a.sql", "src/a.kt"):
        try:
            check_text(text, source_path=path)
        except AssistantError as exc:
            assert exc.code == "sensitive_content"
print(perf_counter() - start)
"""
    completed = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=60)
    assert float(completed.stdout.strip()) < 8.0
