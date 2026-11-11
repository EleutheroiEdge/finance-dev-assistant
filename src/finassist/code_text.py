"""Tell a reference from a value, for the credential screen only.

In the languages listed here a string literal needs quotes. So a credential-named field followed
by an unquoted value, written in code, is being given an expression and not a value. The same
words inside a string or a comment are text, and the screen keeps its strict rules for them.
This module finds a file's strings and comments, and the strings inside an assigned expression.

It is not a parser. When a file does not read cleanly as its language, `code_text` returns None
and the caller screens the file as plain text, as it did before this module existed.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from pathlib import PurePosixPath
import re

STRING, COMMENT = "string", "comment"
# A string with ${ ... } in it is read in parts: up to the first one, between two, after the last.
WHOLE, HEAD, MIDDLE, TAIL = "whole", "head", "middle", "tail"
REGEX = "regex"  # a regular expression literal: text, but never a value a field would hold
# Characters read past the start of a value to find where its expression ends, and the work one
# file may take in total. Past either limit the answer is "unclear", never "code".
EXPRESSION_LIMIT = 4000
WORK_LIMIT = 1_000_000
_STEP = 8  # what one step of a Python loop costs, in characters read

_EXPANSION = re.compile(
    r"\$\{\{[^{}\n]*\}\}"                    # ${{ secrets.NAME }}
    r"|\{\{[^{}\n]*\}\}"                     # {{ name }}
    r"|\$\{[A-Za-z_][A-Za-z0-9_.\[\]]*(?::(?![-=+?])[A-Za-z0-9_./\[\]-]*)?\}"  # ${NAME}, ${var.name}, ${ssm:/path}
    r"|\$[A-Z_][A-Z0-9_]*"                   # $NAME, in upper case: a password can start with a dollar
    r"|\$\([^()\n]*\)"                       # $(command)
)


_NESTED_KEY = re.compile(r"[A-Za-z0-9_.-]+:")
YAML_SUFFIXES = frozenset({".yml", ".yaml"})


def nested_yaml_key(text: str, path: str | None, separator: int, start: int, end: int) -> bool:
    """True when the "value" a label rule matched is the first key of a mapping under the label.

    That is a key on a later line than the label's separator, ending in a colon that a space or
    the end of the line follows. YAML reads those words as a key whatever they spell.
    """
    return (path is not None and PurePosixPath(path).suffix.lower() in YAML_SUFFIXES
            and "\n" in text[separator:start] and _NESTED_KEY.fullmatch(text, start, end) is not None
            and (end == len(text) or text[end].isspace()))


def is_expansion(value: str) -> bool:
    """True when the whole value is one variable or command expansion.

    An expansion names a value that is kept somewhere else. One with a default written into it,
    such as ${NAME:-word} or ${NAME-word}, is not matched, and neither is a dollar before a name
    with a lower-case letter: without braces that is also how a password can be spelled.
    """
    return _EXPANSION.fullmatch(value.strip()) is not None


class _Unclear(Exception):
    """The file does not read cleanly as this language, or reading it took too long."""


@dataclass(frozen=True)
class Language:
    """How one family of languages writes comments and strings. All of them use /* ... */."""

    line_comment: str
    block_strings: tuple[str, ...]         # delimiters of strings that can span lines
    line_strings: str = "\"'"              # quotes of strings that end on their line, with backslash escapes
    block_escapes: bool = True             # a backslash escapes the next character in a block string
    interpolation: bool = False            # ${ ... } inside a block string holds code
    words_end_values: bool = False         # a word after a complete value starts a new clause, as in SQL
    backslash_quote_unclear: bool = False  # dialects disagree on a backslash before a quote
    markup: tuple[str, ...] = ()           # in code, these mean the file holds markup with unquoted text
    regex_literals: bool = False           # /.../ can hold unquoted text
    data: bool = False                     # SQL: COPY rows, client commands and dollar-quoted strings


_SCRIPT = Language("//", ("`",), interpolation=True, markup=("</", "/>"), regex_literals=True)
_GO = Language("//", ("`",), block_escapes=False)
_JAVA = Language("//", ('"""',))
_KOTLIN = Language("//", ('"""',), block_escapes=False)
_SQL = Language("--", ("'", '"'), line_strings="", block_escapes=False, words_end_values=True,
                backslash_quote_unclear=True, data=True)
# JSX files are left out on purpose: the text between two tags is not quoted, so an unquoted value
# there can be a literal. They keep the strict text rules, and so does a script that holds a
# closing or self-closing tag.
LANGUAGES = {
    ".js": _SCRIPT, ".mjs": _SCRIPT, ".cjs": _SCRIPT, ".ts": _SCRIPT, ".mts": _SCRIPT, ".cts": _SCRIPT,
    ".go": _GO, ".java": _JAVA, ".kt": _KOTLIN, ".kts": _KOTLIN, ".sql": _SQL,
}

_LINE_BODY = {
    '"': re.compile(r'(?:[^"\\\r\n]|\\[^\r\n])*'),
    "'": re.compile(r"(?:[^'\\\r\n]|\\[^\r\n])*"),
}
_LINE_END = re.compile(r"[^\r\n]*")
# Unquoted text in a SQL file: the rows after COPY ... FROM stdin, a client command such as
# \connect, and a dollar-quoted string. A dollar-quoted body after AS or DO is code.
_COPY_ROWS = r"(?i:\bfrom\s+stdin\b[^;\n]*;)"
_CLIENT_COMMAND = r"(?m:^[ \t]*\\)"
_DOLLAR_TAG = r"\$[A-Za-z_]*\$"
_BODY_BEFORE = re.compile(r"(?i)\b(?:as|do)\s*$")
_SPACE = re.compile(r"\s*")
_OPENING, _CLOSING = "([{", ")]}"
_INTERPOLATION = "${"
# An operator at the end of a line, or at the start of the next, carries an expression across it.
_TRAILING = frozenset("|&?:+=.")
_LEADING = frozenset("|&?:+.")
_SQL_OPERATORS = frozenset("|+-*/%=<>,(")
# What can come directly before the bracket of a call or an index: a name, a closing bracket, or
# the end of a generic or optional call. A bracket after an operator only groups.
_CALLEE_END = frozenset("_$)]>.")
_AFTER_STRING = '"'  # stands for a whole string in the record of what came before
# A slash starts a regular expression after one of these characters or words, and at the start of
# the file. After a name, a number, a string or a closing bracket it divides. A less-than sign is
# left out on purpose: with a slash it closes a tag, which has_markup has to see.
_BEFORE_REGEX = frozenset("(,=:[!&|?{};+-*%>~^}")
# Characters one regular expression may span. Without a bound, every slash before an unfinished
# class would be read to the end of its line, and a long line of them would take quadratic time.
_REGEX_REACH = 1000
_WORDS_BEFORE_REGEX = frozenset({"return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "do", "else",
                                 "yield", "await", "instanceof"})
_REGEX_REST = re.compile(r"(?:[^/\\\[\r\n]|\\[^\r\n]|\[(?:[^\]\\\r\n]|\\[^\r\n])*\])+/[A-Za-z]*")
_BRACKET = re.compile(r"[()\[\]{}]")
# Code in front of a label on its line that only a program has: a keyword or an owner, or a bracket.
_PROGRAM = re.compile(r"[A-Za-z_$.,(){}\[\]]")
_STATEMENT_REACH = 2000  # characters read back from a label to find the start of its statement
_LINE_REACH = 400  # and along its line, which in generated code can be the whole file
_SQL_WORD = re.compile(
    r"(?i)\b(?:select|insert|update|delete|set|where|values|and|or|on|using|when|then|else|if|return|returning|declare"
    r"|begin|check|default|from|join|with|create|alter|grant|merge|call|perform|execute|into)\b")
_CONTEXT = 24  # code characters kept in front of a string, spaces dropped
# A call whose first argument is what the field receives when the lookup finds nothing.
_GIVES_DEFAULT = re.compile(
    r"(?i)(?<![A-Za-z0-9_$])(?:orelse|getorelse|unwrapor|unwrap_or|default|defaultvalue|withdefault|fallback)\($")


def _alternation(parts: list[str]) -> re.Pattern:
    return re.compile("|".join(parts), re.DOTALL)


class _Reader:
    """The patterns for one language, built once."""

    def __init__(self, language: Language):
        self.language = language
        blocks = sorted(language.block_strings, key=len, reverse=True)
        opener = [re.escape("/*"), re.escape(language.line_comment), *map(re.escape, blocks),
                  *map(re.escape, language.line_strings)]
        if language.interpolation:
            opener.append("[{}]")
        if language.data:
            opener += [_COPY_ROWS, _CLIENT_COMMAND, _DOLLAR_TAG]
        if language.regex_literals:
            opener.append("/")  # tried after the two comment marks, which begin with a slash too
        self.opener = _alternation(opener)
        # A mark with a backslash before its slash is part of a regular expression, not a tag.
        self.markup = re.compile(r"(?<!\\)(?:%s)" % "|".join(map(re.escape, language.markup))) if language.markup else None
        self.block_end = {}
        for mark in blocks:
            parts = [re.escape(mark)]
            if language.block_escapes:
                parts.insert(0, r"\\.")  # with DOTALL: a backslash and whatever follows it
            if language.interpolation:
                parts.append(r"\$\{")
            self.block_end[mark] = _alternation(parts)
        structure = [r"[()\[\]{},;\n]"]
        if language.words_end_values:
            structure.append(r"[ \t]+(?=[A-Za-z_])")
        self.structure = _alternation(structure)

    def spans(self, text: str) -> list[tuple[int, int, str, int, str]]:
        """Every string and comment as (start, end, kind, characters inside, part), in order."""
        language, spans = self.language, []
        depths: list[int] = []  # open braces inside each ${ ... } being read, innermost last
        bodies: list[str] = []  # dollar tags of the code bodies being read, innermost last
        position = 0
        while True:
            found = self.opener.search(text, position)
            if found is None:
                break
            piece, start = found.group(), found.start()
            if language.data and piece not in self.block_end and piece not in ("/*", language.line_comment):
                position = self._data(text, found, spans, bodies)
            elif piece == "/*":
                end = text.find("*/", start + 2)
                if end < 0:
                    raise _Unclear
                spans.append((start, end + 2, COMMENT, 0, WHOLE))
                position = end + 2
            elif piece == language.line_comment:
                position = _LINE_END.match(text, start).end()
                spans.append((start, position, COMMENT, 0, WHOLE))
            elif piece == "/":
                end = self._regex_end(text, start, spans)
                if end is None:
                    position = start + 1  # a division sign
                else:
                    spans.append((start, end, STRING, 0, REGEX))
                    position = end
            elif piece == "{":
                if depths:
                    depths[-1] += 1
                position = start + 1
            elif piece == "}":
                position = start + 1
                if depths:
                    if depths[-1]:
                        depths[-1] -= 1
                    else:  # The end of ${ ... }: the block string goes on.
                        depths.pop()
                        position = self._block(text, position, position, language.block_strings[0], spans, depths,
                                               resumed=True)
            elif piece in self.block_end:
                position = self._block(text, start, start + len(piece), piece, spans, depths, resumed=False)
            else:
                end = _LINE_BODY[piece].match(text, start + 1).end()
                if text[end:end + 1] != piece:
                    raise _Unclear  # It runs to the end of its line, so it is not a string we know.
                spans.append((start, end + 1, STRING, end - start - 1, WHOLE))
                position = end + 1
        if depths or bodies:
            raise _Unclear
        return spans

    @staticmethod
    def _data(text: str, found: re.Match, spans: list, bodies: list[str]) -> int:
        """Read one piece of SQL that is not code; return where reading code resumes."""
        piece, start = found.group(), found.start()
        if piece.startswith("$"):
            if bodies and bodies[-1] == piece:
                bodies.pop()  # the end of a body that was read as code
                return found.end()
            if _BODY_BEFORE.search(text, max(0, start - 40), start):
                bodies.append(piece)  # a function body or a DO block: code, up to the same tag
                return found.end()
            end = text.find(piece, found.end())
            if end < 0:
                raise _Unclear
            spans.append((start, end + len(piece), STRING, end - found.end(), WHOLE))
            return end + len(piece)
        if piece.endswith(";"):  # COPY ... FROM stdin; and its rows, up to the line that ends them
            end = text.find("\n\\.", found.end())
            if end < 0:
                raise _Unclear
            spans.append((found.end(), end + 3, STRING, 0, WHOLE))
            return end + 3
        end = _LINE_END.match(text, found.end()).end()  # a client command: its line
        spans.append((start, end, STRING, 0, WHOLE))
        return end

    @staticmethod
    def _regex_end(text: str, start: int, spans: list) -> int | None:
        """Where the regular expression that starts with the slash at `start` ends, or None for a division sign.

        What stands before the slash decides, as it does for the language itself. A regular
        expression ends on its line and within _REGEX_REACH characters; a slash with no partner
        there is a division sign after all.
        """
        index, last = start - 1, len(spans) - 1
        while index >= 0:
            if last >= 0 and spans[last][1] == index + 1:
                if spans[last][2] != COMMENT:
                    return None  # after a string or another regular expression
                index, last = spans[last][0] - 1, last - 1  # a comment says nothing: look before it
            elif text[index].isspace():
                index -= 1
            else:
                break
        if index >= 0 and text[index] not in _BEFORE_REGEX:
            word = index
            while word >= 0 and index - word < 12 and (text[word].isalnum() or text[word] in "_$"):
                word -= 1
            if text[word + 1:index + 1] not in _WORDS_BEFORE_REGEX:
                return None
        found = _REGEX_REST.match(text, start + 1, min(len(text), start + 1 + _REGEX_REACH))
        return found.end() if found else None

    def _block(self, text: str, start: int, body: int, mark: str, spans: list, depths: list[int], *,
               resumed: bool) -> int:
        """Read a block string whose text begins at `body`; return where reading code resumes."""
        pattern, position = self.block_end[mark], body
        while True:
            found = pattern.search(text, position)
            if found is None:
                raise _Unclear
            piece = found.group()
            if piece == mark:
                spans.append((start, found.end(), STRING, found.start() - body, TAIL if resumed else WHOLE))
                return found.end()
            if piece == _INTERPOLATION:
                spans.append((start, found.start(), STRING, found.start() - body, MIDDLE if resumed else HEAD))
                depths.append(0)
                return found.end()
            position = found.end()  # an escaped character


_READERS = {language: _Reader(language) for language in set(LANGUAGES.values())}


@dataclass
class _Literal:
    """One string inside an expression, with what the code around it says about its role."""

    size: int
    before: str  # the code in front of it, spaces dropped: the last few characters
    inside: str  # the innermost bracket of the expression that is open around it, or ""


class CodeText:
    """One file's strings and comments, and the questions the credential screen asks of them."""

    def __init__(self, text: str, reader: _Reader, spans: list[tuple[int, int, str, int, str]]):
        self._text = text
        self._reader = reader
        self._starts = [span[0] for span in spans]
        self._ends = [span[1] for span in spans]
        self._kinds = [span[2] for span in spans]
        self._sizes = [span[3] for span in spans]
        self._parts = [span[4] for span in spans]
        self._work = 0
        self._brackets: tuple[list[int], list[int]] | None = None  # where each bracket is, and the depth after it

    def spans(self) -> list[tuple[int, int, str]]:
        """Every string and comment as (start, end, kind), in order."""
        return list(zip(self._starts, self._ends, self._kinds, strict=True))

    def _spend(self, amount: int) -> None:
        self._work += amount
        if self._work > WORK_LIMIT:
            raise _Unclear

    def _span_at(self, position: int) -> int | None:
        index = bisect_right(self._starts, position) - 1
        return index if index >= 0 and position < self._ends[index] else None

    def in_code(self, position: int) -> bool:
        """True when the character at `position` is neither in a string nor in a comment."""
        return self._span_at(position) is None

    def _code(self, start: int, end: int) -> str:
        """The text from `start` to `end` with strings and comments left out."""
        pieces, index = [], bisect_right(self._starts, start) - 1
        if index >= 0 and self._ends[index] > start:
            start = self._ends[index]
        index += 1
        while start < end:
            stop = min(end, self._starts[index]) if index < len(self._starts) else end
            pieces.append(self._text[start:stop])
            if stop == end:
                break
            start = self._ends[index]
            index += 1
        return "".join(pieces)

    def _depth(self, position: int) -> int:
        """How many brackets are open in code before `position`.

        Zero everywhere when the file's brackets do not balance: one that is never closed would
        otherwise put the rest of the file inside it.
        """
        if self._brackets is None:
            places, depths, depth, start, balanced = [], [], 0, 0, True
            for end, resume in zip([*self._starts, len(self._text)], [*self._ends, len(self._text)], strict=True):
                for found in _BRACKET.finditer(self._text, start, end):
                    depth += 1 if found.group() in _OPENING else -1
                    balanced = balanced and depth >= 0
                    places.append(found.start())
                    depths.append(depth)
                start = resume
            self._brackets = (places, depths) if balanced and depth == 0 else ([], [])
        places, depths = self._brackets
        index = bisect_right(places, position - 1) - 1
        return depths[index] if index >= 0 else 0

    def written_as_code(self, start: int) -> bool:
        """True when the code around a label at `start` shows that it is part of a program.

        A label and a bare value alone on a line, outside every bracket, read the same in a
        settings file saved under this suffix, where the value is a literal. So one of these has
        to hold: a bracket is open around the label; code stands in front of it on its line, such
        as a keyword or the object it belongs to; or, in SQL, a keyword stands earlier in its
        statement.
        """
        span = self._span_at(start)
        if span is not None:
            start = self._starts[span]  # a quoted key: from its opening quote
        if self._depth(start) > 0:
            return True
        line = max(self._text.rfind("\n", 0, start) + 1, start - _LINE_REACH)
        if _PROGRAM.search(self._code(line, start)):
            return True
        if not self._reader.language.words_end_values:
            return False
        statement = self._code(max(0, start - _STATEMENT_REACH), start)
        return _SQL_WORD.search(statement, statement.rfind(";") + 1) is not None

    def has_markup(self) -> bool:
        """True when the file holds one of the language's markup marks, such as a closing tag.

        Strings and comments are not searched. Of what was read as a regular expression only the
        two slashes count, because the slash of a tag can be taken for either: the first when a
        closing bracket follows it, the second when an opening bracket stands before it or a
        closing one after it. A regular expression of one character, as in replacing every "<",
        is left alone.
        """
        pattern, text, start = self._reader.markup, self._text, 0
        if pattern is None:
            return False
        for index, span in enumerate(self._starts):
            if pattern.search(text, start, span):
                return True
            start = end = self._ends[index]
            if self._parts[index] == REGEX:
                close = text.rfind("/", span, end)
                if close - span > 2 and (text[span + 1] == ">" or (text[close - 1] == "<" and text[close - 2] != "\\")
                                         or (close + 1 == end and text.startswith(">", end))):
                    return True
        return pattern.search(text, start) is not None

    def odd_slashes_before(self, position: int) -> bool:
        """True when an odd number of slashes stands in code just before `position` on its line.

        In a language with regular expression literals that can mean `position` is inside one,
        where the words are text. Only as far back as one can reach is counted. A lone division
        sign gives the same answer, and so does running out of the work limit. `position` must
        be in code.
        """
        if not self._reader.language.regex_literals:
            return False
        text = self._text
        cursor = max(text.rfind("\n", 0, position) + 1, position - _REGEX_REACH)
        index = bisect_right(self._starts, cursor) - 1
        if index >= 0 and self._ends[index] > cursor:
            cursor = self._ends[index]  # The line begins inside a string or a comment.
        index += 1
        count = 0
        try:
            while cursor < position:
                stop = min(position, self._starts[index]) if index < len(self._starts) else position
                self._spend(_STEP + (stop - cursor) // 32)  # one count over a short stretch
                count += text.count("/", cursor, stop)
                if stop == position:
                    break
                cursor = self._ends[index]
                index += 1
        except _Unclear:
            return True
        return count % 2 == 1

    def _strings(self, start: int) -> list[_Literal]:
        """The strings inside the expression that starts at `start`, which must be in code.

        The expression ends at a comma, a semicolon or a closing bracket that it did not open, or
        at the end of a line that no operator carries on. Raises _Unclear when no end is found
        within the limits.
        """
        text, structure = self._text, self._reader.structure
        size = len(text)
        limit = min(size, start + EXPRESSION_LIMIT)
        index = bisect_right(self._starts, start)
        position, before, interpolation = start, "", -1
        open_brackets: list[str] = []
        strings: list[_Literal] = []
        templates: list[_Literal] = []  # strings with ${ ... } whose last part is still to come
        while True:
            span = self._starts[index] if index < len(self._starts) else size
            stop = min(limit, span)
            found = structure.search(text, position, stop)
            end = found.start() if found else stop
            self._spend(end - position + _STEP)
            before = (before + "".join(text[position:end].split()))[-_CONTEXT:]
            if found is None:
                if span >= limit:  # Nothing more to read before the limit.
                    if limit < size:
                        raise _Unclear
                    return strings
                if self._kinds[index] == STRING:
                    part, length = self._parts[index], self._sizes[index]
                    if part == REGEX:
                        pass  # not a value a credential field would hold
                    elif part in (MIDDLE, TAIL):
                        if templates:  # Otherwise its first part came before this expression.
                            templates[-1].size += length
                            if part == TAIL:
                                templates.pop()
                    elif part == WHOLE and before[-1:] == _AFTER_STRING and strings:
                        strings[-1].size += length  # two strings side by side are one value
                    else:
                        strings.append(_Literal(length, before, open_brackets[-1] if open_brackets else ""))
                        if part == HEAD:
                            templates.append(strings[-1])
                    if part in (HEAD, MIDDLE):
                        interpolation = self._ends[index] + 1  # where the brace of its ${ is
                    else:
                        before = (before + _AFTER_STRING)[-_CONTEXT:]
                position = self._ends[index]
                index += 1
                if position >= limit:
                    if position < size:
                        raise _Unclear
                    return strings
                continue
            piece = found.group()
            position = found.end()
            if piece in _OPENING:
                open_brackets.append(_INTERPOLATION if found.start() == interpolation else piece)
            elif piece in _CLOSING:
                if not open_brackets:
                    return strings
                open_brackets.pop()
            elif piece in ",;":
                if not open_brackets:
                    return strings
            elif piece == "\n":
                if not open_brackets and not self._continues(before, position, limit):
                    return strings
                continue
            else:  # Space before a word, in a language where a word starts a new clause.
                if not open_brackets and before[-1:] not in _SQL_OPERATORS:
                    return strings
                continue
            before = (before + piece)[-_CONTEXT:]

    def _continues(self, before: str, position: int, limit: int) -> bool:
        if before[-1:] in _TRAILING:
            return True
        while position < limit:
            self._spend(_STEP)
            position = _SPACE.match(self._text, position, limit).end()
            span = self._span_at(position)
            if span is None or self._kinds[span] != COMMENT:
                break
            position = self._ends[span]
        return position < limit and self._text[position] in _LEADING

    def literal_assigned(self, start: int, minimum: int) -> bool | None:
        """Whether the expression at `start` holds a string of `minimum` characters or more.

        Two kinds of string do not count, because they are not what the field receives. One is
        the first argument of a call, or a key in brackets: it names where the value comes from.
        The other is the value of another field inside braces. Every other string counts: a later
        argument, one after an operator, or the argument of a call that supplies a default is
        what the field gets when the lookup finds nothing.

        None means unclear, and the caller then treats the value as text.
        """
        try:
            strings = self._strings(start)
        except _Unclear:
            return None
        for literal in strings:
            if literal.size < minimum:
                continue
            before = literal.before
            if (before[-1:] in ("(", "[") and (before[-2:-1].isalnum() or before[-2:-1] in _CALLEE_END)
                    and not _GIVES_DEFAULT.search(before)):
                continue
            if literal.inside == "{" and before[-1:] == ":":
                continue
            return True
        return False


def code_text(text: str, path: str | None) -> CodeText | None:
    """The strings and comments of a file in a language this module reads, or None."""
    language = LANGUAGES.get(PurePosixPath(path).suffix.lower()) if path else None
    if language is None or "\0" in text:
        return None
    if language.backslash_quote_unclear and ("\\'" in text or '\\"' in text):
        return None
    reader = _READERS[language]
    try:
        code = CodeText(text, reader, reader.spans(text))
    except _Unclear:
        return None
    return None if code.has_markup() else code
