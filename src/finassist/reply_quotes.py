"""Where a quote in a model's reply ends: what may follow a reference that the reply repeats.

A reply may repeat a reference from screened source, such as a field set from the environment.
`security.check_output_document` finds each such quote and blanks it before the label rules
read the reply. These rules decide whether the quote may be blanked: only when nothing after it
can give its label another value. A quote that fails stays, and the label rules refuse it.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
import re
from typing import NamedTuple

from .code_text import MIN_SECRET_LENGTH

# In prose, after the code span that held a quote, the reply is read on to the end of its clause:
# the first comma or semicolon outside the brackets opened on the way, the first closing bracket
# that nothing opened, or the end of the reply. Up to there only plain prose may stand: nothing
# that can begin a string, a comment or type arguments, and no long number. So no literal can
# follow the quote, whatever sign or word stands before it, and nothing can hide where the clause
# ends. Two things are plain though they hold a backtick: a code span too short to be a credential,
# with no escape, quote mark, dollar or brace in it, and a span that holds another quote.
# A string begins with a quote mark or a backtick, or in SQL with a dollar tag, spelled as the reader
# of source spells it. A number is counted with the point it may begin with, as it is in source.
_CLAUSE = re.compile(
    r"(?P<plain>`[^`\\\"'${}\n]{0," + str(MIN_SECRET_LENGTH - 1) + r"}`)"
    r"|(?P<end>[,;])|(?P<open>[(\[{])|(?P<close>[)\]}])"
    r"|(?P<refused>[\"'`/\\#<]|--|\$(?:[^\W\d]\w*)?\$"
    r"|(?<![A-Za-z0-9_$.])(?:\.[0-9][0-9A-Za-z_.]{" + str(MIN_SECRET_LENGTH - 2) + r",}"
    r"|[0-9][0-9A-Za-z_.]{" + str(MIN_SECRET_LENGTH - 1) + r",}))")
_CLAUSE_REACH = 4000  # characters read after a span for the end of its clause
_CLAUSE_PARTS = 400  # and the brackets and short spans read in them
_PATCH_MARK = re.compile(r"(?<=\n)[+\- ]")  # the mark that begins each further line of a patch
_LINE_BREAK = re.compile(r"\n")
_VALUE_MARK = re.compile(r"[\"'=]")
_BLANK = re.compile(r"[ \t\r]*")
# A quote that stops inside a bracket or a string it opened is not a whole expression.
_WHOLE_STRING = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\\n]|\\.)*`")
# A quote that ends with one of these is a whole operand. One that ends with an operator is not
# over, whatever follows it.
_QUOTE_END = re.compile(r"[A-Za-z0-9_$)\]}\"'!,;]")
# In code, the line after a quote that ends its line has to begin something new: a name that is no
# operator, a closing bracket, a quoted key, or the end of a fenced block. Anything else may carry
# the expression on, whatever the operator. The words are those the reader of source knows, and
# the ones Python has; a test holds the two lists together.
_BEGINS_NEW = re.compile(
    r"```|[)\]}\"']|(?!(?:in|instanceof|as|satisfies|is|else|extends|or|and|not)\b)[A-Za-z_$@]")
_COMMENT_LINE = re.compile(r"//|#|--")
_PATCH_NOTE = "\\ No newline at end of file"


class Reply(NamedTuple):
    """One string of model output as the rules for a quote read it, worked out once for all its quotes."""

    value: str  # as written
    text: str  # with every quote of a reference blanked
    prose: str  # the same, and in a patch with the mark that begins each line blanked too
    starts: list[int]  # where each line starts
    new_after: list[bool]  # for each line: whether the next line that holds code begins something new
    marks: list[int]  # where a quote mark or an equals sign stands
    spans: dict[int, int]  # for each code span that holds a quote of a reference: where it opens, and where it closes
    diff: bool


def read_reply(value: str, text: str, diff: bool, quotes: list) -> Reply:
    """Read one string of output once, so that each quote in it is then judged where it stands.

    A reply can be made of quotes. Reading the rest of it again for each would take time that
    grows with the square of its length.
    """
    starts = [0, *(found.end() for found in _LINE_BREAK.finditer(text))]
    new_after, new = [True] * len(starts), True  # After the last line nothing follows.
    for index in range(len(starts) - 1, -1, -1):
        new_after[index] = new
        line = text[starts[index]:starts[index + 1] - 1 if index + 1 < len(starts) else len(text)]
        if diff and line[:1] in ("+", "-", " "):
            line = line[1:]  # the mark of a patch line
        line = line.strip(" \t\r")
        if line and _COMMENT_LINE.match(line) is None and not (diff and line == _PATCH_NOTE):
            new = _BEGINS_NEW.match(line) is not None
    prose = _PATCH_MARK.sub(" ", text) if diff else text  # the mark of a patch line is not an operator
    marks = [found.start() for found in _VALUE_MARK.finditer(text)]
    spans = {}
    for start, end, rests in quotes:
        if value[start - 1:start] == "`":
            for rest in ("", *rests):
                closes = _BLANK.match(value, end + len(rest)).end() if value.startswith(rest, end) else -1
                if closes >= 0 and value[closes:closes + 1] == "`":
                    spans[start - 1] = closes
    return Reply(value, text, prose, starts, new_after, marks, spans, diff)


def ends_there(reply: Reply, start: int, end: int, rests: set[str]) -> bool:
    """Whether the expression that a permitted quote repeats is over where the quote ends.

    It may first go on exactly as it does in the source: `rests` holds what follows this
    reference on its line there.
    """
    value = reply.value
    return any(_QUOTE_END.fullmatch(value[stop - 1:stop]) and not leaves_open(value[start:stop])
               and _is_over(reply, start, stop)
               for stop in (end + len(rest) for rest in ("", *rests) if value.startswith(rest, end)))


def _plain_to_the_end_of_its_clause(reply: Reply, position: int) -> bool:
    """Whether only plain prose stands from `position` to the end of the clause that begins there.

    The clause ends at a comma or a semicolon outside the brackets opened on the way, at a closing
    bracket that nothing opened, and with the reply. Brackets can be counted because nothing that
    could hold one as text is let through: see `_CLAUSE`. A code span that holds another quote of
    a reference is stepped over: if that quote is not permitted either, the label rules refuse
    it. Short code spans with only space between them are one string, as strings that stand side
    by side are in source, and count together. No end in reach is unclear, and unclear is refused.
    """
    prose, depth = reply.prose, 0
    limit = min(len(prose), position + _CLAUSE_REACH)
    together, last = 0, -1  # the length of the short spans that stand side by side, and where the last one ended
    for _part in range(_CLAUSE_PARTS):
        part = _CLAUSE.search(prose, position, limit)
        if part is None:
            return limit == len(prose)  # The reply ends here, and nothing was joined to the quote.
        kind, position = part.lastgroup, part.end()
        if kind == "plain":
            beside = last >= 0 and not prose[last:part.start()].strip()
            together, last = (together if beside else 0) + len(part.group()) - 2, part.end()
            if together >= MIN_SECRET_LENGTH:
                return False
        if kind == "end" and not depth:
            return True
        if kind == "open":
            depth += 1
        elif kind == "close":
            if not depth:
                return True
            depth -= 1
        elif kind == "refused":
            closes = reply.spans.get(part.start())
            if closes is None:
                return False
            position = closes + 1
    return False


def leaves_open(quote: str) -> bool:
    """Whether a quote stops inside a bracket or a string that it opened.

    Then its expression goes on over the next lines, as the arguments of a call do, and what
    stands there is not looked at here.
    """
    code = _WHOLE_STRING.sub("", quote)
    depth = 0
    for character in code:
        if character in "([{":
            depth += 1
        elif character in ")]}" and depth:
            depth -= 1
    return depth > 0 or any(mark in code for mark in "\"'`")


def _is_over(reply: Reply, start: int, end: int) -> bool:
    """Whether nothing from `end` on can give the label that starts at `start` another value.

    A quote is over in two shapes. In prose it is a code span: a backtick just before the label
    and one just after the quote, with only plain prose after it to the end of its clause. In
    code it ends its line, or a comma or a semicolon does, and the next line of code begins
    something new. Anything else after the quote could hold a literal, in quote marks, in
    backticks or as a number.
    """
    text = reply.text
    line = bisect_right(reply.starts, end) - 1
    line_end = reply.starts[line + 1] - 1 if line + 1 < len(reply.starts) else len(text)
    mark = bisect_left(reply.marks, end)
    if mark < len(reply.marks) and reply.marks[mark] < line_end:
        return False  # a quote mark or an equals sign after the quote on its line
    first = _BLANK.match(text, end, line_end).end()  # where the first thing after the quote on its line is
    if first < line_end and text[first] == "`":
        # The code span has ended. Only plain prose may follow it, to the end of its clause.
        return text[start - 1:start] == "`" and _plain_to_the_end_of_its_clause(reply, first + 1)
    if first < line_end:
        return text[first] in ",;" and _BLANK.match(text, first + 1, line_end).end() == line_end
    return reply.new_after[line]  # The quote ends its line: what begins the next line that holds code?
