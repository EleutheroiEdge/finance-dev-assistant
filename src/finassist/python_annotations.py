"""Build an annotation-free Python view for label-assignment screening.

The returned screening view never replaces source or request bytes. Filename and
syntax are context, not proof that a repository contains no private information.
"""
import ast
import io
from pathlib import PurePosixPath
import re
import warnings
import tokenize


def credential_screening_view(text: str, source_path: str | None) -> str:
    if source_path is None or PurePosixPath(source_path).suffix.lower() not in {".py", ".pyi"}:
        return text
    try:
        # Python can warn about invalid escapes and echo the source line.
        # Screening must not disclose candidate source through diagnostics.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return text  # Unparseable source retains strict generic screening.
    lines = re.findall(r"[^\r\n]*(?:\r\n|\r|\n|$)", text)
    starts, position = [], 0
    for line in lines:
        starts.append(position)
        position += len(line)

    def offset(node, *, end=False):
        row = (node.end_lineno if end else node.lineno) - 1
        column = node.end_col_offset if end else node.col_offset
        # AST columns count UTF-8 bytes, including non-ASCII text before a name.
        return starts[row] + len(lines[row].encode("utf-8")[:column].decode("utf-8"))

    comments = []
    syntax = list(text)
    # Comments are screened separately after removing annotations. Leaving one
    # in the middle of a masked annotation would split label from assigned value.
    try:
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        for token in tokenize.generate_tokens(io.StringIO(normalized).readline):
            if token.type == tokenize.COMMENT:
                start = starts[token.start[0] - 1] + token.start[1]
                end = starts[token.end[0] - 1] + token.end[1]
                comments.append(text[start:end])
                syntax[start:end] = " " * (end - start)
    except (tokenize.TokenError, IndentationError):
        return text
    syntax = "".join(syntax)
    spans = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AnnAssign, ast.arg)):
            continue
        annotation = node.annotation
        if annotation is None:
            continue
        start, end = offset(annotation), offset(annotation, end=True)
        label_end = offset(node.target, end=True) if isinstance(node, ast.AnnAssign) else offset(node)
        prefix = syntax[label_end:start]
        # AST spans exclude enclosing parentheses. Accept only the annotation
        # colon/whitespace/parentheses here, never another syntax token.
        # Comments removed from syntax are still screened in full below.
        pattern = r"\s*:\s*(?:\(\s*)*" if isinstance(node, ast.AnnAssign) else r"[^\W\d]\w*\s*:\s*(?:\(\s*)*"
        if not re.fullmatch(pattern, prefix):
            continue
        for _ in range(prefix.count("(")):
            closing = re.match(r"\s*\)", syntax[end:])
            if closing is None:
                break
            end += closing.end()
        else:
            spans.append((text.index(":", label_end, start), end))
    if not spans:
        return text
    view = list(text)
    for start, end in spans:
        # Retain the variable name, assigned value, comments and all other text.
        # An annotated assignment becomes name = value for label heuristics.
        for index in range(start, end):
            if view[index] not in "\r\n":
                view[index] = " "
    return "".join(view) + "\n" + "\n".join(comments)
