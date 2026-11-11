"""Related-code context for a review packet (#64 phase 3a).

For changed Python code, add signature-only skeletons of unchanged definitions in other files:
the functions it calls, the functions that call it, the tests that use it, and the classes it
extends. Offline and deterministic, with the standard library's ``ast`` only. Every snippet is read
from the head revision through the same path policy, private-name and content screening as a
changed file, and the block has its own byte budget inside the packet limit.
"""

import ast
import difflib
from pathlib import PurePosixPath
import re

from .config import Config
from .errors import AssistantError
from .python_source import SOURCE_ERRORS
from .hidden_text import BYTE_ORDER_MARK, Waiting
from .security import canonical, check_credentials, check_name, digest

RULE_VERSION = 1
# Fixed ranking tiers, in order. No graph ranking: the same commit gives the same block.
RELATIONS = ("callee", "caller", "test", "base")
MAX_SNIPPETS = 40
MAX_SNIPPET_BYTES = 4_000
MAX_SKIPPED = 50
MAX_CALL_LINES = 5
MAX_PER_TARGET = 3  # Callers, and tests, shown per changed definition; the rest are listed by name.
_PARSE_LIMIT = 500  # Files read for callers, at most; the rest are listed as related_search_limit.
_NEWLINE = re.compile(r"\r\n|\r|\n")


def source_lines(text: str) -> list[str]:
    """Lines numbered as Python numbers them: str.splitlines() also splits on form feeds and
    Unicode separators, which would shift every later line number."""
    lines = _NEWLINE.split(text)
    return lines[:-1] if lines and lines[-1] == "" else lines


def _changed_lines(before: str | None, after: str | None) -> set[int]:
    """Post-image line numbers added or replaced by the change."""
    if after is None:
        return set()
    old, new = source_lines(before or ""), source_lines(after)
    lines = set()
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if tag in {"replace", "insert"}:
            lines.update(range(j1 + 1, j2 + 1))
    return lines


def _parse(text: str):
    try:
        return ast.parse(text.removeprefix("\ufeff"))  # A byte-order mark keeps line numbers.
    except SOURCE_ERRORS:
        return None


def _top_level(tree) -> dict:
    return {node.name: node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


def _start(node) -> int:
    return min([node.lineno] + [decorator.lineno for decorator in node.decorator_list])


def _signature(node, lines: list[str]) -> list[int]:
    """Decorators and the def/class line(s), then the docstring's first line."""
    end = node.body[0].lineno - 1 if node.body[0].lineno > node.lineno else node.lineno
    numbers = list(range(_start(node), end + 1))
    first = node.body[0]
    if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str) and first.lineno <= len(lines)):
        numbers.append(first.lineno)
    return numbers


def _skeleton(node, lines: list[str]) -> list[int]:
    numbers = _signature(node, lines)
    if isinstance(node, ast.ClassDef):  # A class shows its methods' signatures too.
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                numbers += _signature(item, lines)
    return sorted(set(numbers))


def _module_paths(module: str, tracked: set[str]) -> str | None:
    relative = module.replace(".", "/")
    for candidate in (relative + ".py", relative + "/__init__.py", "src/" + relative + ".py",
                      "src/" + relative + "/__init__.py"):
        if candidate in tracked:
            return candidate
    return None


def _package_parts(path: str) -> list[str]:
    parts = list(PurePosixPath(path).parts[:-1])
    return parts[1:] if parts[:1] == ["src"] else parts


def _absolute(path: str, module: str | None, level: int) -> str | None:
    if level == 0:
        return module
    parts = _package_parts(path)
    if level - 1 > len(parts):
        return None
    base = parts[:len(parts) - (level - 1)]
    return ".".join(base + ([module] if module else [])) or None


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef,
           ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _parents(tree) -> dict:
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _bound(scope) -> set[str]:
    """Every name bound anywhere inside a scope, nested scopes included: an over-approximation,
    so a name that might be local is never resolved to an import."""
    names = set()
    for node in ast.walk(scope):
        if node is scope:
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.alias):
            names.add(node.asname or node.name.split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.add(node.rest)
    if isinstance(scope, _FUNCTIONS):
        arguments = scope.args
        names.update(argument.arg for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
                                                   arguments.vararg, arguments.kwarg) if argument is not None)
    return names


class _Scopes:
    """Whether a name at a node is bound by an enclosing scope, so it can't be the module's import."""

    def __init__(self, tree):
        self.parents, self.cache = _parents(tree), {}

    def module_level(self, node) -> bool:
        while node in self.parents:
            node = self.parents[node]
            if isinstance(node, _SCOPES):
                return False
        return True

    def shadowed(self, node, name: str) -> bool:
        in_function = False
        while node in self.parents:
            node = self.parents[node]
            if not isinstance(node, _SCOPES):
                continue
            # As in Python, a class body's names are not visible inside its methods.
            if not (isinstance(node, ast.ClassDef) and in_function):
                if id(node) not in self.cache:
                    self.cache[id(node)] = _bound(node)
                if name in self.cache[id(node)]:
                    return True
            in_function = in_function or isinstance(node, _FUNCTIONS)
        return False


def _imports(tree, path: str, tracked: set[str], scopes: "_Scopes") -> tuple[dict, dict]:
    """Local name -> (module path, name) for imported names, and local name -> module path.

    Only module-level imports count: an import inside a function binds a name in that
    function only, and is treated as a local binding instead.
    """
    names, modules = {}, {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)) and not scopes.module_level(node):
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = _module_paths(alias.name, tracked)
                if target and alias.asname:
                    modules[alias.asname] = target
                elif target and "." not in alias.name:
                    modules[alias.name] = target
        elif isinstance(node, ast.ImportFrom):
            module = _absolute(path, node.module, node.level)
            if module is None:
                continue
            for alias in node.names:
                local = alias.asname or alias.name
                submodule = _module_paths(module + "." + alias.name, tracked)
                if submodule:
                    modules[local] = submodule
                elif (target := _module_paths(module, tracked)):
                    names[local] = (target, alias.name)
    # A name the file defines or assigns at top level shadows an import of the same name.
    own = set(_top_level(tree))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                own |= {item.id for item in ast.walk(target) if isinstance(item, ast.Name)}
    return ({name: value for name, value in names.items() if name not in own},
            {name: value for name, value in modules.items() if name not in own})


def _resolve(expression, names: dict, modules: dict, scopes: "_Scopes") -> tuple[str, str] | None:
    """Only a plain imported name or module.attribute resolves, and only where no enclosing
    scope binds that name; anything else is ambiguous and left out."""
    if isinstance(expression, ast.Name) and expression.id in names:
        if not scopes.shadowed(expression, expression.id):
            return names[expression.id]
    elif (isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name)
            and expression.value.id in modules and not scopes.shadowed(expression, expression.value.id)):
        return modules[expression.value.id], expression.attr
    return None


def _is_test(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return "tests" in parts or "test" in parts or parts[-1].startswith("test_")


class _Collector:
    def __init__(self, repo, head: str, config: Config, changed: set[str], tracked: set[str], read):
        self.repo, self.head, self.config, self.changed, self.tracked = repo, head, config, changed, tracked
        self.read = read  # (path) -> text or raises AssistantError; screened by the caller.
        self.cache, self.skipped = {}, []

    def eligible(self, path: str) -> bool:
        return (path in self.tracked and path not in self.changed and path.endswith(".py")
                and self.config.allows(path) and not self.config.generated(path))

    def source(self, path: str):
        if path not in self.cache:
            try:
                text = self.read(path)
            except AssistantError as exc:
                self.skipped.append({"path": path, "symbol": None, "reason": exc.code})
                text = None
            tree = _parse(text) if text is not None else None
            if text is not None and tree is None:
                self.skipped.append({"path": path, "symbol": None, "reason": "python_source_unparseable"})
            self.cache[path] = (text, tree) if tree is not None else None
        return self.cache[path]


def _numbered(text: str, numbers: list[int]) -> list[list]:
    lines = source_lines(text)
    if lines:
        lines[0] = lines[0].removeprefix(BYTE_ORDER_MARK)  # It marks the file, and is no part of its first line.
    return [[number, lines[number - 1]] for number in numbers if 1 <= number <= len(lines)]


def candidates(repo, head: str, files: list[dict], config: Config, tracked: set[str], read, grep) -> tuple[list, list]:
    """Ranked snippet candidates and early skips. ``grep(names)`` lists tracked paths mentioning any name."""
    changed = {file["path"] for file in files}
    collector = _Collector(repo, head, config, changed, tracked, read)
    found = {}  # (path, symbol) -> candidate; the first, highest-ranked relation wins.

    def add(relation, path, symbol, numbers, reference):
        source = collector.source(path)
        if source is None or not numbers:
            return
        text, _tree = source
        key = (path, symbol)
        if key in found and found[key]["relation"] == relation and found[key]["reference"] == reference:
            # The same caller again, such as a second call: show every call line, in order.
            numbers = sorted({number for number, _line in found[key]["lines"]} | set(numbers))
        elif key in found and RELATIONS.index(found[key]["relation"]) <= RELATIONS.index(relation):
            return
        found[key] = {"path": path, "symbol": symbol, "relation": relation, "reference": reference,
                      "lines": _numbered(text, numbers), "sha256": digest(text.encode())}

    targets = {}  # changed module path -> names of changed or removed top-level definitions
    for file in sorted(files, key=lambda item: item["path"]):
        path = file["path"]
        if not path.endswith(".py"):
            continue
        after = _parse(file["after"]) if file["after"] is not None else None
        before = _parse(file["before"]) if file["before"] is not None else None
        changed_lines = _changed_lines(file["before"], file["after"])
        names = set()
        if after is not None:
            for name, node in _top_level(after).items():
                if changed_lines & set(range(_start(node), node.end_lineno + 1)):
                    names.add(name)
        if before is not None:  # A removed definition's callers matter too.
            names |= set(_top_level(before)) - (set(_top_level(after)) if after is not None else set())
        if names:
            targets[path] = names
        if after is None:
            continue
        scopes = _Scopes(after)
        imported, modules = _imports(after, path, tracked, scopes)
        for node in ast.walk(after):
            # A call counts when any of its lines changed, such as an argument on a later line.
            if isinstance(node, ast.Call) and changed_lines & set(range(node.lineno, node.end_lineno + 1)):
                relation, expressions = "callee", [node.func]
            elif isinstance(node, ast.ClassDef) and changed_lines & set(
                    range(node.lineno, max(node.lineno, node.body[0].lineno - 1) + 1)):
                relation, expressions = "base", node.bases
            else:
                continue
            for expression in expressions:
                resolved = _resolve(expression, imported, modules, scopes)
                if resolved is None or not collector.eligible(resolved[0]):
                    continue
                source = collector.source(resolved[0])
                definition = _top_level(source[1]).get(resolved[1]) if source else None
                if definition is None or (relation == "base") != isinstance(definition, ast.ClassDef):
                    continue
                add(relation, resolved[0], resolved[1], _skeleton(definition, source_lines(source[0])),
                    {"path": path, "line": node.lineno})

    wanted = sorted({name for names in targets.values() for name in names})
    mentions = sorted(path for path in grep(wanted) if collector.eligible(path)) if wanted else []
    for path in mentions[_PARSE_LIMIT:]:
        collector.skipped.append({"path": path, "symbol": None, "reason": "related_search_limit"})
    for path in mentions[:_PARSE_LIMIT]:
        source = collector.source(path)
        if source is None:
            continue
        text, tree = source
        scopes = _Scopes(tree)
        imported, modules = _imports(tree, path, tracked, scopes)
        lines = source_lines(text)
        parents = scopes.parents
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            resolved = _resolve(node.func, imported, modules, scopes)
            if resolved is None or resolved[1] not in targets.get(resolved[0], set()):
                continue
            enclosing = node
            while enclosing in parents and not isinstance(enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)):
                enclosing = parents[enclosing]
            calls = list(range(node.lineno, min(node.end_lineno, node.lineno + MAX_CALL_LINES - 1) + 1))
            if isinstance(enclosing, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbol, numbers = enclosing.name, sorted(set(_signature(enclosing, lines) + calls))
            else:
                symbol, numbers = "<module>", calls
            add("test" if _is_test(path) else "caller", path, symbol, numbers,
                {"path": resolved[0], "symbol": resolved[1]})
    ranked, shown = [], {}
    for item in sorted(found.values(), key=lambda item: (RELATIONS.index(item["relation"]), item["path"],
                                                         item["lines"][0][0] if item["lines"] else 0)):
        if item["relation"] in {"caller", "test"}:
            target = (item["relation"], item["reference"]["path"], item["reference"]["symbol"])
            shown[target] = shown.get(target, 0) + 1
            if shown[target] > MAX_PER_TARGET:  # Many callers of one function add noise, not insight.
                collector.skipped.append({"path": item["path"], "symbol": item["symbol"],
                                          "reason": "related_target_limit"})
                continue
        ranked.append(item)
    return ranked, collector.skipped


def related_block(ranked: list, skipped: list, budget: int) -> dict:
    """Fill the budget greedily in rank order; a candidate that doesn't fit is listed by name only."""
    snippets, used = [], 0
    for item in ranked:
        size = len(canonical(item))
        if len(snippets) < MAX_SNIPPETS and size <= MAX_SNIPPET_BYTES and used + size <= budget:
            snippets.append(item)
            used += size
        else:
            skipped.append({"path": item["path"], "symbol": item["symbol"], "reason": "related_budget"})
    return {"rule_version": RULE_VERSION, "budget_bytes": budget, "snippets": snippets,
            "skipped": skipped[:MAX_SKIPPED], "skipped_count": len(skipped)}


_BLOCK_KEYS = {"rule_version", "budget_bytes", "snippets", "skipped", "skipped_count"}
_SNIPPET_KEYS = {"path", "symbol", "relation", "reference", "lines", "sha256"}
_CODE = re.compile(r"[a-z][a-z0-9_]{0,80}")


def verify_related(block, changed: list[str], config: Config, private, waiting: Waiting | None = None) -> None:
    """Re-check a packet's related block as strictly as the builder made it.

    ``private(path)`` is the packet builder's private-name rule: a private name never appears.
    A snippet is lines of a file, never the start of one, so it may not begin with a byte order
    mark. With ``waiting``, a hidden-character refusal is left there for the caller to release.
    """
    held = waiting if waiting is not None else Waiting()
    def refuse():
        raise AssistantError("packet_related_invalid")

    if (not isinstance(block, dict) or set(block) != _BLOCK_KEYS or block["rule_version"] != RULE_VERSION
            or type(block["budget_bytes"]) is not int or not 0 <= block["budget_bytes"] <= config.related_max_bytes
            or not isinstance(block["snippets"], list) or len(block["snippets"]) > MAX_SNIPPETS
            or not isinstance(block["skipped"], list) or len(block["skipped"]) > MAX_SKIPPED
            or type(block["skipped_count"]) is not int
            or not len(block["skipped"]) <= block["skipped_count"] <= 1_000_000):
        refuse()
    extras = config.extra_sensitive_patterns
    used, seen = 0, set()
    for item in block["snippets"]:
        if (not isinstance(item, dict) or set(item) != _SNIPPET_KEYS or item["relation"] not in RELATIONS
                or not isinstance(item["path"], str) or not isinstance(item["symbol"], str)
                or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or not isinstance(item["lines"], list) or not item["lines"]):
            refuse()
        try:
            path = config.check_path(item["path"])  # The same path rules as a changed file.
        except AssistantError:
            refuse()
        if (path in changed or private(path) or not path.endswith(".py") or not config.allows(path)
                or config.generated(path) or (path, item["symbol"]) in seen):
            refuse()
        seen.add((path, item["symbol"]))
        reference = item["reference"]
        if (not isinstance(reference, dict) or not isinstance(reference.get("path"), str)
                or reference["path"] not in changed
                or not (set(reference) == {"path", "line"} and type(reference["line"]) is int
                        and reference["line"] >= 1
                        or set(reference) == {"path", "symbol"} and isinstance(reference["symbol"], str))):
            refuse()
        previous = 0
        for entry in item["lines"]:
            if (not isinstance(entry, list) or len(entry) != 2 or type(entry[0]) is not int
                    or entry[0] <= previous or not isinstance(entry[1], str) or _NEWLINE.search(entry[1])):
                refuse()
            previous = entry[0]
        lines = "\n".join(line for _number, line in item["lines"])
        check_credentials(item["symbol"], extra_patterns=extras, source_path=path)  # a name, never placeholder text
        held.check(item["symbol"])
        check_credentials(lines, extra_patterns=extras, source_path=path, placeholders=config.placeholder_credential_paths)
        held.check(lines)
        size = len(canonical(item))
        if size > MAX_SNIPPET_BYTES:
            refuse()
        used += size
    if used > block["budget_bytes"]:
        refuse()
    for item in block["skipped"]:
        if (not isinstance(item, dict) or set(item) != {"path", "symbol", "reason"}
                or not isinstance(item["path"], str) or not isinstance(item["reason"], str)
                or not _CODE.fullmatch(item["reason"])
                or not (item["symbol"] is None or isinstance(item["symbol"], str))):
            refuse()
        try:
            name = config.check_path(item["path"], source_only=False, metadata_only=True)
        except AssistantError:
            refuse()
        if private(name):
            refuse()
        check_name(item["path"], extra_patterns=extras)
        if item["symbol"] is not None:
            check_credentials(item["symbol"], extra_patterns=extras)
            held.check(item["symbol"])
    if waiting is None:
        held.release()
