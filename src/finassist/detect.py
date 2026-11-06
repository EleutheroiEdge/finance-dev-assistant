"""Propose a configuration from what a repository has committed, without running any of it.

`init --detect` reads only files committed at one revision, through Git. It never
runs a Makefile, noxfile, tox, npm script, setup.py, conftest or workflow step. It
reads agent instructions such as AGENTS.md and CLAUDE.md as data: a command found
there is proposed, never run or obeyed. Every proposal names the file and rule
that suggested it, so a person can check it before anything is written.
"""

from __future__ import annotations

import ast
import configparser
import json
from pathlib import PurePosixPath
from pathlib import Path
import re
import shlex
import subprocess
import tomllib
import unicodedata

from .config import Config, config_document, save_config
from .errors import AssistantError, prices_required
from .scope import git, git_command, git_environment, resolve
from .security import DENIED_PARTS, TEXT_SUFFIXES, canonical, check_path, check_text, safe_relative

PURPOSES = {"quant": "quant-review", "accounting": "finance-saas", "research": "investment-research",
            "general": "general"}
SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rs", ".java", ".sql", ".sh"}
TEST_DIRECTORIES = ("tests/", "test/")
DOC_DIRECTORIES = ("docs/", "doc/")
NOT_SOURCE = {"build", "dist", "out", "site", "htmlcov", "vendor", "third_party", "third-party", "node_modules",
              "data", "tests", "test", "docs", "doc", "examples", "fixtures"}
LOCKFILES = {"poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "package-lock.json", "yarn.lock",
             "pnpm-lock.yaml", "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock"}
PROTECTED_CANDIDATES = ("AGENTS.md", "CLAUDE.md", "CODEOWNERS", "LICENSE", "SECURITY.md", "pyproject.toml",
                        "setup.cfg", "setup.py", "tox.ini", "noxfile.py", "Makefile", "package.json")
AGENT_DOCS = ("AGENTS.md", "CLAUDE.md", ".github/copilot-instructions.md")
RUNNERS = {"pytest", "tox", "nox", "make", "npm", "pnpm", "yarn", "go", "cargo", "uv", "hatch", "poetry"}
# Data and credential formats are private: never read, and denied if they sit inside a
# reviewed prefix. Images and archives are binary assets, refused for review but not private.
PRIVATE_SUFFIXES = {".csv", ".tsv", ".parquet", ".db", ".sqlite", ".sqlite3", ".xlsx", ".xls", ".pem", ".key", ".p12",
                    ".pfx"}
# name-<content hash>.js, as bundlers write. A hash has a digit: "input-validation.js" is a module.
_BUILT = re.compile(r".+-(?=[A-Za-z0-9_]*[0-9])[A-Za-z0-9_]{8,20}\.(?:js|mjs|css)")
_NOT_TEST_WORDS = {"publish", "deploy", "release", "upload", "install", "push"}
_SHELL = re.compile(r"[|&;<>`$(){}*?\[\]]")
_READ_LIMIT = 128_000
_EXAMPLES = 20
_FENCE = re.compile(r"^(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)")


def _shown(name: str) -> str:
    """A name for local output, or [redacted] when the name fails screening or could hide text.

    Control and format characters (such as a right-to-left override) can make a name
    display as something else, so such a name is never shown.
    """
    if any(unicodedata.category(character) in {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"} for character in name):
        return "[redacted]"
    try:
        safe_relative(name.removesuffix("/"))
        check_text(name)
    except AssistantError:
        return "[redacted]"
    return name


def _examples(names) -> list[str]:
    return [_shown(name) for name in sorted(names)[:_EXAMPLES]]


class _Detector:
    def __init__(self, repo, head: str):
        self.repo, self.head = repo, head
        self.files: dict[str, int] = {}
        self.undecodable = 0
        self.unsafe = 0
        self.evidence: dict[str, list[dict]] = {}
        self.truncated: dict[str, int] = {}
        self.warnings: list[dict] = []
        self.has_source = False

    # Reading -----------------------------------------------------------------
    def list_files(self) -> None:
        raw = git(self.repo, "ls-tree", "-r", "-z", "-l", "--full-tree", self.head, binary=True)
        for record in filter(None, raw.split(b"\0")):
            meta, _tab, name = record.partition(b"\t")
            mode, kind, _oid, size = meta.split()
            if kind != b"blob" or mode not in (b"100644", b"100755"):
                continue  # Links and submodules are never proposed.
            try:
                path = name.decode("utf-8")
            except UnicodeDecodeError:
                self.undecodable += 1
                continue
            if _shown(path) == "[redacted]":
                # Such a name could display as another or hold a credential-like value, so it
                # never becomes a configuration value; the file itself stays refused by review.
                self.unsafe += 1
                continue
            self.files[path] = int(size)
        if self.undecodable:
            self.warn("path_name_not_utf8", count=self.undecodable)
        if self.unsafe:
            self.warn("unsafe_names_skipped", count=self.unsafe)

    def read(self, path: str) -> str | None:
        """A small committed text file, or None. Never the working tree.

        The shared path policy is applied before any read, so a private, credential or
        reserved name is never opened, whatever directory it is in.
        """
        if path not in self.files or self.private(path):
            return None
        try:
            check_path(path, source_only=False, metadata_only=True)
        except AssistantError:
            return None
        if self.files[path] > _READ_LIMIT:
            self.warn("detect_file_too_large", path=_shown(path), limit=_READ_LIMIT)
            return None
        data = git(self.repo, "cat-file", "blob", f"{self.head}:{path}", binary=True)
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            self.warn("detect_file_not_utf8", path=_shown(path))
            return None
        return text

    def warn(self, code: str, **details) -> None:
        self.warnings.append({"code": code, **details})

    def note(self, field: str, value, rule: str, path: str | None = None, line: int | None = None) -> None:
        """Record why a value was proposed; at most 20 entries per field are kept, the rest counted."""
        if len(self.evidence.get(field, ())) >= _EXAMPLES:
            self.truncated[field] = self.truncated.get(field, 0) + 1
            return
        entry = {"value": value, "rule": rule}
        if path is not None:
            entry["path"] = _shown(path)
        if line is not None:
            entry["line"] = line
        self.evidence.setdefault(field, []).append(entry)

    # Layout ------------------------------------------------------------------
    def private(self, path: str) -> bool:
        parts = PurePosixPath(path).parts
        lowered = {part.lower() for part in parts}
        return bool(lowered & DENIED_PARTS) or PurePosixPath(path).suffix.lower() in PRIVATE_SUFFIXES

    def layout(self) -> dict:
        roots: dict[str, str] = {}
        for path in sorted(self.files):
            parts = PurePosixPath(path).parts
            suffix = PurePosixPath(path).suffix.lower()
            if self.private(path) or suffix not in SOURCE_SUFFIXES:
                continue
            if len(parts) == 1:
                roots.setdefault(path, path)
                continue
            top = parts[0]
            if top.startswith(".") or top.lower() in NOT_SOURCE:
                continue
            if top == "src" and len(parts) > 2:
                roots.setdefault("src/", path)
            else:
                roots.setdefault(top + "/", path)
        allow = []
        self.has_source = bool(roots)
        for prefix, example in sorted(roots.items()):
            allow.append(prefix)
            self.note("allow_paths", prefix, "source_files" if prefix.endswith("/") else "root_source_file", example)
        for prefix in (*TEST_DIRECTORIES, *DOC_DIRECTORIES, "scripts/"):
            sample = next((path for path in sorted(self.files) if path.startswith(prefix)
                           and not self.private(path) and PurePosixPath(path).suffix.lower() in TEXT_SUFFIXES), None)
            if sample and prefix not in allow:
                allow.append(prefix)
                self.note("allow_paths", prefix, "tests" if prefix in TEST_DIRECTORIES else "docs_or_scripts", sample)
        for name in ("README.md", "README.rst", "pyproject.toml"):
            if name in self.files and name not in allow:
                allow.append(name)
                self.note("allow_paths", name, "project_file", name)
        return {"allow_paths": allow}

    def generated(self) -> list[str]:
        names, ceilings = set(), {}
        for path in self.files:
            name = PurePosixPath(path).name
            if name in LOCKFILES:
                names.add(path)
                self.note("generated_paths", path, "lockfile", path)
            elif name.endswith((".min.js", ".min.css", ".js.map", ".css.map")):
                names.add(path)
                self.note("generated_paths", path, "minified_or_map", path)
            elif "assets" in PurePosixPath(path).parts[:-1] and _BUILT.fullmatch(name):
                names.add(path)
                ceilings[path] = _ceiling(path, "assets")
                self.note("generated_paths", path, "hashed_build_asset", path)
            elif "dist" in PurePosixPath(path).parts[:-1]:
                names.add(path)
                ceilings[path] = _ceiling(path, "dist")
                self.note("generated_paths", path, "build_output", path)
        for path, attribute in self.linguist():
            names.add(path)
            self.note("generated_paths", path, attribute, ".gitattributes")
        for prefix in ("vendor/", "third_party/", "third-party/"):
            if any(path.startswith(prefix) for path in self.files):
                names = {name for name in names if not name.startswith(prefix)} | {prefix}
                self.note("generated_paths", prefix, "vendored_directory")
        return _collapse(names, self.files, ceilings)

    def linguist(self) -> list[tuple[str, str]]:
        """Paths .gitattributes marks generated or vendored at this revision, read by Git itself."""
        if ".gitattributes" not in self.files and not any(path.endswith("/.gitattributes") for path in self.files):
            return []
        names = sorted(path for path in self.files if not self.private(path))
        try:
            done = subprocess.run(
                git_command(self.repo, "check-attr", f"--source={self.head}", "-z", "--stdin",
                            "linguist-generated", "linguist-vendored"),
                input="\0".join(names).encode("utf-8"), env=git_environment(), capture_output=True,
                timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            done = None
        if done is None or done.returncode != 0:
            self.warn("gitattributes_not_read")  # Git before 2.40 can't read attributes from a revision.
            return []
        raw = done.stdout
        fields = raw.split(b"\0")
        found = []
        for index in range(0, len(fields) - 2, 3):
            path, attribute, value = (item.decode("utf-8", "replace") for item in fields[index:index + 3])
            if value in {"set", "true"}:
                found.append((path, attribute))
        return found

    # Data, fixtures and limits -------------------------------------------------
    def data(self, allow: list[str]) -> dict:
        private = sorted(path for path in self.files if self.private(path))
        fixtures = {}
        deny = set()
        for path in private:
            parts = PurePosixPath(path).parts
            suffix = PurePosixPath(path).suffix.lower()
            lowered = [part.lower() for part in parts[:-1]]
            if suffix in {".csv", ".tsv"} and ("tests" in lowered or "fixtures" in lowered) and not (
                    set(lowered) & DENIED_PARTS or "data" in lowered):
                root = "/".join(parts[:-1]) + "/"
                fixtures.setdefault(root, path)
            elif _allowed(path, allow):
                # Data formats are always refused anyway. Deny only a directory named as private
                # data inside a reviewed prefix, so the policy states that intent.
                for depth, part in enumerate(lowered):
                    if part in DENIED_PARTS or part == "data":
                        deny.add("/".join(parts[:depth + 1]) + "/")
                        break
        for root, example in sorted(fixtures.items()):
            self.note("fixture_roots", root, "csv_or_tsv_under_tests", example)
        for prefix in sorted(deny):
            self.note("deny_paths", prefix, "private_or_data_files")
        if fixtures:
            self.warn("fixture_roots_must_be_synthetic", count=len(fixtures))
        return {"private": private, "fixture_roots": sorted(fixtures), "deny_paths": sorted(deny)}

    def file_limit(self, allow: list[str], generated: list[str]) -> int:
        """Fit the largest reviewed source file. Other large text files are reported, not fitted."""
        reviewed = {path: size for path, size in self.files.items() if _allowed(path, allow)
                    and not self.private(path) and not _allowed(path, generated)
                    and PurePosixPath(path).suffix.lower() in TEXT_SUFFIXES}
        source = [size for path, size in reviewed.items() if PurePosixPath(path).suffix.lower() in SOURCE_SUFFIXES]
        too_large = [path for path, size in reviewed.items() if size > 2_000_000
                     and PurePosixPath(path).suffix.lower() in SOURCE_SUFFIXES]
        if too_large:
            self.warn("source_file_never_reviewable", count=len(too_large), paths=_examples(too_large),
                      limit=2_000_000)
        limit = min(2_000_000, max(48_000, -(-max(source, default=0) // 16_384) * 16_384))
        if limit > 48_000:
            self.note("max_file_bytes", limit, "largest_reviewed_source_file")
        large = [path for path, size in reviewed.items() if size > limit and path not in too_large]
        if large:
            self.warn("large_files_over_limit", count=len(large), paths=_examples(large), limit=limit)
        self.sources = {path: size for path, size in reviewed.items() if size <= limit
                        and PurePosixPath(path).suffix.lower() in SOURCE_SUFFIXES}
        return limit

    def encoded_sizes(self) -> tuple[int, int]:
        """(packet bytes, request bytes) that one changed source file needs, measured.

        A changed file travels as its earlier and later text. The packet escapes each
        side once as JSON; the provider request escapes the packet's JSON text again, so
        tabs, quotes and non-ASCII characters grow there most. The largest file is read
        first, then any file whose worst case (7 bytes per byte) could exceed it.
        """
        once = twice = 0
        for path, size in sorted(self.sources.items(), key=lambda item: -item[1]):
            if 7 * size + 2 <= twice:
                break
            data = git(self.repo, "cat-file", "blob", f"{self.head}:{path}", binary=True)
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue  # Review refuses it as non_text_blob; it can't shape a limit.
            single = json.dumps(text)
            once, twice = max(once, len(single)), max(twice, len(json.dumps(single)))
        packet, request = 2 * once + _ROOM, 2 * twice + _ROOM
        if request > 2_000_000:
            self.warn("request_cap_cannot_fit_file", limit=2_000_000, needed=request)
        self.note("max_request_bytes", min(2_000_000, max(120_000, request)), "largest_encoded_source_file")
        return min(2_000_000, max(120_000, packet)), min(2_000_000, max(120_000, request))

    # Test commands ------------------------------------------------------------
    def tests(self) -> list[dict]:
        proposals: dict[tuple[str, ...], dict] = {}

        def propose(argv: list[str], confidence: str, rule: str, path: str, line: int | None = None) -> None:
            if not argv or not all(part.isprintable() and part.isascii() for part in argv):
                return
            try:
                check_text(" ".join(argv))
            except AssistantError:
                return
            entry = proposals.setdefault(tuple(argv), {"argv": argv, "confidence": confidence, "evidence": []})
            if _rank(confidence) > _rank(entry["confidence"]):
                entry["confidence"] = confidence
            evidence = {"rule": rule, "path": _shown(path)}
            if line is not None:
                evidence["line"] = line
            entry["evidence"].append(evidence)

        self._pytest(propose)
        self._tox_and_nox(propose)
        self._make_and_npm(propose)
        for path in sorted(self.files):
            if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
                for line, command in _workflow_runs(self.read(path) or ""):
                    argv = _runner_argv(command)
                    if argv:
                        propose(argv, "medium", "ci_run_step", path, line)
        for path in AGENT_DOCS:
            for line, command in _fenced_commands(self.read(path) or ""):
                argv = _runner_argv(command)
                if argv:
                    propose(argv, "low", "agent_instructions", path, line)
        return sorted(proposals.values(), key=lambda entry: (-_rank(entry["confidence"]), entry["argv"]))

    def _pytest(self, propose) -> None:
        text = self.read("pyproject.toml")
        if text is not None:
            try:
                document = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                self.warn("detect_file_unreadable", path="pyproject.toml")
                document = {}
            tool = document.get("tool", {}) if isinstance(document.get("tool"), dict) else {}
            pytest_table = tool.get("pytest")
            if isinstance(pytest_table, dict) and ("ini_options" in pytest_table or pytest_table):
                propose(["python", "-m", "pytest"], "high", "pytest_configuration", "pyproject.toml")
        for name, section in (("pytest.ini", "pytest"), ("tox.ini", "pytest"), ("setup.cfg", "tool:pytest")):
            text = self.read(name)
            if text is None:
                continue
            parser = configparser.ConfigParser(interpolation=None)
            try:
                parser.read_string(text, source=name)
            except configparser.Error:
                self.warn("detect_file_unreadable", path=name)
                continue
            if parser.has_section(section):
                propose(["python", "-m", "pytest"], "high", "pytest_configuration", name)

    def _tox_and_nox(self, propose) -> None:
        text = self.read("tox.ini")
        if text is not None:
            parser = configparser.ConfigParser(interpolation=None)
            try:
                parser.read_string(text, source="tox.ini")
                if parser.has_section("tox"):
                    propose(["tox"], "medium", "tox_configuration", "tox.ini")
            except configparser.Error:
                pass  # Already reported by the pytest pass.
        text = self.read("noxfile.py")
        if text is not None:
            try:
                tree = ast.parse(text)  # Parsed only; never imported or run.
            except (SyntaxError, ValueError):
                self.warn("detect_file_unreadable", path="noxfile.py")
                return
            for node in tree.body:
                if isinstance(node, ast.FunctionDef) and any(_is_nox_session(item) for item in node.decorator_list):
                    if node.name.startswith("test") or node.name in {"tests", "unit"}:
                        propose(["nox", "-s", node.name], "medium", "nox_session", "noxfile.py", node.lineno)

    def _make_and_npm(self, propose) -> None:
        text = self.read("Makefile")
        if text is not None:
            for number, line in enumerate(text.splitlines(), 1):
                if re.match(r"test\s*:(?!=)", line):
                    propose(["make", "test"], "medium", "make_target", "Makefile", number)
                    break
        text = self.read("package.json")
        if text is not None:
            try:
                scripts = json.loads(text).get("scripts", {})
            except (ValueError, AttributeError):
                self.warn("detect_file_unreadable", path="package.json")
                return
            if isinstance(scripts, dict) and isinstance(scripts.get("test"), str):
                propose(["npm", "test"], "medium", "package_script", "package.json")

    def protected(self, generated: list[str]) -> list[str]:
        names = [".github/", ".gitattributes", "finassist.json"]
        names += [name for name in PROTECTED_CANDIDATES if name in self.files]
        names += [path for path in generated if PurePosixPath(path).name in LOCKFILES]
        return sorted(dict.fromkeys(names))


def _is_nox_session(node) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    return isinstance(target, ast.Attribute) and target.attr == "session" and getattr(target.value, "id", "") == "nox"


def _rank(confidence: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}[confidence]


def _allowed(path: str, allow: list[str]) -> bool:
    return any(path.startswith(prefix) if prefix.endswith("/") else path == prefix for prefix in allow)


def _ceiling(path: str, component: str) -> str:
    """The prefix up to the last `component` directory in path, such as `web/assets/`."""
    parts = PurePosixPath(path).parts[:-1]
    index = len(parts) - 1 - parts[::-1].index(component)
    return "/".join(parts[:index + 1]) + "/"


def _collapse(names: set[str], files: dict[str, int], ceilings: dict[str, str] | None = None) -> list[str]:
    """Replace a directory whose every committed file is listed with one prefix.

    A path found by a name guess has a ceiling (its assets or dist directory), so the
    guess never grows into an ancestor that may hold source.
    """
    ceilings = ceilings or {}
    result = set(names)
    for path in sorted(name for name in names if not name.endswith("/")):
        parents = PurePosixPath(path).parents
        for parent in reversed(list(parents)[:-1]):
            prefix = parent.as_posix() + "/"
            if path in ceilings and not prefix.startswith(ceilings[path]):
                continue
            inside = [name for name in files if name.startswith(prefix)]
            if inside and all(name in names or any(name.startswith(p) for p in result if p.endswith("/"))
                              for name in inside):
                result = {name for name in result if not name.startswith(prefix)} | {prefix}
                break
    return sorted(result)


def _workflow_runs(text: str):
    """Commands in `run:` steps, from a bounded line scan. YAML isn't parsed, so this is partial."""
    lines = text.splitlines()[:5000]
    index = 0
    while index < len(lines):
        stripped = lines[index].strip().removeprefix("- ")
        if stripped.startswith("run:"):
            value = stripped[4:].strip()
            if value in {"|", ">", "|-", ">-", "|+", ">+"}:
                indent = len(lines[index]) - len(lines[index].lstrip())
                index += 1
                while index < len(lines) and (not lines[index].strip()
                                              or len(lines[index]) - len(lines[index].lstrip()) > indent):
                    if lines[index].strip():
                        yield index + 1, lines[index].strip()
                    index += 1
                continue
            if value:
                yield index + 1, value.strip("\"'")
        index += 1


def _fenced_commands(text: str):
    """Lines inside shell code fences of a Markdown file."""
    fence = None
    for number, line in enumerate(text.splitlines()[:5000], 1):
        match = _FENCE.match(line.strip())
        if match:
            if fence is None:
                fence = match.group(1) if match.group(2).lower() in {"", "sh", "bash", "shell", "console", "zsh"} else ""
            elif line.strip().startswith(fence or "\0"):
                fence = None
            elif fence == "" and line.strip().startswith(("```", "~~~")):
                fence = None
            continue
        if fence:
            yield number, line.strip().removeprefix("$ ").strip()


def _runner_argv(command: str) -> list[str] | None:
    """A command as argv when it is a known runner's test command, with no shell syntax.

    Each runner's own grammar is matched, so `npm publish test` or `make deploy test`
    is not taken for a test command.
    """
    if not command or len(command) > 300 or _SHELL.search(command):
        return None
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if not argv:
        return None
    head, rest = argv[0], argv[1:]
    accepted = (
        (head in {"python", "python3", "py"} and rest[:2] in (["-m", "pytest"], ["-m", "unittest"]))
        or (head in {"pytest", "tox", "nox"} and not (rest[:1] and rest[0] in _NOT_TEST_WORDS))
        or (head == "make" and rest in (["test"], ["check"]))
        or (head in {"npm", "pnpm"} and (rest[:1] == ["test"] or rest[:2] == ["run", "test"]))
        or (head == "yarn" and (rest[:1] == ["test"] or rest[:2] == ["run", "test"]))
        or (head in {"go", "cargo"} and rest[:1] == ["test"])
        or (head in {"uv", "poetry", "hatch"} and (rest[:2] == ["run", "pytest"]
                                                  or rest[:4] == ["run", "python", "-m", "pytest"]))
        or (head == "hatch" and rest[:1] == ["test"])
    )
    if not accepted:
        return None
    # Extra words after a package script name are arguments to it: allow them only after "--".
    if head in {"npm", "pnpm", "yarn"}:
        tail = rest[1:] if rest[:1] == ["test"] else rest[2:]
        if tail and tail[0] != "--":
            return None
    return argv


# Room for the system instructions, the response schema and the packet's other fields.
_ROOM = 65_536


def detect(repo, *, revision: str = "HEAD", purpose: str | None = None) -> dict:
    """A proposal for this repository. Nothing is written and nothing from the repository runs."""
    if purpose is not None and purpose not in PURPOSES:
        raise AssistantError("invalid_purpose")
    head = resolve(repo, revision)
    detector = _Detector(repo, head)
    detector.list_files()
    if not detector.files:
        raise AssistantError("detect_empty_repository")
    allow = detector.layout()["allow_paths"]
    if not detector.has_source:
        detector.warn("no_source_detected")
    generated = detector.generated()
    data = detector.data(allow)
    limit = detector.file_limit(allow, generated)
    profile = PURPOSES[purpose] if purpose else Config().profile
    detector.note("profile", profile, "purpose" if purpose else "default")
    config = {"allow_paths": allow, "generated_paths": generated, "protected_paths": detector.protected(generated),
              "profile": profile, "max_file_bytes": limit}
    config["max_packet_bytes"], request = detector.encoded_sizes()
    policy = {"allow_paths": allow, "deny_paths": data["deny_paths"], "fixture_roots": data["fixture_roots"],
              "max_file_bytes": limit, "max_request_bytes": request, "profile": profile}
    return {
        "schema_version": 1,
        "mode": "init-detect",
        "head": head,
        "config": config,
        "gate_policy_draft": {"model_review": policy},
        "tests": detector.tests(),
        "private_paths": {"count": len(data["private"]), "examples": _examples(data["private"])},
        "evidence": detector.evidence,
        "evidence_not_listed": detector.truncated,
        "warnings": detector.warnings,
        "purpose_choices": sorted(PURPOSES),
        "files_read_from": "committed revision only",
        "commands_run": [],
        "source_detected": detector.has_source,
        "written": False,
    }


_DETECT_ONLY = ("detect_repo", "revision", "write")
_LOCAL_PROVIDERS = {"offline", "ollama"}


def _configured(args, config: Config) -> Config:
    """The configuration init writes: the base, the provider choices and their required prices."""
    from dataclasses import replace

    if args.profile and args.purpose:
        raise AssistantError("init_profile_and_purpose_conflict")
    if args.purpose is not None and args.purpose not in PURPOSES:
        raise AssistantError("invalid_purpose")
    prices = {"input_usd_per_million": config.input_usd_per_million,
              "output_usd_per_million": config.output_usd_per_million}
    for name in prices:
        if getattr(args, name) is not None:
            prices[name] = getattr(args, name)
    # A paid provider without prices would write a configuration every review refuses.
    if args.provider not in _LOCAL_PROVIDERS and any(value <= 0 for value in prices.values()):
        raise prices_required(prices)
    updates = {"provider": args.provider, "model": args.model, "profile_files": (), "profiles": dict(config.profiles),
               "profile": PURPOSES[args.purpose] if args.purpose else args.profile or config.profile, **prices}
    if args.api_key_env is not None:
        updates["api_key_env"] = args.api_key_env
    return replace(config, **updates)


def run_init(args, config: Config) -> int:
    from dataclasses import replace

    if not args.detect and any(getattr(args, name) not in (None, False) for name in _DETECT_ONLY):
        raise AssistantError("init_option_requires_detect")
    configured = _configured(args, config)
    if not args.detect:
        save_config(Path(args.output), configured)
        print(canonical({"created": args.output, "network_enabled": False}).decode())
        return 0
    proposal = detect(Path(args.detect_repo or "."), revision=args.revision or "HEAD", purpose=args.purpose)
    detected = proposal["config"]
    if not args.purpose:
        detected["profile"] = configured.profile
    packet = max(configured.max_packet_bytes, detected["max_packet_bytes"])
    proposed = replace(configured, allow_paths=tuple(detected["allow_paths"]),
                       generated_paths=tuple(detected["generated_paths"]),
                       protected_paths=tuple(detected["protected_paths"]),
                       max_file_bytes=detected["max_file_bytes"], max_packet_bytes=packet, profile=detected["profile"])
    proposed.validate()  # The proposal is checked by the same rules as a saved configuration.
    document = config_document(proposed)
    proposal["config"] = {key: document[key] for key in (
        "provider", "model", "profile", "allow_paths", "generated_paths", "protected_paths", "max_file_bytes",
        "max_packet_bytes", "input_usd_per_million", "output_usd_per_million")}
    proposal["gate_policy_draft"]["model_review"]["profile"] = detected["profile"]
    if args.write:
        if not proposal["source_detected"]:
            raise AssistantError("detect_no_source_to_write")
        save_config(Path(args.output), proposed)
        proposal.update(written=True, created=args.output)
    print(canonical(proposal).decode())
    return 0
