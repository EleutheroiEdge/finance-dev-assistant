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
from decimal import ROUND_CEILING, Decimal
import json
from pathlib import PurePosixPath
import re
import shlex
import subprocess
import tomllib
from urllib.parse import urlsplit

from .config import MAX_PACKET_BYTES, Config
from .errors import AssistantError, prices_required
from .model_policy import missing_fields
from .review import ENVELOPE_ALLOWANCE, reserved_usd
from .scope import git, git_command, git_environment, resolve
from .security import _check_model_private, TEXT_SUFFIXES, check_path, check_text, local_name

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
# Words in a repository's own description that point to what its code does. A purpose is
# inferred only when at least three of its words appear and it leads the next by two.
PURPOSE_WORDS = {
    "quant": ("portfolio", "rebalanc", "optimizer", "backtest", "tax lot", "tax-lot", "wash sale",
              "allocation", "holdings", "securities", "trading", "drift"),
    "accounting": ("ledger", "invoice", "billing", "subscription", "journal entr", "accounts payable",
                   "accounts receivable", "reconciliation", "payroll", "bookkeeping", "chart of accounts"),
    "research": ("investment research", "equity research", "thesis", "valuation", "earnings", "filings",
                 "10-k", "analyst", "discounted cash flow"),
}
_HISTORY = 40  # Recent first-parent changes whose sizes shape the packet and request limits.
_EXAMPLES = 20
_FENCE = re.compile(r"^(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)")


def _shown(name: str) -> str:
    return local_name(name)


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
        self.texts: dict[str, str | None] = {}
        self.ratios = (1.1, 1.25)  # Encoded size per source byte: in a packet, in a request.

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
        """A small committed text file, or None; read, and warned about, once."""
        if path not in self.texts:
            self.texts[path] = self._read(path)
        return self.texts[path]

    def _read(self, path: str) -> str | None:
        """A small committed text file, or None. Never the working tree.

        The shared path policy is applied before any read, so a private, credential or
        reserved name is never opened, whatever directory it is in.
        """
        if path not in self.files or self.private(path) or _refusal(path):
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

    def note(self, field: str, value, rule: str, path: str | None = None, line: int | None = None,
             **extra) -> None:
        """Record why a value was proposed; at most 20 entries per field are kept, the rest counted."""
        if len(self.evidence.get(field, ())) >= _EXAMPLES:
            self.truncated[field] = self.truncated.get(field, 0) + 1
            return
        entry = {"value": value, "rule": rule, **extra}
        if path is not None:
            entry["path"] = _shown(path)
        if line is not None:
            entry["line"] = line
        self.evidence.setdefault(field, []).append(entry)

    # Layout ------------------------------------------------------------------
    def private(self, path: str) -> bool:
        """Whether the shared path policy, or the gate's private names, treats this name as private.

        The same rule guards every read, so a name refused anywhere is never read or sized here.
        """
        return _refusal(path) in _PRIVACY_CODES or PurePosixPath(path).suffix.lower() in PRIVATE_SUFFIXES

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
        if not self.has_source:
            self.warn("no_source_detected")
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
        # A range that changes a reviewable file outside allow_paths is left incomplete or refused,
        # so other directories of text, and root text files such as a roadmap, are proposed too.
        # That includes hidden ones, such as .github/ and .pre-commit-config.yaml: workflow and
        # tool settings change in many pull requests. A private file never counts toward a
        # directory, at any depth: the path policy refuses .env files, .git, .aws, a hidden
        # spelling of a private name such as .secrets, and credential stores such as
        # .docker/config.json, and the same rule guards every read and every size below.
        others: dict[str, str] = {}
        for path in sorted(self.files):
            parts = PurePosixPath(path).parts
            if (self.private(path) or _refusal(path)
                    or PurePosixPath(path).suffix.lower() not in TEXT_SUFFIXES
                    or any(character in parts[0] for character in "*?[]")):  # A gate policy refuses such a prefix.
                continue
            if len(parts) == 1:
                if path not in LOCKFILES:
                    others.setdefault(path, path)
            elif parts[0].lower() not in NOT_SOURCE:
                others.setdefault(parts[0] + "/", path)
        for prefix, example in others.items():
            if not _allowed(example, allow):
                allow.append(prefix)
                self.note("allow_paths", prefix, "text_files" if prefix.endswith("/") else "root_text_file", example)
        return {"allow_paths": allow}

    def profile(self, purpose: str | None, stated: str | None) -> str:
        """The profile to propose: the stated purpose or profile, else what the description points to."""
        if purpose or stated:
            profile = PURPOSES[purpose] if purpose else stated
            self.note("profile", profile, "purpose" if purpose else "stated")
            return profile
        inferred, words = self.purpose()
        if inferred:
            self.note("profile", PURPOSES[inferred], "described_as", purpose=inferred, words=words[inferred])
            return PURPOSES[inferred]
        self.note("profile", Config().profile, "default")
        self.warn("purpose_not_stated", choices=sorted(PURPOSES))
        return Config().profile

    def purpose(self) -> tuple[str | None, dict[str, list[str]]]:
        """The purpose the repository's own description points to, and the words found for each.

        Only the README and agent instruction files are read, as data.
        """
        text = " ".join(filter(None, (self.read(name) for name in ("README.md", "README.rst", *AGENT_DOCS)))).lower()
        found = {name: sorted(word for word in words if word in text) for name, words in PURPOSE_WORDS.items()}
        best, second = sorted(found, key=lambda name: (-len(found[name]), name))[:2]
        if len(found[best]) >= 3 and len(found[best]) - len(found[second]) >= 2:
            return best, found
        return None, found

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
        inside = outside = 0
        for path in private:
            parts = PurePosixPath(path).parts
            suffix = PurePosixPath(path).suffix.lower()
            lowered = [part.lower() for part in parts[:-1]]
            root = "/".join(parts[:-1]) + "/"
            if (suffix in {".csv", ".tsv"} and ("tests" in lowered or "fixtures" in lowered)
                    and _fixture_refusal(path, root) is None):
                fixtures.setdefault(root, path)
            elif _allowed(path, allow):
                inside += 1
            else:
                outside += 1
        for root, example in sorted(fixtures.items()):
            self.note("fixture_roots", root, "csv_or_tsv_under_tests", example)
        if fixtures:
            self.warn("fixture_roots_must_be_synthetic", count=len(fixtures))
        # A gate refuses any range that changes a private file, by its name. No deny_paths entry is
        # drafted for one: the name rule already covers it, and an entry would refuse the range
        # even under skip-and-report, which otherwise withholds the file and reviews the rest.
        if inside:
            self.warn("private_paths_inside_scope", count=inside)
        if outside:
            self.warn("private_paths_outside_scope", count=outside)
        return {"private": private, "fixture_roots": sorted(fixtures), "deny_paths": []}

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
            if self.private(path) or _refusal(path):  # Never read a name the path policy refuses.
                continue
            data = git(self.repo, "cat-file", "blob", f"{self.head}:{path}", binary=True)
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue  # Review refuses it as non_text_blob; it can't shape a limit.
            single = json.dumps(text)
            double = json.dumps(single)
            if len(double) > twice and size:
                self.ratios = (len(single) / size, len(double) / size)
            once, twice = max(once, len(single)), max(twice, len(double))
        packet, request = 2 * once + _ROOM, 2 * twice + _ROOM
        if request > MAX_PACKET_BYTES:
            self.warn("request_cap_cannot_fit_file", limit=MAX_PACKET_BYTES, needed=request)
        self.note("max_request_bytes", min(MAX_PACKET_BYTES, max(120_000, request)), "largest_encoded_source_file")
        return min(MAX_PACKET_BYTES, max(120_000, packet)), min(MAX_PACKET_BYTES, max(120_000, request))

    def history(self, allow: list[str], generated: list[str], limit: int) -> list[tuple[str, int, int]]:
        """(commit, bytes of earlier plus later text, changed paths) for recent first-parent changes.

        Sizes come from Git's object headers: no file is read. A name the path policy treats
        as private, or that the proposal would not review, is skipped before its size is asked for.

        It also counts the changes that hold a file the proposal cannot review, though the file is
        not private: one outside allow_paths, with an unsupported suffix or over the file limit. A
        gate refuses such a range unless `unreviewable_paths` is skip-and-report.
        """
        try:
            chain = git(self.repo, "rev-list", "--first-parent", f"--max-count={_HISTORY + 1}", self.head).split()
        except AssistantError:
            return []
        changes, wanted = [], set()
        for commit, parent in zip(chain, chain[1:], strict=False):
            try:
                raw = git(self.repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--raw", "-z",
                          "--no-abbrev", parent, commit, binary=True)
            except AssistantError:
                break  # A shallow clone has no earlier history.
            records = raw.split(b"\0")
            sides, unreviewable = [], False
            for index in range(0, len(records) - 1, 2):
                meta = records[index].split()
                try:
                    path = records[index + 1].decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if len(meta) < 5 or self.private(path) or _refusal(path):
                    continue
                if not _allowed(path, allow) or _unsupported(path):
                    unreviewable = True  # By its name alone; a private name never counts here.
                if (not _allowed(path, allow) or _allowed(path, generated)
                        or PurePosixPath(path).suffix.lower() not in TEXT_SUFFIXES):
                    continue
                pair = [oid.decode("ascii") for mode, oid in zip(meta[0:2], meta[2:4], strict=True)
                        if mode.lstrip(b":") in (b"100644", b"100755")]
                sides.append(pair)
                wanted.update(pair)
            changes.append((commit, sides, (len(records) - 1) // 2, unreviewable))
        sizes = self._sizes(sorted(wanted))
        rows, held = [], 0
        for commit, sides, paths, unreviewable in changes:
            kept = [pair for pair in sides if all(sizes.get(oid, limit + 1) <= limit for oid in pair)]
            held += unreviewable or len(kept) < len(sides)
            if kept:
                rows.append((commit, sum(sizes[oid] for pair in kept for oid in pair), paths))
        if held:
            self.warn("unreviewable_files_in_recent_changes", count=held, changes_measured=len(changes))
        return rows

    def fit_recent(self, packet: int, request: int, allow: list[str], generated: list[str],
                   limit: int) -> tuple[int, int, int]:
        """Packet and request limits, and a file count, that also fit the largest recent change.

        One file's change is the floor; the largest recent change is what a range really needs.
        """
        files = 20
        recent = self.history(allow, generated, limit)
        if not recent:
            return packet, request, files
        commit, raw, _paths = max(recent, key=lambda row: row[1])
        once, twice = self.ratios
        packet_needed, request_needed = int(raw * once) + _ROOM, int(raw * twice) + _ROOM
        why = {"commit": commit[:12], "changes_measured": len(recent)}
        if request_needed > MAX_PACKET_BYTES:
            self.warn("recent_change_over_ceiling", limit=MAX_PACKET_BYTES, needed=request_needed, **why)
        if _fit(packet_needed) > packet:
            packet = _fit(packet_needed)
            self.note("max_packet_bytes", packet, "largest_recent_change", **why)
        if _fit(request_needed) > request:
            request = _fit(request_needed)
            self.note("max_request_bytes", request, "largest_recent_change", **why)
        files = min(2000, max(files, -(-max(row[2] for row in recent) * 3 // 20) * 10))
        self.note("max_files", files, "largest_recent_change", changes_measured=len(recent))
        return packet, request, files

    def _sizes(self, oids: list[str]) -> dict[str, int]:
        """Blob sizes from object headers, in one Git process. Contents are never read."""
        if not oids:
            return {}
        try:
            done = subprocess.run(git_command(self.repo, "cat-file", "--batch-check"),
                                  input=("\n".join(oids) + "\n").encode("ascii"), env=git_environment(),
                                  capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            return {}
        sizes = {}
        if done.returncode == 0:
            for line in done.stdout.decode("ascii", "replace").splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[1] == "blob" and parts[2].isdigit():
                    sizes[parts[0]] = int(parts[2])
        return sizes

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


_PRIVACY_CODES = {"private_path", "private_profile_path", "gate_private_path"}


def _refusal(path: str) -> str | None:
    """The code the shared path policy or the gate's private names give this name, or None.

    Names only: nothing is read. Binary and data formats come back as private_or_binary_path.
    """
    try:
        check_path(path, source_only=False, metadata_only=True)
        _check_model_private(path)
    except AssistantError as exc:
        return exc.code
    return None


def _unsupported(path: str) -> bool:
    """Whether a review refuses this name for its suffix alone. Names only."""
    try:
        check_path(path)
    except AssistantError as exc:
        return exc.code == "unsupported_file_type"
    return False


def _fixture_refusal(path: str, root: str) -> str | None:
    """The code the path policy gives this file as a fixture under `root`, or None. Names only.

    A root the gate would refuse is never drafted: one under a private or reserved directory, in
    any spelling the policy reads as that name.
    """
    try:
        check_path(path, source_only=False, fixture_roots=(root,))
    except AssistantError as exc:
        return exc.code
    return None


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


def _fit(needed: int) -> int:
    """Round up to 16 KiB, within the ceiling."""
    return min(MAX_PACKET_BYTES, -(-needed // 16_384) * 16_384)


def detect(repo, *, revision: str = "HEAD", purpose: str | None = None, profile: str | None = None) -> dict:
    """A proposal for this repository. Nothing is written and nothing from the repository runs.

    `profile` is one the person already chose; without it or a purpose, the repository's own
    description decides, and the default is proposed with a warning when that is unclear.
    """
    if purpose is not None and purpose not in PURPOSES:
        raise AssistantError("invalid_purpose")
    head = resolve(repo, revision)
    detector = _Detector(repo, head)
    detector.list_files()
    if not detector.files:
        raise AssistantError("detect_empty_repository")
    allow = detector.layout()["allow_paths"]
    generated = detector.generated()
    data = detector.data(allow)
    limit = detector.file_limit(allow, generated)
    profile = detector.profile(purpose, profile)
    config = {"allow_paths": allow, "generated_paths": generated, "protected_paths": detector.protected(generated),
              "profile": profile, "max_file_bytes": limit}
    config["max_packet_bytes"], request = detector.encoded_sizes()
    config["max_packet_bytes"], request, files = detector.fit_recent(
        config["max_packet_bytes"], request, allow, generated, limit)
    # Every field that follows from the repository. The provider, its key variable, prices and
    # budgets are the person's choice: `init` adds them from its options, and what is still
    # absent is listed in gate_policy_missing.
    policy = {"enabled": True, "allow_paths": allow, "deny_paths": data["deny_paths"],
              "fixture_roots": data["fixture_roots"], "max_file_bytes": limit, "max_request_bytes": request,
              "max_files": files, "profile": profile, "max_output_tokens": 4096,
              "timeout_seconds": 300 if request > 1_000_000 else 120, "blocking_severities": ["critical", "high"]}
    draft = {"schema_version": 2, "model_review": policy}
    return {
        "schema_version": 1,
        "mode": "init-detect",
        "head": head,
        "config": config,
        "gate_policy_draft": draft,
        "gate_policy_missing": missing_fields(draft),
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


def _provider_fields(configured: Config, model: dict) -> dict:
    """The gate policy fields that are the person's choice, from what `init` was given.

    Nothing is invented: a field stays absent until an option or the configuration states it.

    The run budget is the largest reserve a request within the proposed limit can need, by the
    gate's own arithmetic. A gate reserves max(packet + instructions, request body) plus a fixed
    allowance as input units. The body holds the packet and the instructions, each escaped, so it
    is never the smaller, and the gate refuses a body over max_request_bytes before it reserves.
    """
    if configured.provider == "offline" or not configured.model:
        return {}
    fields = {"provider": configured.provider, "model": configured.model}
    endpoint = configured.resolved_endpoint
    host = urlsplit(endpoint).hostname if endpoint else None
    if host:
        fields.update(endpoint=endpoint, allowed_host=host)
    if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", configured.key_name or ""):
        fields["api_key_env"] = configured.key_name
    prices = (configured.input_usd_per_million, configured.output_usd_per_million)
    if configured.provider == "ollama" or all(value > 0 for value in prices):
        reserve = reserved_usd(model["max_request_bytes"] + ENVELOPE_ALLOWANCE, model["max_output_tokens"], *prices)
        run = max(Decimal(str(configured.max_run_usd)), reserve.quantize(Decimal("0.01"), rounding=ROUND_CEILING))
        daily = max(Decimal(str(configured.daily_budget_usd)), 3 * run)
        fields.update(input_usd_per_million=prices[0], output_usd_per_million=prices[1],
                      max_run_usd=float(run), daily_budget_usd=float(daily))
    return fields


def run_init(args, config: Config) -> int:
    from .initialization import run_init as initialize

    return initialize(args, config)
