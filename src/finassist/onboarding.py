"""One-run local readiness preflight for a gate range (#64).

It reads Git objects, the pinned policy at base and the operator's token file. It never
reads a provider key value, uses the network, opens the ledger or spends. Path names
appear only in this local report, as "[redacted]" when a name itself fails screening.
They never enter a packet, gate report or audit row. The checks reuse the gate's own
functions, and once those pass the real loader and source builder run as well, so the
preflight cannot report ready for a range the gate would refuse at those steps.
"""

from dataclasses import fields
from decimal import Decimal
import os
from pathlib import Path, PurePosixPath
import re
import unicodedata
from urllib.parse import urlsplit

import jsonschema

from .ci_policy import decode_document
from .config import Config
from .errors import AssistantError
from .forbidden_tokens import screen_packet, screen_source
from .model_gate import name_outcome, prepare_model_source, prepare_token_guard
from .model_policy import (_PROPERTIES, _SCHEMA, ModelGatePolicy, _prefix, _profile, load_model_policy,
                           policy_config_fields)
from .policy_fixtures import fixture_settings, load_policy_config
from .policy_ignores import screen_ignores
from .providers import request_payload
from .review import review_schema, spend_estimate
from .error_hints import error_fields
from .scope import WITHHELD_REASON, git, omission_for, read_entry, read_sides, require_regular, resolve
from .security import (TEXT_FIXTURE_SUFFIXES, canonical, local_name, check_fixture_private, check_name,
                       check_path, check_text, digest, refusal_location, regular_path)

HINTS = {
    "invalid_revision": "Pass a commit that exists in this repository.",
    "git_commit_unavailable": "Fetch the commit first; the preflight never fetches.",
    "gate_policy_missing_at_base": "Commit the policy on the base branch. The gate reads it at base, never from the working "
                                   "tree. For a past range, preflight with --policy-file instead.",
    "gate_policy_pin_required": "Pass --policy-sha256 as 64 lowercase hex characters, or omit it to see the value.",
    "gate_policy_pin_mismatch": "The pin must equal the sha256 of the policy bytes at base, shown in policy.sha256.",
    "gate_policy_invalid": "Fix the named field. Allowed values are shown; the current value is never echoed.",
    "gate_model_opt_in_required": "Use schema_version 2 with a model_review object.",
    "sensitive_content": "Remove credential-like text. A policy may name a key variable but never hold a key.",
    "hidden_characters": "Remove the character that is not shown, on the lines listed. It is never left out or skipped.",
    "gate_policy_path_invalid": "Use literal path prefixes; wildcards are not supported.",
    "fixture_root_invalid": "Use literal fixture prefixes; wildcards are not supported.",
    "fixture_root_contains_data": "A fixture root cannot sit under a private data directory.",
    "fixture_root_unqualified": "A fixture root without a tests or fixtures component needs a .finledgerpoli-synthetic "
                                "marker at base whose first line is 'synthetic: true'.",
    "gate_endpoint_host_mismatch": "Set allowed_host to the endpoint's host.",
    "provider_prices_required": "Set both prices above zero, in US dollars per million tokens.",
    "provider_key_missing": "Set the named environment variable before gate run. The preflight checks only that it is set.",
    "gate_profile_missing_at_base": "Commit the profile file on the base branch.",
    "gate_profile_pin_mismatch": "Update profile_sha256 to the profile bytes at base.",
    "empty_review_scope": "The range changes no files.",
    "gate_file_count_exceeded": "Raise max_files (up to 2000) or review a smaller range.",
    "gate_policy_change_requires_review": "The range changes the policy itself. Land the policy change on its own first.",
    "gate_profile_change_requires_review": "The range changes the profile file. Land that change on its own first.",
    "gate_fixture_marker_change_requires_review": "The range changes a fixture marker. Land that change on its own first.",
    "gate_ignore_change_requires_review": "The range changes a .gitignore file. Land that change on its own first.",
    "gate_path_not_allowed": "Add a prefix covering this path to allow_paths, or keep the file out of the range.",
    "gate_denied_path": "deny_paths excludes this path. Keep the file out of the range.",
    "private_or_binary_path": "Data and binary formats are always refused, whatever text_suffixes says.",
    "gate_private_path": "Paths with a private component (data, private, client, household) are never reviewed.",
    "private_path": "This path is always private and is never reviewed.",
    "unsupported_file_type": "Only text source suffixes are reviewed.",
    "unsafe_path": "The path is unsafe to read; rename it.",
    "file_limit_exceeded": "Raise max_file_bytes (up to 2,000,000; fixture_max_file_bytes for fixtures) "
                           "or keep the file out of the range.",
    "non_text_blob": "Only UTF-8 text is reviewed.",
    "gate_ignored_path": "A .gitignore rule at base or merge base ignores this path.",
    "linked_or_special_git_object": "Symbolic links and submodules are not reviewed.",
    "forbidden_token_present": "This content contains a listed confidential figure.",
    "forbidden_token_file_invalid": "The token file must be an absolute path outside every checkout of the repository.",
    "forbidden_token_source_invalid": "Each figure source must be a delimited text file outside every checkout "
                                      "of the repository, with at least one numeric cell.",
    "gate_request_bytes_exceeded": "Raise max_request_bytes (up to 8,000,000) or review a smaller range.",
    "run_budget_exceeded": "Raise max_run_usd above the reserved estimate, or review a smaller range.",
    "daily_budget_exceeded": "Raise daily_budget_usd above the reserved estimate.",
    "path_name_not_utf8": "Rename the changed files whose names are not UTF-8 text; the gate can't read them.",
    "preflight_check_failed": "A preflight step failed on unexpected input. Check the repository and policy, then rerun.",
}
_DEFAULT_HINT = "See the pre-merge gate guide for this code."
WARNINGS = {
    "full_revisions_required": "gate run needs the full commit hashes shown in base and head.",
    "policy_pin_not_supplied": "gate run needs --policy-sha256 with the value in policy.sha256.",
    "prefix_matches_nothing": "This prefix matches no tracked file at head, so it has no effect.",
    "prefix_outside_allow_paths": "This prefix is outside every allow_paths prefix, so it has no effect.",
    "file_limit_above_request_limit": "max_file_bytes is above max_request_bytes, so the request limit applies first.",
    "daily_budget_below_run_budget": "daily_budget_usd is below max_run_usd, so a full run can never fit in one day.",
    "fixture_limit_without_roots": "fixture_max_file_bytes has no effect without fixture_roots.",
    "private_paths_withheld": "These private paths will be withheld unread; the review's coverage will be incomplete.",
    "unreviewable_paths_left_out": "These files cannot be reviewed and will be left out; the review's coverage will be "
                                   "incomplete.",
    "policy_from_working_tree": "Read from a file on this machine, so this preflight authorizes nothing: gate run reads "
                                "the policy only at --base.",
}
_BOUNDS = ("type", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "enum", "const", "pattern")
_MAX_ROWS = 2000  # The most changed files a policy can allow; longer ranges are summarized.
_EXAMPLES = 20  # Example names kept per grouped path blocker.


def _format_hint(path: str) -> str:
    """The remedy that can actually work for a refused data or binary file."""
    if PurePosixPath(path).suffix.lower() in TEXT_FIXTURE_SUFFIXES:
        try:
            check_fixture_private(path)
        except AssistantError:
            return "This is private data. It is never reviewed; keep it out of the range."
        return ("A synthetic fixture in this format can be admitted with fixture_roots: a root under a tests "
                "or fixtures directory, or one with a .finledgerpoli-synthetic marker.")
    return "This format is always refused and can't be admitted as a fixture; keep it out of the range."


def _shown_argument(value: str, placeholder: str = "<repository>") -> str:
    """A local command-line argument for display, or a placeholder when it fails screening."""
    try:
        if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
            raise AssistantError("unsafe_path")
        check_text(value)
    except AssistantError:
        return placeholder
    return value


def _shown(name, extra_patterns: tuple[str, ...] = ()) -> str:
    return local_name(name, extra_patterns)


def _schema_issues(document: dict) -> list[dict]:
    """Every schema error with its field and allowed values; current values are never echoed."""
    issues = []
    errors = jsonschema.Draft202012Validator(_SCHEMA).iter_errors(document)
    for error in sorted(errors, key=lambda item: [str(part) for part in item.absolute_path]):
        issue = {"field": "/" + "/".join(_shown(str(part)) for part in error.absolute_path),
                 "rule": error.validator}
        instance = error.instance if isinstance(error.instance, dict) else {}
        if error.validator == "additionalProperties":
            known = set(error.schema.get("properties", {}))
            issue["unknown"] = sorted(_shown(name) for name in instance if name not in known)
        elif error.validator == "required":
            issue["missing"] = sorted(name for name in error.validator_value if name not in instance)
        elif error.validator == "dependentRequired":
            issue["missing"] = sorted(need for name, needs in error.validator_value.items()
                                      if name in instance for need in needs if need not in instance)
        elif error.validator == "not":
            issue["allowed"] = "profile_text or profile_path, not both"
        else:
            issue["allowed"] = {key: error.schema[key] for key in _BOUNDS if key in error.schema}
        issues.append(issue)
    return issues


def _out_by_name(path: str, model: dict, config) -> bool:
    """Whether the gate sets this path aside before its ignore check: withheld or left out by name.

    The gate refuses a denied path, and any other refused name, before it screens ignore rules,
    so those stay in the preflight's scope and keep their own row.
    """
    try:
        return name_outcome(path, config, model["deny_paths"])[0] != "review"
    except AssistantError:
        return False


def _matches(path, prefix):
    """Prefix rule for str or bytes names: a trailing slash matches a directory."""
    slash = "/" if isinstance(prefix, str) else b"/"
    return path.startswith(prefix) if prefix.endswith(slash) else path == prefix


_CONFIG_FIELDS = frozenset(item.name for item in fields(Config))


def _looks_like_configuration(document) -> bool:
    """A finassist.json configuration given where a gate policy belongs."""
    if not isinstance(document, dict) or "model_review" in document:
        return False
    keys = set(document) - {"schema_version", "$schema"}
    return bool(keys) and keys <= _CONFIG_FIELDS


def _names(raw: bytes) -> tuple[list[str], set[bytes]]:
    """Git -z names as text, plus the raw names that are not UTF-8 (never decoded for display)."""
    names, undecodable = [], set()
    for part in raw.split(b"\0"):
        if part:
            try:
                names.append(part.decode("utf-8"))
            except UnicodeDecodeError:
                undecodable.add(part)
    return names, undecodable


class _Preflight:
    def __init__(self, repo: Path, base: str, head: str, policy_path: str, pin: str | None, environment,
                 policy_file: str | None = None):
        self.repo, self.base_ref, self.head_ref = repo, base, head
        self.policy_path, self.pin = policy_path, pin
        # A file on this machine instead of the policy at base: same checks, no authority.
        self.policy_file = policy_file
        # Names only, taken once. Iterating an environment mapping yields names, while
        # a membership test on os.environ looks up and decodes the value.
        self.environment_names = frozenset(iter(environment))
        self.report = {
            "schema_version": 1, "mode": "gate-preflight", "status": "blocked", "base": None, "head": None,
            "policy": {"path": _shown(policy_path) if policy_file is None else _shown_argument(policy_file, "<policy file>"),
                       "source": "base" if policy_file is None else "working-tree", "sha256": None,
                       "pin": "not_supplied" if pin is None else "unchecked"},
            "blockers": [], "warnings": [], "paths": [], "coverage_complete": None, "request": None,
            "provider": None, "network_used": False, "key_value_read": False, "ledger_opened": False,
            "next_step": None,
        }
        self._seen: set[bytes] = set()
        # Path refusals are grouped by code and hint: a count plus a few example names,
        # so the report stays bounded whatever the size of the range.
        self._grouped: dict[tuple[str, str], dict] = {}

    def block(self, code: str, **details) -> None:
        entry = {"code": code, **details}
        entry.setdefault("hint", HINTS.get(code) or error_fields(code).get("hint", _DEFAULT_HINT))
        key = canonical(entry)
        if key not in self._seen:
            self._seen.add(key)
            self.report["blockers"].append(entry)

    def block_path(self, code: str, path: str, hint: str | None = None) -> None:
        hint = hint or HINTS.get(code) or error_fields(code).get("hint", _DEFAULT_HINT)
        group = self._grouped.setdefault((code, hint), {"code": code, "count": 0, "paths": [], "hint": hint})
        group["count"] += 1
        if len(group["paths"]) < _EXAMPLES:
            group["paths"].append(path)

    def failed(self, exc: AssistantError, **details) -> None:
        self.block(exc.code, **exc.public_details, **details)

    def warn(self, code: str, **details) -> None:
        self.report["warnings"].append({"code": code, **details, "hint": WARNINGS[code]})

    def run(self) -> dict:
        try:
            self._run()
        except AssistantError as exc:
            self.failed(exc)
        except (OSError, ValueError, LookupError) as exc:
            # Keep the report: name the failing step's class, never its message.
            self.block("preflight_check_failed", kind=type(exc).__name__)
        self.report["blockers"].extend(self._grouped.values())
        ready = not self.report["blockers"]
        self.report["status"] = "ready" if ready else "blocked"
        if ready and self.policy_file is not None:
            self.report["next_step"] = ("The range passes this policy file, but gate run reads a policy only at --base. "
                                        "Commit it on the base branch through review, then preflight with --policy "
                                        "and run the gate.")
        elif ready:
            self.report["next_step"] = {"command": [
                "finassist", "gate", "run", "--repo", _shown_argument(str(self.repo)), "--base", self.report["base"],
                "--head", self.report["head"], "--policy", self.report["policy"]["path"],
                "--policy-sha256", self.report["policy"]["sha256"],
                "--state-dir", "<private state directory>", "--output", "<new report file>"]}
        else:
            self.report["next_step"] = "Fix every blocker listed, then run this preflight again."
        return self.report

    def _run(self) -> None:
        repo = regular_path(self.repo)
        try:
            base, head = resolve(repo, self.base_ref), resolve(repo, self.head_ref)
        except AssistantError as exc:
            return self.failed(exc)
        self.report.update(base=base, head=head)
        if (self.base_ref, self.head_ref) != (base, head):
            self.warn("full_revisions_required")
        policy = self._policy(repo, base)
        if policy is None:
            return None
        self._prefix_warnings(repo, head, policy.document["model_review"])
        self._paths(repo, base, head, policy)
        # The gate's own loader and source builder run only once nothing else blocks.
        # A missing key variable is the one exception: it doesn't change the source.
        if not self._grouped and all(entry["code"] == "provider_key_missing" for entry in self.report["blockers"]):
            self._gate_source(repo, base, head, policy)
        return None

    def _working_tree_policy(self, repo: Path) -> tuple[str, bytes]:
        """Policy bytes from a file on this machine. The preflight that reads them authorizes nothing."""
        file = regular_path(Path(self.policy_file))
        try:
            if not file.is_file():
                raise AssistantError("policy_file_unavailable")
            with file.open("rb") as handle:
                raw = handle.read(128_001)  # Never more than the cap and one byte, whatever the file's size.
            if len(raw) > 128_000:
                raise AssistantError("file_limit_exceeded", {"limit": 128_000, "bytes": file.stat().st_size})
        except OSError as exc:
            raise AssistantError("policy_file_unavailable") from exc
        # Inside the repository, its path still lets a change to it in the range be caught.
        try:
            path = file.relative_to(repo).as_posix()
        except ValueError:
            path = ""
        return path, raw

    def _policy(self, repo: Path, base: str) -> ModelGatePolicy | None:
        try:
            if self.policy_file is None:
                path = check_path(self.policy_path, source_only=False)
                raw, _ = read_entry(repo, base, path, 128_000)
            else:
                path, raw = self._working_tree_policy(repo)
        except AssistantError as exc:
            return self.failed(exc)
        if raw is None:
            return self.block("gate_policy_missing_at_base")
        sha = self.report["policy"]["sha256"] = digest(raw)
        if self.policy_file is not None:
            self.warn("policy_from_working_tree")
        if self.pin is None:
            if self.policy_file is None:  # gate run needs the pin; a policy file is never run.
                self.warn("policy_pin_not_supplied")
        elif not isinstance(self.pin, str) or re.fullmatch(r"[0-9a-f]{64}", self.pin) is None:
            self.report["policy"]["pin"] = "invalid"
            self.block("gate_policy_pin_required")
        else:
            self.report["policy"]["pin"] = "matches" if self.pin == sha else "mismatch"
            if self.pin != sha:
                self.block("gate_policy_pin_mismatch")
        try:
            document = decode_document(raw, "gate_policy_invalid")
        except AssistantError as exc:
            return self.failed(exc, field="/")
        if _looks_like_configuration(document):
            return self.block("gate_policy_is_configuration")
        if document.get("schema_version") == 1:
            return self.block("gate_model_opt_in_required")
        issues = _schema_issues(document)
        for issue in issues:
            self.block("gate_policy_invalid", **issue)
        if issues:
            return None
        model = document["model_review"]
        if type(document["schema_version"]) is not int:
            self.block("gate_policy_invalid", field="/schema_version", rule="integer")
        for field, schema in _PROPERTIES.items():
            if schema.get("type") == "integer" and type(model[field]) is not int:
                self.block("gate_policy_invalid", field="/model_review/" + field, rule="integer")
        # Checks on the policy bytes alone, with no reads it directs. A policy that fails
        # screening or path rules is not used to read anything else.
        usable = True
        try:
            check_text(canonical(document).decode())
        except AssistantError as exc:
            usable = False
            self.failed(exc, field="/")
        roots = tuple(model.get("fixture_roots", ()))
        for name in ("allow_paths", "deny_paths"):
            for index, prefix in enumerate(model[name]):
                try:
                    _prefix(prefix, roots, denied=name == "deny_paths")
                except AssistantError as exc:
                    usable = False
                    self.failed(exc, field=f"/model_review/{name}/{index}", prefix=_shown(prefix))
        try:
            host = urlsplit(model["endpoint"]).hostname
        except ValueError:
            usable = False
            self.block("gate_policy_invalid", field="/model_review/endpoint", rule="url")
        else:
            if host != model["allowed_host"]:
                self.block("gate_endpoint_host_mismatch", field="/model_review/allowed_host")
        prices = {name: model[name] for name in ("input_usd_per_million", "output_usd_per_million")}
        if model["provider"] != "ollama" and any(value <= 0 for value in prices.values()):
            self.block("provider_prices_required", missing=sorted(k for k, v in prices.items() if v <= 0))
        if model["max_file_bytes"] > model["max_request_bytes"]:
            self.warn("file_limit_above_request_limit")
        if model["daily_budget_usd"] < model["max_run_usd"]:
            self.warn("daily_budget_below_run_budget")
        if "fixture_max_file_bytes" in model and not roots:
            self.warn("fixture_limit_without_roots")
        if not usable or (self.pin is not None and self.report["policy"]["pin"] != "matches"):
            return None  # Nothing an unscreened or unconfirmed policy selects is read.
        try:
            settings = fixture_settings(repo, base, model)
        except AssistantError as exc:
            return self.failed(exc, field="/model_review/fixture_roots")  # The profile is not read either.
        try:
            profile_text, profile_path = _profile(repo, base, model)
        except AssistantError as exc:
            return self.failed(exc, field="/model_review/profile_path")  # Nothing later is read.
        try:
            config = load_policy_config(policy_config_fields(model, profile_text), settings)
        except AssistantError as exc:
            return self.failed(exc)
        key = config.key_name
        self.report["provider"] = {
            "provider": model["provider"], "key_variable": key,
            "key_variable_set": bool(key) and key in self.environment_names,
            "allowed_host": model["allowed_host"],
            "prices_configured": model["provider"] == "ollama" or all(value > 0 for value in prices.values()),
        }
        if key and key not in self.environment_names:
            self.block("provider_key_missing", variable=key)
        return ModelGatePolicy(document, config, path, sha, base, profile_path, repo)

    def _prefix_warnings(self, repo: Path, head: str, model: dict) -> None:
        # Tracked names are compared as bytes, so an unrelated name that isn't UTF-8
        # can't stop the preflight.
        tracked = [name for name in git(repo, "ls-tree", "-r", "--name-only", "-z", head, binary=True).split(b"\0")
                   if name]
        allow = model["allow_paths"]
        for name in ("allow_paths", "deny_paths", "fixture_roots"):
            for prefix in model.get(name, ()):
                encoded = prefix.encode("utf-8")
                if not any(_matches(path, encoded) for path in tracked):
                    self.warn("prefix_matches_nothing", field="/model_review/" + name, prefix=_shown(prefix))
                elif name != "allow_paths" and not any(
                        _matches(prefix, outer) or _matches(outer, prefix) for outer in allow):
                    self.warn("prefix_outside_allow_paths", field="/model_review/" + name, prefix=_shown(prefix))

    def _paths(self, repo: Path, base: str, head: str, policy: ModelGatePolicy) -> None:
        model, config = policy.document["model_review"], policy.config

        def changed(old: str, new: str) -> tuple[list[str], int]:
            return _names(git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z",
                              old, new, binary=True))

        ancestor = git(repo, "merge-base", base, head)
        paths, undecodable = changed(ancestor, head)
        base_names, base_undecodable = changed(base, head)
        # A reason that stops every content read; affected paths are reported unchecked.
        stopped = None
        names_not_utf8 = undecodable | base_undecodable  # Both comparisons, each name once.
        if names_not_utf8:
            self.block("path_name_not_utf8", count=len(names_not_utf8))
            stopped = "path_name_not_utf8"
        if not paths and not undecodable:
            return self.block("empty_review_scope")
        if len(paths) + len(undecodable) > model["max_files"]:
            self.block("gate_file_count_exceeded", files=len(paths) + len(undecodable), limit=model["max_files"])
            stopped = stopped or "gate_file_count_exceeded"
        # A change to the rules that screen the range stops the gate before it reads
        # any content, so the preflight reads none either.
        guarded = set(paths).union(base_names)
        markers = list(getattr(config, "fixture_markers", {}))
        rule_changes = []
        if policy.path in guarded:
            rule_changes.append(("gate_policy_change_requires_review", policy.path))
        if policy.profile_path and policy.profile_path in guarded:
            rule_changes.append(("gate_profile_change_requires_review", policy.profile_path))
        for name in sorted(guarded):
            if name in markers:
                rule_changes.append(("gate_fixture_marker_change_requires_review", name))
            if PurePosixPath(name).name == ".gitignore":
                rule_changes.append(("gate_ignore_change_requires_review", name))
        for code, name in rule_changes:
            self.block_path(code, _shown(name))
        if rule_changes:
            stopped = stopped or rule_changes[0][0]
        guard = None
        outside = next((name for name in ("forbidden_token_file", "forbidden_token_sources") if name in model), None)
        if stopped is None and outside and self.pin is None:
            # A file the policy points outside the repository is opened only once the
            # caller has confirmed the policy bytes with --policy-sha256.
            self.block("gate_policy_pin_required", field="/model_review/" + outside,
                       hint="Pass --policy-sha256 so the preflight may open the policy's figure files.")
            stopped = "gate_policy_pin_required"
        if stopped is None:
            try:
                guard = prepare_token_guard(policy, repo)
                if guard is not None:
                    screen_packet({"files": []}, config.instructions(), guard.snapshot)
            except AssistantError as exc:
                self.failed(exc, field="/model_review")
                stopped = exc.code
        ignored = set()
        if stopped is None:
            # The gate's ignore scope: the changed paths it reviews, plus the policy's profile and
            # fixture markers. A path it withholds by name is never read, so it is not screened.
            scope = ([path for path in paths if not _out_by_name(path, model, config)]
                     + ([policy.profile_path] if policy.profile_path else []) + markers)
            try:
                screen_ignores(repo, {base, ancestor}, scope)
            except AssistantError as exc:
                if exc.code != "gate_ignored_path":
                    self.failed(exc)
                    stopped = exc.code
                else:  # Name the ignored paths; this slower pass runs only when one exists.
                    for path in dict.fromkeys(scope):
                        try:
                            screen_ignores(repo, {base, ancestor}, [path])
                        except AssistantError as single:
                            if single.code != "gate_ignored_path":
                                self.failed(single)  # The check itself failed: nothing more is read.
                                stopped = single.code
                                break
                            ignored.add(path)
                    for path in sorted(ignored):  # Named once, whatever their row shows.
                        self.block_path("gate_ignored_path", _shown(path))
                    if stopped is None and ignored.difference(paths):
                        # An ignored profile or fixture marker is a screening input the gate
                        # refuses before reading any content, so the preflight reads none.
                        stopped = "gate_ignored_path"
        rows = [self._classify(repo, (ancestor, head), path, model, config, guard, ignored, stopped)
                for path in paths[:_MAX_ROWS]]
        self.report["paths"] = rows
        if len(paths) > _MAX_ROWS:
            self.report["paths_not_listed"] = len(paths) - _MAX_ROWS
        self.report["coverage_complete"] = (not names_not_utf8 and len(paths) <= _MAX_ROWS
                                            and all(row["status"] == "included" for row in rows))
        withheld = sum(row["status"] == "withheld" for row in rows)
        if withheld:
            self.warn("private_paths_withheld", count=withheld)
        left = sum(row["status"] == "omitted" for row in rows)
        if left:
            self.warn("unreviewable_paths_left_out", count=left)
        for row in rows:
            if row["status"] == "refused" and row["code"] != "gate_ignored_path":  # Ignored paths are named above.
                self.block_path(row["code"], row["path"], row.get("hint"))
        return None

    def _classify(self, repo: Path, revisions: tuple[str, str], path: str, model: dict, config, guard,
                  ignored: set[str], stopped: str | None) -> dict:
        ancestor, head = revisions
        row = {"path": _shown(path, config.extra_sensitive_patterns)}
        try:
            # Name-only rules first, by the gate's own function: they read nothing.
            outcome, reason = name_outcome(path, config, model["deny_paths"])
            if outcome != "review":
                # The gate sets this path aside unread, so it is not a blocker, unless the name
                # matches a configured pattern: then it refuses, as the gate does.
                check_name(path, extra_patterns=config.extra_sensitive_patterns)
                if outcome == "withheld":
                    return {**row, "status": "withheld", "reason": WITHHELD_REASON}
                require_regular(repo, revisions, path)  # Only an ordinary file is left out, as in the gate.
                return {**row, "status": "omitted", "reason": reason}
            if path in ignored:
                raise AssistantError("gate_ignored_path")
            if stopped is not None:
                return {**row, "status": "unchecked", "reason": stopped}
            # The gate's own reader and figure screen, one version at a time, so a version that
            # cannot be read never hides a figure or a credential in the other one.
            screen = None if guard is None else (lambda text, name: screen_source(text, name, guard.snapshot))
            before, after = (text for _data, _mode, text in read_sides(repo, revisions, path, config, screen))
            if guard is not None:
                screen_packet({"files": [{"path": path, "before": before, "after": after}]}, "", guard.snapshot)
        except AssistantError as exc:
            reason = None
            if exc.code != "gate_path_not_allowed":
                try:
                    reason = omission_for(repo, revisions, path, config, exc.code)
                except AssistantError as special:  # A link or submodule: never left out.
                    exc = special
            if reason is not None:
                return {**row, "status": "omitted", "reason": reason}  # A version too large, or not UTF-8 text.
            refused = {**row, "status": "refused", "code": exc.code, **exc.public_details, **refusal_location(exc)}
            if exc.code == "private_or_binary_path":
                refused["hint"] = _format_hint(path)
            return refused
        return {**row, "status": "included"}

    def _gate_source(self, repo: Path, base: str, head: str, policy: ModelGatePolicy) -> None:
        """Run the gate's own loader and source builder, then size the key-free request body."""
        try:
            if self.policy_file is None:
                gate_policy = load_model_policy(repo, base, policy.path, policy.sha256)
            else:  # Never read at base: the policy checked above is the one the source builder uses.
                gate_policy = policy
            packet = prepare_model_source(repo, base, head, gate_policy)
        except AssistantError as exc:
            return self.failed(exc)
        config, rules = gate_policy.config, gate_policy.document["model_review"]
        system = config.instructions()
        body = canonical(request_payload(config, system, packet, review_schema()))
        _, estimate = spend_estimate(packet, system, body, config, policy_bound=True)
        self.report["request"] = {"bytes": len(body), "limit": rules["max_request_bytes"],
                                  "reserved_usd": str(estimate), "prior_spend_checked": False}
        if len(body) > rules["max_request_bytes"]:
            self.block("gate_request_bytes_exceeded", bytes=len(body), limit=rules["max_request_bytes"])
        if estimate > Decimal(str(config.max_run_usd)):
            self.block("run_budget_exceeded", reserved_usd=str(estimate), limit_usd=str(config.max_run_usd))
        if estimate > Decimal(str(config.daily_budget_usd)):
            self.block("daily_budget_exceeded", reserved_usd=str(estimate), limit_usd=str(config.daily_budget_usd))
        return None


def policy_preflight(repo: Path, base: str, head: str, policy_path: str, policy_pin: str | None = None,
                     *, environment=None, policy_file: str | None = None) -> dict:
    """Every gate blocker for one range, in one local run.

    With policy_file, the policy comes from that file instead of the repository at base. The
    report then says so, and it never offers a gate run command: gate run reads only at base.
    """
    return _Preflight(Path(repo), base, head, policy_path, policy_pin,
                      os.environ if environment is None else environment, policy_file).run()


def run_policy_doctor(args) -> int:
    """Validate every preflight option before anything else runs; empty values count as missing."""
    if args.policy is None and args.policy_file is None and args.policy_sha256 is None:
        # A range alone checks the configuration route: plan, then review.
        from .config import load_config
        from .config_preflight import run_config_doctor

        return run_config_doctor(args, load_config(args.config))
    if args.config is not None or args.fix or args.check_updates or args.state_dir is not None:
        raise AssistantError("doctor_policy_options_conflict")
    if args.policy and args.policy_file:
        raise AssistantError("doctor_policy_source_conflict")
    if not args.policy and not args.policy_file:
        raise AssistantError("doctor_policy_required")
    # The raw argument is checked: an empty --repo must not become the current directory.
    if not args.repo or not args.base or not args.head:
        raise AssistantError("doctor_policy_range_required")
    report = policy_preflight(args.repo, args.base, args.head, args.policy or "", args.policy_sha256,
                              policy_file=args.policy_file or None)
    print(canonical(report).decode())
    return 0 if report["status"] == "ready" else 1
