"""One-run local preflight for the configuration route: plan, then review.

It lists every blocker plan and review would hit for one range, in one run: refused,
withheld and omitted paths, file and packet limits, settings with no effect, the network
setting, the key variable, prices and the reserved spend. It reads Git objects and the
configuration. It never reads a key value, uses the network, opens the ledger or writes
a packet. Path names appear only in this local report, as "[redacted]" when a name fails
screening. Once its own checks pass it runs the real packet builder, so "ready" means
plan builds this range's packet and review accepts it up to the provider call.
"""

from decimal import ROUND_CEILING, Decimal
import os
from pathlib import Path

from .config import Config, config_hash
from .error_hints import error_fields
from .errors import AssistantError
from .health import config_warnings
from .onboarding import _shown_argument
from .providers import request_payload
from .review import ENVELOPE_ALLOWANCE, reserved_usd, review_schema, spend_estimate
from .forbidden_tokens import screen_source
from .scope import (_private_name, build_packet, config_token_guard, git, omission_for, omission_reason, read_sides,
                    resolve)
from .security import canonical, check_text, local_name, refusal_location, regular_path

_EXAMPLES = 20  # Example names kept per grouped blocker.
_LEFT_OUT = frozenset({"unsupported_file_type", "file_limit_exceeded", "non_text_blob"})  # Reasons the setting adds.
_DEFAULT_HINT = "See the configuration guide for this code."


def _hint(code: str) -> str:
    return error_fields(code).get("hint", _DEFAULT_HINT)


class _ConfigPreflight:
    def __init__(self, repo: Path, base: str, head: str, config: Config, config_path: Path | None, environment):
        self.repo, self.base_ref, self.head_ref = repo, base, head
        self.config, self.config_path = config, config_path
        # Names only: iterating an environment mapping never reads a value.
        self.environment_names = frozenset(iter(environment))
        self.report = {
            "schema_version": 1, "mode": "config-preflight", "status": "blocked", "base": None, "head": None,
            "config": {"source": "defaults" if config_path is None else "file",
                       "config_hash": config_hash(config)},
            "blockers": [], "warnings": [], "paths": [], "coverage_complete": None, "packet": None,
            # Whether a list of confidential figures is configured, and how many entries it holds.
            "figure_screen": {"configured": False, "listed": 0, "match": config.forbidden_token_match,
                              "digit_forms": 0},
            "request": None, "provider": None, "network_used": False, "key_value_read": False,
            "ledger_opened": False, "next_step": None,
        }
        # Path blockers are grouped by code: a count plus a few example names.
        self._grouped: dict[str, dict] = {}
        self.guard = None

    def block(self, code: str, **details) -> None:
        self.report["blockers"].append({"code": code, **details, "hint": _hint(code)})

    def block_path(self, code: str, path: str) -> None:
        group = self._grouped.setdefault(code, {"code": code, "count": 0, "paths": [], "hint": _hint(code)})
        group["count"] += 1
        if len(group["paths"]) < _EXAMPLES:
            group["paths"].append(path)

    def run(self) -> dict:
        try:
            self._run()
        except AssistantError as exc:
            self.block(exc.code, **exc.public_details)
        except (OSError, ValueError, LookupError) as exc:
            # Keep the report: name the failing step's class, never its message.
            self.block("preflight_check_failed", kind=type(exc).__name__)
        self.report["blockers"].extend(self._grouped.values())
        ready = not self.report["blockers"]
        self.report["status"] = "ready" if ready else "blocked"
        self.report["next_step"] = (self._commands() if ready
                                    else "Fix every blocker listed, then run this preflight again.")
        return self.report

    def _run(self) -> None:
        config = self.config
        self.report["warnings"].extend(config_warnings(config, self.config_path,
                                                       file_selected=self.config_path is not None))
        repo = regular_path(self.repo)
        try:
            base, head = resolve(repo, self.base_ref), resolve(repo, self.head_ref)
        except AssistantError as exc:
            return self.block(exc.code)
        self.report.update(base=base, head=head)
        self.report["figure_screen"]["configured"] = bool(config.forbidden_token_rules)
        try:
            self.guard = config_token_guard(config, repo)
        except AssistantError as exc:  # The list can't be read; the other blockers are still listed.
            self.block(exc.code)
        if self.guard is not None:
            snapshot = self.guard.snapshot
            self.report["figure_screen"].update(listed=snapshot.listed, match=config.forbidden_token_match,
                                                digit_forms=len(snapshot.digit_hashes))
        rows = self._paths(repo, base, head)
        packet = None
        if rows and not self._grouped and not self.report["blockers"]:
            try:  # The real builder, so "ready" means plan builds this packet.
                packet = build_packet(repo, base, head, config, token_guard=self.guard)
            except AssistantError as exc:
                self.block(exc.code, **exc.public_details)
            else:
                body = {key: value for key, value in packet.items() if key != "packet_hash"}
                self.report["packet"] = {"bytes": len(canonical(body)), "limit": config.max_packet_bytes,
                                         "packet_hash": packet["packet_hash"]}
        if config.provider != "offline":
            self._provider(packet)
        return None

    def _paths(self, repo: Path, base: str, head: str) -> list[dict]:
        config = self.config
        ancestor = git(repo, "merge-base", base, head)
        raw = git(repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-status", "-z",
                  ancestor, head, binary=True)
        try:
            tokens = raw.decode("utf-8").split("\0")
        except UnicodeDecodeError:
            self.block("path_name_not_utf8")
            return []
        names = [tokens[pos + 1] for pos in range(0, len(tokens) - 1, 2)]
        if len(names) > 2000:
            self.block("packet_file_count_limit", files=len(names), limit=2000)
            return []
        if not names:
            self.block("empty_review_scope")
            return []
        rows = [self._classify(repo, (ancestor, head), name) for name in names]
        self.report["paths"] = rows
        self.report["coverage_complete"] = all(row["status"] == "included" for row in rows)
        # Only a model call refuses omissions or an empty context: offline review answers before those checks.
        # unreviewable_paths: skip-and-report is the choice to review without the files it names.
        model = config.provider != "offline"
        partial = config.allow_partial_review or config.unreviewable_paths == "skip-and-report"
        for row in rows:
            if row["status"] == "refused":
                self.block_path(row["code"], row["path"])
            elif row["status"] == "omitted" and model and not partial:
                self.block_path("scope_incomplete", row["path"])
        withheld = sum(row["status"] == "withheld" for row in rows)
        if withheld:
            self.report["warnings"].append({"code": "private_paths_withheld", "count": withheld,
                                            "hint": _hint("private_paths_withheld")})
        left = sum(row["status"] == "omitted" and row["reason"] in _LEFT_OUT for row in rows)
        if left:
            self.report["warnings"].append({"code": "unreviewable_paths_left_out", "count": left,
                                            "hint": _hint("unreviewable_paths_left_out")})
        if withheld == len(rows):
            self.block("review_scope_entirely_withheld")
        elif model and not any(row["status"] == "included" for row in rows) and not self._grouped:
            self.block("empty_model_context")
        return rows

    def _classify(self, repo: Path, revisions: tuple[str, str], path: str) -> dict:
        """The same rules plan applies, in the same order, for one changed path."""
        config = self.config
        row = {"path": local_name(path, config.extra_sensitive_patterns)}
        try:
            if config.private_paths == "skip-and-report" and _private_name(config, path):
                # A name matching a configured sensitive pattern still refuses, as in plan.
                check_text(path, extra_patterns=config.extra_sensitive_patterns)
                return {**row, "status": "withheld"}
            config.check_path(path, source_only=False, metadata_only=True)
            check_text(path, extra_patterns=config.extra_sensitive_patterns)
            reason = omission_reason(config, path)
            if reason is not None:
                return {**row, "status": "omitted", "reason": reason}
            guard = self.guard
            screen = None if guard is None else (lambda text, name: screen_source(text, name, guard.snapshot))
            read_sides(repo, revisions, path, config, screen)
        except AssistantError as exc:
            try:
                reason = omission_for(repo, revisions, path, config, exc.code)
            except AssistantError as special:  # A link or submodule: never left out.
                exc, reason = special, None
            if reason is not None:
                return {**row, "status": "omitted", "reason": reason}
            return {**row, "status": "refused", "code": exc.code, **exc.public_details, **refusal_location(exc)}
        return {**row, "status": "included"}

    def _provider(self, packet: dict | None) -> None:
        config = self.config
        key = config.key_name
        prices = {"input_usd_per_million": config.input_usd_per_million,
                  "output_usd_per_million": config.output_usd_per_million}
        priced = config.provider == "ollama" or all(value > 0 for value in prices.values())
        self.report["provider"] = {
            "provider": config.provider, "model_configured": bool(config.model),
            "network_enabled": config.allow_network, "key_variable": key or None,
            "key_variable_set": bool(key) and key in self.environment_names, "prices_configured": priced,
        }
        if not config.allow_network:
            self.block("network_not_approved", allow_network=False)
        if not priced:
            self.block("provider_prices_required", missing=sorted(name for name, value in prices.items() if value <= 0))
        if key and key not in self.environment_names:
            self.block("provider_key_missing", variable=key)
        if packet is None or not priced:
            return
        system = config.instructions()
        body = canonical(request_payload(config, system, packet, review_schema()))
        _bound, estimate = spend_estimate(packet, system, body, config, policy_bound=False)
        self.report["request"] = {"bytes": len(body), "reserved_usd": str(estimate), "prior_spend_checked": False}
        if estimate > Decimal(str(config.max_run_usd)):
            self.block("run_budget_exceeded", reserved_usd=str(estimate), limit_usd=str(config.max_run_usd))
        if estimate > Decimal(str(config.daily_budget_usd)):
            self.block("daily_budget_exceeded", reserved_usd=str(estimate), limit_usd=str(config.daily_budget_usd))
        if estimate > Decimal(str(config.monthly_budget_usd)):
            self.block("monthly_budget_exceeded", reserved_usd=str(estimate), limit_usd=str(config.monthly_budget_usd))

    def _commands(self) -> dict:
        """The next commands, with placeholders where the person chooses or inspects something."""
        chosen = [] if self.config_path is None else ["--config", _shown_argument(str(self.config_path), "<configuration>")]
        plan = ["finassist", *chosen, "plan", "--repo", _shown_argument(str(self.repo)), "--base", self.report["base"],
                "--head", self.report["head"], "--output", "<new packet file>"]
        review = ["finassist", *chosen, "review", "--packet", "<packet file>", "--approve-packet",
                  "<packet_hash shown by plan, after you inspect the packet>",
                  *(["--allow-network"] if self.config.provider != "offline" else []), "--output", "<new review file>"]
        return {"commands": [plan, review]}


def config_preflight(repo: Path, base: str, head: str, config: Config, config_path: Path | None = None,
                     *, environment=None) -> dict:
    """Every plan and review blocker for one range, in one local run."""
    return _ConfigPreflight(Path(repo), base, head, config, config_path,
                            os.environ if environment is None else environment).run()


def run_config_doctor(args, config: Config) -> int:
    """Validate the preflight options first; empty values count as missing."""
    if args.fix or args.check_updates or args.state_dir is not None:
        raise AssistantError("doctor_config_preflight_conflict")
    if not args.repo or not args.base or not args.head:
        raise AssistantError("doctor_policy_range_required")
    report = config_preflight(args.repo, args.base, args.head, config, args.config)
    print(canonical(report).decode())
    return 0 if report["status"] == "ready" else 1


# What the hash of a packet adds to it. The packet limit is checked before the hash is added, and the
# reserve is worked out after.
_PACKET_HASH_BYTES = len(canonical({"packet_hash": "0" * 64}))


def budgets_for_the_packet_limit(proposed: Config) -> dict:
    """The budgets a drafted configuration needs for one request at its own packet limit.

    By this route's own arithmetic: it reserves the packet, the instructions and a fixed allowance
    as input units, and every permitted output token. A draft that raises `max_packet_bytes` to
    fit the largest recent change and keeps a smaller budget would refuse that change for its
    cost. Each of the three budgets is asked on its own whether that request fits it: a run
    budget that is enough does not excuse a day or a month that is not. Only a budget that is
    too small is named, and none is lowered. With no provider, model or prices there is nothing
    to work out, and nothing is invented.
    """
    prices = (proposed.input_usd_per_million, proposed.output_usd_per_million)
    if (proposed.provider == "offline" or not proposed.model
            or not (proposed.provider == "ollama" or all(value > 0 for value in prices))):
        return {}
    units = proposed.max_packet_bytes + _PACKET_HASH_BYTES + len(proposed.instructions().encode()) + ENVELOPE_ALLOWANCE
    run = reserved_usd(units, proposed.max_output_tokens, *prices).quantize(Decimal("0.01"), rounding=ROUND_CEILING)
    stated_run, stated_day, stated_month = (Decimal(str(value)) for value in (
        proposed.max_run_usd, proposed.daily_budget_usd, proposed.monthly_budget_usd))
    budgets = {}
    if run > stated_run:
        budgets["max_run_usd"] = float(run)
    # A day that has to change is given three requests, as the gate policy draft gives it.
    changed = run > stated_run or run > stated_day
    daily = max(stated_day, 3 * run) if changed else stated_day
    if daily > stated_day:
        budgets["daily_budget_usd"] = float(daily)
    # A month holds the day that is proposed beside it. Beside a day that stays, it holds one request.
    if (daily if changed else run) > stated_month:
        budgets["monthly_budget_usd"] = float(daily)
    return budgets
