"""Remedies on real repositories: does following what `doctor` proposes reach a reviewable setup?

Set up as first_run_scenarios.py does: for each repository, `init --detect` at the revision before
the oldest of its last N first-parent changes. Each later change is then checked on both routes
with the documents exactly as drafted. While a range is blocked and `doctor` lists a remedy, the
first option a program can apply is taken from every remedy, applied to a copy of the document
kept for that change alone, and `doctor` runs again. `doctor` lists an option that sends or spends
more only after one that does not, so this is the most careful path a script could take.

Each change, on each route, ends as one of:

    ready            as drafted, nothing stood in the way but authorization: network approval, a
                     key, prices
    remedied         the same, after following remedies; the runs it took are counted
    needs_decision   still blocked, no blocker left has an option a program can apply, and every
                     blocker left is one only a person can settle (DECISIONS below)
    unexplained      still blocked by a code that is not in DECISIONS, with no option to apply
    failed           a blocker an applied option targeted is still there on the next run
    looped           still blocked, with remedies still listed, after the limit of rounds

`unexplained`, `failed` and `looped` are defects to look at: a remedy is listed only when it is
known to clear its blocker, and a blocker with no remedy should be one a person must settle. A
code is a decision only by being listed below, so a new code is never counted as one unseen. A
`doctor` run that fails (`preflight_check_failed`, or no report at all) makes the repository's
measurement incomplete, as in first_run_scenarios.py. The other three outcomes measure the setup.

Nothing is sent anywhere: `doctor` is offline and the key variable holds a placeholder. Nothing
is written inside a repository, and its objects are read as first_run_scenarios.py reads them.
Only codes, setting names, counts and timings are printed, under an anonymous number for each
repository. Every document tried, which can name files, and the list of which number is which
repository go to --output: a new folder, created here, that must not exist yet and must be
outside every repository. Keep it private.

    python scripts/remedy_scenarios.py --changes 25 --output /private/new-folder REPO [REPO ...]

--tips, --branch and --python mean what they mean in first_run_scenarios.py, and a run prints
the same fingerprint for the same changes.

Exit status: 0 when every repository was measured in full; 2 when a repository could not be, as
in first_run_scenarios.py. A change that ends `failed` or `looped` is a measurement, not a failed
run: the totals report it.
"""

from __future__ import annotations

import collections
import copy
import importlib.util
import json
from pathlib import Path
import statistics

_SPEC = importlib.util.spec_from_file_location("first_run_scenarios", Path(__file__).with_name("first_run_scenarios.py"))
first_run = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(first_run)

Incomplete = first_run.Incomplete
# A route is named as a remedy names its document; the value is that document's field in the proposal.
ROUTES = {"configuration": "config", "gate policy": "gate_policy_draft"}
OUTCOMES = ("ready", "remedied", "needs_decision", "unexplained", "failed", "looped")
DEFECTS = ("unexplained", "failed", "looped")
MAX_ROUNDS = 6
# Blockers only a person can settle, as release gate B4 lists them: content that must not be sent (a credential,
# a hidden character, a listed figure), a change to the review's own rules, a private or binary file, a size or a
# cost over a stated limit, and a range left with nothing to review once the files a setting leaves out are out.
# A code that is not here, and has no remedy, is reported as unexplained.
DECISIONS = frozenset({
    "sensitive_content", "hidden_characters", "forbidden_token_present", "forbidden_publication_text",
    "gate_ignore_change_requires_review", "gate_policy_change_requires_review", "gate_profile_change_requires_review",
    "gate_fixture_marker_change_requires_review", "gate_ignored_path",
    "private_path", "private_or_binary_path", "private_profile_path", "gate_private_path",
    "unsupported_file_type", "file_limit_exceeded", "non_text_blob", "scope_incomplete", "gate_path_not_allowed",
    "packet_limit_exceeded", "gate_request_bytes_exceeded", "gate_file_count_exceeded", "packet_file_count_limit",
    "run_budget_exceeded", "daily_budget_exceeded", "monthly_budget_exceeded",
    "empty_review_scope", "empty_model_context", "review_scope_entirely_withheld",
})
# A doctor run that failed is not a measurement of the setup.
EXECUTION_FAILURES = frozenset({"preflight_check_failed"})


def apply(route: str, document: dict, option: dict) -> dict | None:
    """A copy of the document with one option's changes made, as a program reading the report would
    make them: each at the place its `pointer` names, with no knowledge of the document's layout.
    None when a program cannot: the option edits another document, or a change needs a value only
    the user knows."""
    if option.get("document") != route:
        return None
    changed = copy.deepcopy(document)
    for change in option["changes"]:
        try:
            *parents, name = [part.replace("~1", "/").replace("~0", "~") for part in change["pointer"].split("/")[1:]]
            settings = changed
            for part in parents:
                settings = settings[part]
        except (KeyError, TypeError, ValueError):
            raise Incomplete("a remedy's change does not say where its setting is") from None
        if "value" in change:
            settings[name] = change["value"]
        elif "at_least" in change:
            settings[name] = change["at_least"]
        elif "add" in change:
            settings[name] = [*settings.get(name, []), *change["add"]]
        else:
            return None
    return changed


def preflight(command: list[str], arguments: list[str], cwd: Path, environment: dict) -> dict:
    """One `doctor` run: status, blocker codes, remedies, files not included, seconds. Remedies can name files."""
    done, seconds = first_run.finassist(command, arguments, cwd, environment)
    report = first_run.report_or_refusal(done)
    if isinstance(report, str):
        return {"status": "refused", "blockers": [report], "remedies": [], "left_out": 0, "seconds": seconds}
    return {"status": report["status"], "blockers": sorted({item.get("code") for item in report.get("blockers", [])}),
            "remedies": report.get("remedies", []),
            "left_out": sum(row.get("status") != "included" for row in report.get("paths", [])), "seconds": seconds}


def _ended(outcome: str, rounds: int, applied: list[dict], codes: list[str], result: dict, seconds: list[float]) -> dict:
    return {"outcome": outcome, "rounds": rounds, "applied": applied, "codes": codes, "status": result["status"],
            "left_out": result["left_out"], "seconds": round(sum(seconds), 2)}


def follow(command: list[str], route: str, document: dict, repo: Path, base: str, head: str, folder: Path,
           environment: dict) -> dict:
    """One change on one route: `doctor`, then the first option of each remedy, until nothing but
    authorization is left or nothing more can be applied. Every document tried is kept in `folder`."""
    folder.mkdir(mode=0o700, parents=True)
    applied, last, seconds, open_codes, result = [], {}, [], [], {}
    for number in range(1, MAX_ROUNDS + 1):
        path = folder / f"{number}.json"
        first_run.write_new(path, json.dumps(document, indent=1))
        route_arguments = ["--config", str(path), "doctor"] if route == "configuration" else ["doctor", "--policy-file", str(path)]
        result = preflight(command, [*route_arguments, "--repo", str(repo), "--base", base, "--head", head],
                           folder, environment)
        seconds.append(result["seconds"])
        if EXECUTION_FAILURES & set(result["blockers"]):
            raise Incomplete("doctor failed on a range: " + ", ".join(sorted(EXECUTION_FAILURES & set(result["blockers"]))))
        open_codes = [code for code in result["blockers"] if code not in first_run.AUTHORIZATION]
        if not open_codes:
            return _ended("ready" if number == 1 else "remedied", number, applied, [], result, seconds)
        # An option is listed only when it is known to clear its blocker: one still there after it was applied is a
        # defect, whether doctor proposes the same option again, another option, or none.
        survived = sorted(set(last) & set(open_codes))
        if survived:
            return _ended("failed", number, applied, survived, result, seconds)
        steps = {}
        for remedy in result["remedies"]:
            for option in remedy["options"]:
                changed = apply(route, document, option)
                if changed is not None:
                    steps[remedy["code"]], document = option, changed
                    break
        if not steps:
            unexplained = sorted(set(open_codes) - DECISIONS)
            if unexplained:
                return _ended("unexplained", number, applied, unexplained, result, seconds)
            return _ended("needs_decision", number, applied, open_codes, result, seconds)
        applied.extend({"code": code, "effect": option.get("effect"),
                        "settings": sorted(change["setting"] for change in option["changes"])}
                       for code, option in steps.items())
        last = steps
    return _ended("looped", MAX_ROUNDS, applied, open_codes, result, seconds)


def summarize(rows: list[dict]) -> dict:
    """One route's counts over its changes. Codes and setting names only."""
    outcomes = collections.Counter(row["outcome"] for row in rows)
    runs = [row["rounds"] for row in rows if row["outcome"] == "remedied"]
    steps = [step for row in rows for step in row["applied"]]
    return {
        "outcomes": {name: outcomes.get(name, 0) for name in OUTCOMES},
        "set_up": outcomes["ready"] + outcomes["remedied"],
        "runs_to_set_up": sorted(runs),
        "effects": dict(collections.Counter(step["effect"] for step in steps)),
        "settings": dict(collections.Counter(name for step in steps for name in step["settings"])),
        "decisions": dict(collections.Counter(code for row in rows if row["outcome"] == "needs_decision"
                                              for code in row["codes"])),
        "defects": dict(collections.Counter(f"{row['outcome']}:{code}" for row in rows if row["outcome"] in DEFECTS
                                            for code in row["codes"])),
        "left_out_when_set_up": sum(row["left_out"] for row in rows if row["outcome"] in ("ready", "remedied")),
    }


def combine(parts: list[dict]) -> dict:
    """The sum of several repositories' counts for one route."""
    total = {"outcomes": collections.Counter(), "set_up": 0, "runs_to_set_up": [], "effects": collections.Counter(),
             "settings": collections.Counter(), "decisions": collections.Counter(), "defects": collections.Counter(),
             "left_out_when_set_up": 0}
    for part in parts:
        for name, value in part.items():
            if isinstance(value, dict):
                total[name].update(value)
            else:
                total[name] += value
    return {name: dict(value) if isinstance(value, collections.Counter) else value for name, value in total.items()}


def shown(route: str, counts: dict, changes: int, prefix: str = "  ") -> str:
    outcomes, runs = counts["outcomes"], counts["runs_to_set_up"]
    lines = [f"{prefix} {route:13} ready {outcomes.get('ready', 0)}/{changes} | remedied {outcomes.get('remedied', 0)} "
             f"| needs a decision {outcomes.get('needs_decision', 0)} | unexplained {outcomes.get('unexplained', 0)} "
             f"| failed {outcomes.get('failed', 0)} | looped {outcomes.get('looped', 0)} | set up {counts['set_up']}/{changes} "
             f"({100 * counts['set_up'] / changes:.0f}%)",
             f"{prefix} {'':13} applied {counts['effects']} | settings {counts['settings']}",
             f"{prefix} {'':13} decisions {counts['decisions']} | defects {counts['defects']} | runs to set up: "
             + (f"median {statistics.median(runs):g}, most {max(runs)}" if runs else "none needed")
             + f" | files left out where set up {counts['left_out_when_set_up']}"]
    return "\n".join(lines)


def scenario(command: list[str], label: str, repo: Path, revision: str, changes: int, output: Path,
             environment: dict) -> tuple[dict, str]:
    """One repository's counts on both routes, and the commit its history was read from."""
    before = first_run.git(repo, "status", "--porcelain")
    tip, ranges = first_run.changes_after_setup(repo, revision, changes)
    proposal, seconds = first_run.detect(command, repo, ranges[0][0], output, environment)
    key = proposal["gate_policy_draft"]["model_review"].get("api_key_env") or "GEMINI_API_KEY"
    environment = {**environment, key: "placeholder-not-a-key"}
    print(f"== {label}: {len(ranges)} changes after setup | detect {seconds:.1f}s", flush=True)
    rows = {route: [] for route in ROUTES}
    for number, (base, head) in enumerate(ranges, 1):
        for route, field in ROUTES.items():
            rows[route].append(follow(command, route, proposal[field], repo, base, head,
                                      output / label / field / str(number), environment))
    first_run.write_new(output / f"{label}-rows.json", json.dumps(rows))
    result = {"changes": len(ranges), "routes": {route: summarize(rows[route]) for route in ROUTES}}
    for route in ROUTES:
        print(shown(route, result["routes"][route], len(ranges)), flush=True)
    if first_run.git(repo, "status", "--porcelain") != before:
        raise Incomplete("working tree changed during the run")
    return result, tip


def main(argv: list[str] | None = None) -> int:
    args, output, labels, pinned = first_run.prepare(argv, __doc__.split("\n\n")[0])
    summary, tips, incomplete = {}, [], 0
    for number, (label, repo) in enumerate(labels.items()):
        try:
            summary[label], tip = scenario([args.python, "-m", "finassist"], label, repo,
                                           pinned[number] if pinned else args.branch, args.changes, output,
                                           first_run.git_environment())
            tips.append(tip)
        except Incomplete as failure:
            incomplete += 1
            summary[label] = {"incomplete": str(failure)}
            print(f"== {label}: INCOMPLETE ({failure})", flush=True)
    first_run.write_new(output / "summary.json", json.dumps(summary, indent=1))
    if not incomplete:  # Of a whole run only: a shorter list would pin fewer repositories than it claims.
        first_run.write_new(output / "tips.txt", "".join(tip + "\n" for tip in tips))
    measured = [label for label, item in summary.items() if "routes" in item]
    total = sum(summary[label]["changes"] for label in measured)
    if total:
        for route in ROUTES:
            print(shown(route, combine([summary[label]["routes"][route] for label in measured]), total, "ALL"))
    print(f"repositories measured: {len(measured)} | incomplete: {incomplete}")
    if not incomplete:
        print(f"reference set: {first_run.fingerprint(tips, args.changes)} ({len(tips)} repositories, "
              f"{args.changes} changes each)")
    return 2 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
