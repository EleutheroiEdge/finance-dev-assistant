"""First-run scenarios on real repositories: does a detected setup review the changes that follow it?

For each repository, take the last N first-parent changes on a branch. Run `init --detect` at the
revision before the oldest of them, as someone setting up once would, then check each later change
with `doctor` on both routes, as drafted and with `private_paths: skip-and-report`.

Nothing is sent anywhere and no key is read: `doctor` is offline and the key variable holds a
placeholder. Nothing is written inside a repository. Only codes, counts and timings are printed,
under an anonymous number for each repository. Raw `doctor` output, which names files, and the
list of which number is which repository go to --output: a new folder, created here, that must
not exist yet and must be outside every repository. Keep it private.

    python scripts/first_run_scenarios.py --changes 25 --output /private/new-folder REPO [REPO ...]

Exit status: 0 when every repository was measured in full; 2 when a repository, a branch, a Git
read, `init --detect` or a `doctor` run failed, or a history holds fewer changes than asked for,
so the totals are not a whole measurement. A range `doctor` refuses is a measurement, not a failure.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

PROVIDER = ["--provider", "google", "--model", "review-model", "--input-usd-per-million", "1",
            "--output-usd-per-million", "5"]
# Blockers that say the operator has not authorized a call yet. They are not setup failures.
AUTHORIZATION = frozenset({"network_not_approved", "provider_key_missing", "provider_prices_required"})
VARIANTS = ("config", "config+skip", "gate", "gate+skip")


class Incomplete(Exception):
    """A step failed, so this repository's counts are not a whole measurement."""


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False)
    if done.returncode:
        raise Incomplete("git " + args[0])
    return done.stdout.strip()


def write_new(path: Path, text: str) -> None:
    """Create a file that must not exist, without following a link: nothing outside --output is written."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as handle:
        handle.write(text)


def finassist(command: list[str], arguments: list[str], cwd: Path, environment: dict) -> tuple[subprocess.CompletedProcess, float]:
    started = time.perf_counter()
    done = subprocess.run([*command, *arguments], cwd=cwd, env=environment, capture_output=True, text=True, check=False)
    return done, time.perf_counter() - started


def doctor(command: list[str], arguments: list[str], cwd: Path, environment: dict) -> dict:
    """One range's status, blocker codes and per-path outcome counts. No path name is kept."""
    done, seconds = finassist(command, arguments, cwd, environment)
    try:
        report = json.loads(done.stdout.splitlines()[-1])
        if not isinstance(report, dict) or not isinstance(report.get("status"), str):
            raise ValueError
    except (ValueError, IndexError):
        # No report. A refusal the product states is still a measurement: exit status 2 with its
        # error document. Anything else is a failed run, and counting it would hide the failure.
        try:
            refusal = json.loads(done.stderr.splitlines()[-1])
            code = refusal["code"]
            if done.returncode != 2 or not isinstance(code, str):
                raise ValueError
        except (ValueError, IndexError, KeyError, TypeError):
            raise Incomplete("doctor gave no report") from None
        return {"status": "refused", "blockers": [code], "paths": {}, "seconds": seconds}
    paths = collections.Counter("%s:%s" % (row.get("status"), row.get("code") or row.get("reason") or "")
                                for row in report.get("paths", []))
    return {"status": report.get("status"), "blockers": sorted({item.get("code") for item in report.get("blockers", [])}),
            "paths": dict(paths), "seconds": seconds}


def scenario(command: list[str], label: str, repo: Path, branch: str, changes: int, output: Path, environment: dict) -> dict:
    before = git(repo, "status", "--porcelain")
    tip = git(repo, "rev-parse", "--verify", "--quiet", branch + "^{commit}")
    ranges = []
    for commit in reversed(git(repo, "rev-list", "--first-parent", "-n", str(changes), tip).split()):
        parents = git(repo, "rev-list", "--parents", "-n", "1", commit).split()[1:]
        if parents:
            ranges.append((parents[0], commit))
    if len(ranges) < changes:  # A short or shallow history: fewer ranges than the totals would claim.
        raise Incomplete(f"history holds {len(ranges)} of the {changes} changes asked for")
    done, seconds = finassist(command, ["init", "--detect", "--repo", str(repo), "--revision", ranges[0][0], *PROVIDER],
                              output, environment)
    try:
        proposal = json.loads(done.stdout)
        config, gate = proposal["config"], proposal["gate_policy_draft"]
    except (ValueError, KeyError, TypeError):
        raise Incomplete("init --detect") from None
    documents = {"config": config, "config+skip": {**config, "private_paths": "skip-and-report"}, "gate": gate,
                 "gate+skip": {**gate, "model_review": {**gate["model_review"], "private_paths": "skip-and-report"}}}
    files = {}
    for variant, document in documents.items():
        files[variant] = output / f"{label}-{variant}.json"
        write_new(files[variant], json.dumps(document, indent=1))
    key = gate["model_review"].get("api_key_env") or "GEMINI_API_KEY"
    environment = {**environment, key: "placeholder-not-a-key"}
    warnings = sorted(item.get("code") for item in proposal.get("warnings", []))
    print(f"== {label}: {len(ranges)} changes after setup | detect {seconds:.1f}s | profile {config.get('profile')} "
          f"| warnings {warnings}", flush=True)
    rows = {variant: [] for variant in VARIANTS}
    for base, head in ranges:
        for variant, path in files.items():
            route = ["--config", str(path), "doctor"] if variant.startswith("config") else ["doctor", "--policy-file", str(path)]
            rows[variant].append(doctor(command, [*route, "--repo", str(repo), "--base", base, "--head", head],
                                        output, environment))
    write_new(output / f"{label}-rows.json", json.dumps(rows))
    result = {"changes": len(ranges), "profile": config.get("profile"), "warnings": warnings, "variants": {}}
    for variant in VARIANTS:
        ready = sum(row["status"] == "ready" for row in rows[variant])
        set_up = sum(row["status"] != "error" and not set(row["blockers"]) - AUTHORIZATION for row in rows[variant])
        blockers = collections.Counter(code for row in rows[variant] for code in row["blockers"])
        paths = collections.Counter()
        for row in rows[variant]:
            paths.update(row["paths"])
        seconds = [row["seconds"] for row in rows[variant]]
        result["variants"][variant] = {
            "ready": ready, "ready_but_for_authorization": set_up, "blockers": dict(blockers), "paths": dict(paths),
            "median_seconds": round(statistics.median(seconds), 2), "max_seconds": round(max(seconds), 2)}
        refused = {key: count for key, count in paths.most_common() if not key.startswith("included")}
        print(f"   {variant:12} ready {ready:2}/{len(ranges)} | set up {set_up:2}/{len(ranges)} "
              f"| blockers {dict(blockers.most_common(8))}", flush=True)
        print(f"   {'':12} paths {dict(list(refused.items())[:8])} | median {statistics.median(seconds):.1f}s "
              f"max {max(seconds):.1f}s", flush=True)
    if git(repo, "status", "--porcelain") != before:
        raise Incomplete("working tree changed during the run")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("repositories", nargs="+", type=Path)
    parser.add_argument("--changes", type=int, default=25, help="First-parent changes to check in each repository")
    parser.add_argument("--branch", default="origin/main", help="Branch whose history is used (default: origin/main)")
    parser.add_argument("--output", type=Path, required=True,
                        help="New private folder for raw output; it must not exist and must be outside every repository")
    parser.add_argument("--python", default=sys.executable,
                        help="Interpreter that has the finassist under test installed (default: this one)")
    args = parser.parse_args(argv)
    if args.changes < 1:
        parser.error("--changes must be at least 1")
    output = args.output.resolve()
    repositories = [path.resolve() for path in args.repositories]
    if len(set(repositories)) != len(repositories):
        parser.error("a repository is listed twice")
    for repo in repositories:
        # Git reads a repository from any folder inside it, so the folder given must be its root:
        # otherwise --output could sit inside the repository and still pass the check below.
        found = subprocess.run(["git", "-C", str(repo), "rev-parse", "--show-toplevel"], capture_output=True,
                               text=True, check=False)
        if found.returncode == 0 and Path(found.stdout.strip()).resolve() != repo:
            parser.error("give each repository by its root folder")
    if any(output == repo or repo in output.parents for repo in repositories):
        parser.error("--output must be outside every repository")
    try:
        output.mkdir(mode=0o700)  # A new folder of our own: nothing already in it can redirect a write.
    except FileExistsError:
        parser.error("--output must not exist yet")
    labels = {f"repository-{number}": repo for number, repo in enumerate(repositories, 1)}
    write_new(output / "repositories.json", json.dumps({label: str(repo) for label, repo in labels.items()}, indent=1))
    summary, incomplete = {}, 0
    for label, repo in labels.items():
        try:
            summary[label] = scenario([args.python, "-m", "finassist"], label, repo, args.branch, args.changes, output,
                                      dict(os.environ))
        except Incomplete as failure:
            incomplete += 1
            summary[label] = {"incomplete": str(failure)}
            print(f"== {label}: INCOMPLETE ({failure})", flush=True)
    write_new(output / "summary.json", json.dumps(summary, indent=1))
    measured = [label for label, item in summary.items() if "variants" in item]
    total = sum(summary[label]["changes"] for label in measured)
    for variant in VARIANTS:
        ready = sum(summary[label]["variants"][variant]["ready"] for label in measured)
        set_up = sum(summary[label]["variants"][variant]["ready_but_for_authorization"] for label in measured)
        if total:
            print(f"ALL {variant:12} ready {ready}/{total} ({100 * ready / total:.0f}%) "
                  f"| set up {set_up}/{total} ({100 * set_up / total:.0f}%)")
    print(f"repositories measured: {len(measured)} | incomplete: {incomplete}")
    return 2 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
