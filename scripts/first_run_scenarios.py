"""First-run scenarios on real repositories: does a detected setup review the changes that follow it?

For each repository, take the last N first-parent changes on a branch. Run `init --detect` at the
revision before the oldest of them, as someone setting up once would, then check each later change
with `doctor` on both routes, as drafted and with `private_paths: skip-and-report`.

Nothing is sent anywhere and no key is read: `doctor` is offline and the key variable holds a
placeholder. Nothing is written inside a repository. Only codes, counts and timings are printed;
raw `doctor` output, which names files, goes to --output. Keep that folder private and outside
every repository.

    python scripts/first_run_scenarios.py --changes 25 --output /private/folder REPO [REPO ...]
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


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


def finassist(command: list[str], arguments: list[str], cwd: Path, environment: dict) -> tuple[subprocess.CompletedProcess, float]:
    started = time.perf_counter()
    done = subprocess.run([*command, *arguments], cwd=cwd, env=environment, capture_output=True, text=True, check=False)
    return done, time.perf_counter() - started


def doctor(command: list[str], arguments: list[str], cwd: Path, environment: dict) -> dict:
    """One range's status, blocker codes and per-path outcome counts. No path name is kept."""
    done, seconds = finassist(command, arguments, cwd, environment)
    try:
        report = json.loads(done.stdout.splitlines()[-1])
    except (ValueError, IndexError):
        return {"status": "error", "blockers": ["no_report_exit_%d" % done.returncode], "paths": {}, "seconds": seconds}
    paths = collections.Counter("%s:%s" % (row.get("status"), row.get("code") or row.get("reason") or "")
                                for row in report.get("paths", []))
    return {"status": report.get("status"), "blockers": sorted({item.get("code") for item in report.get("blockers", [])}),
            "paths": dict(paths), "seconds": seconds}


def scenario(command: list[str], repo: Path, branch: str, changes: int, output: Path, environment: dict) -> dict | None:
    name = repo.name
    before = git(repo, "status", "--porcelain")
    commits = git(repo, "rev-list", "--first-parent", "-n", str(changes), branch).split()
    ranges = []
    for commit in reversed(commits):
        parents = git(repo, "rev-list", "--parents", "-n", "1", commit).split()[1:]
        if parents:
            ranges.append((parents[0], commit))
    if not ranges:
        print(f"== {name}: no changes on {branch}")
        return None
    setup = ranges[0][0]
    done, seconds = finassist(command, ["init", "--detect", "--repo", str(repo), "--revision", setup, *PROVIDER],
                              output, environment)
    try:
        proposal = json.loads(done.stdout)
    except ValueError:
        print(f"== {name}: init --detect failed at the setup revision (exit {done.returncode})")
        return {"detect": "failed"}
    config, gate = proposal["config"], proposal["gate_policy_draft"]
    documents = {"config": config, "config+skip": {**config, "private_paths": "skip-and-report"}, "gate": gate,
                 "gate+skip": {**gate, "model_review": {**gate["model_review"], "private_paths": "skip-and-report"}}}
    files = {}
    for variant, document in documents.items():
        files[variant] = output / f"{name}-{variant}.json"
        files[variant].write_text(json.dumps(document, indent=1), encoding="utf-8")
    key = gate["model_review"].get("api_key_env") or "GEMINI_API_KEY"
    environment = {**environment, key: "placeholder-not-a-key"}
    warnings = sorted(item.get("code") for item in proposal.get("warnings", []))
    print(f"== {name}: {len(ranges)} changes after setup | detect {seconds:.1f}s | profile {config.get('profile')} "
          f"| warnings {warnings}", flush=True)
    rows = {variant: [] for variant in VARIANTS}
    for base, head in ranges:
        for variant, path in files.items():
            route = ["--config", str(path), "doctor"] if variant.startswith("config") else ["doctor", "--policy-file", str(path)]
            rows[variant].append(doctor(command, [*route, "--repo", str(repo), "--base", base, "--head", head],
                                        output, environment))
    (output / f"{name}-rows.json").write_text(json.dumps(rows), encoding="utf-8")
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
        print(f"   WARNING: the working tree of {name} changed during the run")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("repositories", nargs="+", type=Path)
    parser.add_argument("--changes", type=int, default=25, help="First-parent changes to check in each repository")
    parser.add_argument("--branch", default="origin/main", help="Branch whose history is used (default: origin/main)")
    parser.add_argument("--output", type=Path, required=True, help="Private folder outside every repository")
    parser.add_argument("--python", default=sys.executable,
                        help="Interpreter that has the finassist under test installed (default: this one)")
    args = parser.parse_args(argv)
    output = args.output.resolve()
    repositories = [path.resolve() for path in args.repositories]
    if any(output == repo or repo in output.parents for repo in repositories):
        parser.error("--output must be outside every repository")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    summary = {}
    for repo in repositories:
        result = scenario([args.python, "-m", "finassist"], repo, args.branch, args.changes, output, dict(os.environ))
        if result is not None:
            summary[repo.name] = result
    (output / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    drafted = [name for name, item in summary.items() if "variants" in item]
    total = sum(summary[name]["changes"] for name in drafted)
    for variant in VARIANTS:
        ready = sum(summary[name]["variants"][variant]["ready"] for name in drafted)
        set_up = sum(summary[name]["variants"][variant]["ready_but_for_authorization"] for name in drafted)
        if total:
            print(f"ALL {variant:12} ready {ready}/{total} ({100 * ready / total:.0f}%) "
                  f"| set up {set_up}/{total} ({100 * set_up / total:.0f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
