"""Gate A11, stability: does `doctor` print the same bytes when it checks the same change again?

Set up as first_run_scenarios.py does: for each repository, `init --detect` at the revision before the
oldest of its last N first-parent changes, or of the changes a --tips file pins. Then run `doctor`
--runs times on every change under the two documented setups: the configuration and the gate policy,
each with test files listed in `placeholder_credential_paths`. Each run's exit status, and the raw
bytes of its output and error output, must equal the first run's.

`doctor` is offline: nothing is sent, and the key variable holds a synthetic placeholder. Nothing is
written in a repository. Only counts, and which of the three (exit status, output, error output)
differed, are printed, under an anonymous number for each repository: never a field, a path, a line
or a value. The drafted setups, and the raw bytes of every run of a change that differed, go to
--output, a new private folder outside every repository. --changes, --tips, --branch and --python
mean what they mean in first_run_scenarios.py.

    python scripts/doctor_stability.py --runs 5 --changes 25 --tips TIPS --output /private/new-folder REPO [REPO ...]

Exit status: 0 when every change gave identical output in every run; 1 when one did not; 2 when a
repository was not measured in full, so the totals are not a whole measurement.
"""

from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import os
from pathlib import Path
import subprocess

_SPEC = importlib.util.spec_from_file_location("first_run_scenarios", Path(__file__).with_name("first_run_scenarios.py"))
first_run = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(first_run)

SETUPS = ("config+tests", "gate+tests")
STREAMS = ("exit status", "output", "error output")


def run_raw(command: list[str], arguments: list[str], cwd: Path, environment: dict) -> subprocess.CompletedProcess:
    """One run with its output kept as bytes: decoding text would make `\\r\\n` and `\\n` the same."""
    return subprocess.run([*command, *arguments], cwd=cwd, env=environment, capture_output=True, check=False)


def _decoded(done: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    """A text copy of a run, only to check that it gave a report or a refusal the product states."""
    return subprocess.CompletedProcess(done.args, done.returncode, done.stdout.decode("utf-8", "replace"),
                                       done.stderr.decode("utf-8", "replace"))


def _write_new_bytes(path: Path, data: bytes) -> None:
    """Create a file that must not exist, without following a link: nothing outside --output is written."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as handle:
        handle.write(data)


def stability(command: list[str], label: str, repo: Path, revision: str, changes: int, runs: int, output: Path,
              environment: dict) -> tuple[dict, str]:
    """One repository's counts, and the commit its history was read from."""
    before = first_run.git(repo, "status", "--porcelain")
    tip, ranges = first_run.changes_after_setup(repo, revision, changes)
    proposal, _seconds = first_run.detect(command, repo, ranges[0][0], output, environment)
    config, gate = proposal["config"], proposal["gate_policy_draft"]
    documents = {"config+tests": {**config, **first_run.TESTS},
                 "gate+tests": {**gate, "model_review": {**gate["model_review"], **first_run.TESTS}}}
    key = gate["model_review"].get("api_key_env") or "GEMINI_API_KEY"
    environment = {**environment, key: "placeholder-not-a-key"}
    counts, streams = collections.Counter(), collections.Counter()
    for setup in SETUPS:
        path = output / f"{label}-{setup}.json"
        first_run.write_new(path, json.dumps(documents[setup], indent=1))
        route = ["--config", str(path), "doctor"] if setup.startswith("config") else ["doctor", "--policy-file", str(path)]
        for number, (base, head) in enumerate(ranges, 1):
            done = [run_raw(command, [*route, "--repo", str(repo), "--base", base, "--head", head], output, environment)
                    for _ in range(runs)]
            first_run.report_or_refusal(_decoded(done[0]))  # no report and no stated refusal: a failed run
            counts["checked"] += 1
            differed = set()
            for item in done[1:]:
                if item.returncode != done[0].returncode:
                    differed.add("exit status")
                if item.stdout != done[0].stdout:
                    differed.add("output")
                if item.stderr != done[0].stderr:
                    differed.add("error output")
            if not differed:
                counts["identical"] += 1
                continue
            counts["different"] += 1
            streams.update(differed)
            for run, item in enumerate(done, 1):  # kept privately, for a person to compare
                stem = output / f"{label}-{setup}-change{number}-run{run}-exit{item.returncode}"
                _write_new_bytes(stem.with_name(stem.name + ".out"), item.stdout)
                _write_new_bytes(stem.with_name(stem.name + ".err"), item.stderr)
    if first_run.git(repo, "status", "--porcelain") != before:
        raise first_run.Incomplete("working tree changed during the run")
    print(f"== {label}: {len(ranges)} changes, {counts['checked']} checks of {runs} runs, "
          f"{counts['different']} differing", flush=True)
    return {"changes": len(ranges), "checked": counts["checked"], "identical": counts["identical"],
            "different": counts["different"], "streams": dict(streams)}, tip


def _at_least_two(text: str) -> int:
    value = int(text)
    if value < 2:
        raise argparse.ArgumentTypeError("must be at least 2")
    return value


def _runs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runs", type=_at_least_two, default=5, help="Runs of doctor on each change (default: 5)")


def main(argv: list[str] | None = None) -> int:
    args, output, labels, pinned = first_run.prepare(argv, __doc__.split("\n\n")[0], _runs)
    summary, tips, incomplete = {}, [], 0
    for number, (label, repo) in enumerate(labels.items()):
        try:
            summary[label], tip = stability([args.python, "-m", "finassist"], label, repo,
                                            pinned[number] if pinned else args.branch, args.changes, args.runs, output,
                                            first_run.git_environment())
            tips.append(tip)
        except first_run.Incomplete as failure:
            incomplete += 1
            summary[label] = {"incomplete": str(failure)}
            print(f"== {label}: INCOMPLETE ({failure})", flush=True)
    first_run.write_new(output / "summary.json", json.dumps(summary, indent=1))
    if not incomplete:
        first_run.write_new(output / "tips.txt", "".join(tip + "\n" for tip in tips))
    measured = [item for item in summary.values() if "checked" in item]
    checked = sum(item["checked"] for item in measured)
    identical = sum(item["identical"] for item in measured)
    streams = collections.Counter()
    for item in measured:
        streams.update(item["streams"])
    print(f"A11: {identical} of {checked} checks gave byte-identical doctor output over {args.runs} runs "
          f"({len(SETUPS)} setups per change)")
    for stream in STREAMS:
        if streams[stream]:
            print(f"   checks whose {stream} differed: {streams[stream]}")
    print(f"repositories measured: {len(measured)} | incomplete: {incomplete}")
    if not incomplete:
        print(f"reference set: {first_run.fingerprint(tips, args.changes)} ({len(tips)} repositories, "
              f"{args.changes} changes each)")
    return 2 if incomplete else 0 if identical == checked else 1


if __name__ == "__main__":
    raise SystemExit(main())
