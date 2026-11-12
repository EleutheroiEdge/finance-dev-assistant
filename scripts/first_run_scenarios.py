"""First-run scenarios on real repositories: does a detected setup review the changes that follow it?

For each repository, take the last N first-parent changes on a branch. Run `init --detect` at the
revision before the oldest of them, as someone setting up once would, then check each later change
with `doctor` on both routes: as drafted, with `private_paths: skip-and-report`, with
`unreviewable_paths: skip-and-report` as well, and with test files listed in
`placeholder_credential_paths` on top of both.

Nothing is sent anywhere and no key is read: `doctor` is offline and the key variable holds a
placeholder. Nothing is written inside a repository, Git's optional index lock is never taken
in one, and its objects are read as they are: replacement refs and the caller's own Git settings
are left out, and a repository with a grafts file is not measured. Only codes, counts and timings are printed,
under an anonymous number for each repository, and a content refusal is counted by its rule and
the file's suffix. Raw `doctor` output, which names files, and the
list of which number is which repository go to --output: a new folder, created here, that must
not exist yet and must be outside every repository. Keep it private.

    python scripts/first_run_scenarios.py --changes 25 --output /private/new-folder REPO [REPO ...]

The repositories keep moving, so the last N changes are different changes on a later day. Each
whole run writes the commit it read each history from to tips.txt in --output, and prints a
fingerprint of them. Give that file as --tips to read the same changes again. Two counts are
compared only when their runs print the same fingerprint.

Exit status: 0 when every repository was measured in full; 2 when a repository, a branch, a Git
read, `init --detect` or a `doctor` run failed, a repository holds a grafts file, or a history
holds fewer changes than asked for,
so the totals are not a whole measurement. A range `doctor` refuses is a measurement, not a failure.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import statistics
import subprocess
import sys
import time

PROVIDER = ["--provider", "google", "--model", "review-model", "--input-usd-per-million", "1",
            "--output-usd-per-million", "5"]
# Blockers that say the operator has not authorized a call yet. They are not setup failures.
AUTHORIZATION = frozenset({"network_not_approved", "provider_key_missing", "provider_prices_required"})
VARIANTS = ("config", "config+skip", "config+leave", "config+tests", "gate", "gate+skip", "gate+leave", "gate+tests")
SKIP = {"private_paths": "skip-and-report"}
LEAVE = {**SKIP, "unreviewable_paths": "skip-and-report"}
# What an operator who says "our test files hold only made-up logins" would list.
TESTS = {**LEAVE, "placeholder_credential_paths": [
    "tests/", "test/", "e2e/", "*/tests/*", "*/test/*", "*/__tests__/*", "*/fixtures/*", "*.test.*", "*.spec.*",
    "*_test.go", "*/test_*.py", "*/conftest.py"]}
_SUFFIX = re.compile(r"\.[a-z0-9]{1,8}")
_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
# A measurement only reads, and reads the objects as they are. Without the first setting,
# `git status` may rewrite a repository's index and hold its lock for a moment, which another Git
# command in that checkout would then trip over. Without the second, a replacement ref would put
# another commit in the place of a pinned one, and the same tips would name other changes.
READ_ONLY_GIT = {"GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1"}


def git_environment() -> dict:
    """The environment of every Git command of a measurement.

    None of the caller's own Git settings come along: one of them could point a command at
    another repository, another index or another object store than the one that was named.
    """
    return {**{name: value for name, value in os.environ.items() if not name.startswith("GIT_")}, **READ_ONLY_GIT}


class Incomplete(Exception):
    """A step failed, so this repository's counts are not a whole measurement."""


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False,
                          env=git_environment())
    if done.returncode:
        raise Incomplete("git " + args[0])
    return done.stdout.strip()


def ancestry_as_written(repo: Path) -> None:
    """Refuse a repository whose history is not the one its commits were written with.

    A legacy grafts file gives commits other parents, whatever the environment says, so the same
    tips would name other changes there. Such a repository is not measured.
    """
    listed = git(repo, "rev-parse", "--git-path", "info/grafts")
    path = Path(listed.decode().strip() if isinstance(listed, bytes) else listed)
    try:
        lines = (path if path.is_absolute() else repo / path).read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return
    except OSError:
        raise Incomplete("the grafts file cannot be read") from None
    if any(line.strip() and not line.lstrip().startswith("#") for line in lines):
        raise Incomplete("the repository holds a grafts file")


def read_tips(path: Path, count: int) -> list[str] | None:
    """The commits an earlier run wrote, one for each repository in order. None when the file is not that."""
    try:
        tips = path.read_text(encoding="utf-8").split()
    except (OSError, UnicodeError):
        return None
    return tips if len(tips) == count and all(_COMMIT.fullmatch(tip) for tip in tips) else None


def fingerprint(tips: list[str], changes: int) -> str:
    """Names a set of changes without naming a commit: the same tips, order and count give the same one."""
    return hashlib.sha256(("%d\n%s\n" % (changes, "\n".join(tips))).encode()).hexdigest()[:16]


def write_new(path: Path, text: str) -> None:
    """Create a file that must not exist, without following a link: nothing outside --output is written."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as handle:
        handle.write(text)


def finassist(command: list[str], arguments: list[str], cwd: Path, environment: dict) -> tuple[subprocess.CompletedProcess, float]:
    started = time.perf_counter()
    done = subprocess.run([*command, *arguments], cwd=cwd, env=environment, capture_output=True, text=True, check=False)
    return done, time.perf_counter() - started


def outcome(row: dict) -> str:
    """One path's outcome as a key: its status with the code or reason, and for a content refusal
    the rule and the file's suffix. Never the name."""
    key = "%s:%s" % (row.get("status"), row.get("code") or row.get("reason") or "")
    if isinstance(row.get("rule"), str):
        suffix = PurePosixPath(str(row.get("path"))).suffix.lower()
        key += ":%s:%s" % (row["rule"], suffix if _SUFFIX.fullmatch(suffix) else "")
    return key


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
    paths = collections.Counter(outcome(row) for row in report.get("paths", []))
    return {"status": report.get("status"), "blockers": sorted({item.get("code") for item in report.get("blockers", [])}),
            "paths": dict(paths), "seconds": seconds}


def scenario(command: list[str], label: str, repo: Path, revision: str, changes: int, output: Path,
             environment: dict) -> tuple[dict, str]:
    """One repository's counts, and the commit its history was read from."""
    before = git(repo, "status", "--porcelain")
    ancestry_as_written(repo)
    tip = git(repo, "rev-parse", "--verify", "--quiet", revision + "^{commit}")
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
    documents = {"config": config, "config+skip": {**config, **SKIP}, "config+leave": {**config, **LEAVE},
                 "config+tests": {**config, **TESTS},
                 "gate": gate, "gate+skip": {**gate, "model_review": {**gate["model_review"], **SKIP}},
                 "gate+leave": {**gate, "model_review": {**gate["model_review"], **LEAVE}},
                 "gate+tests": {**gate, "model_review": {**gate["model_review"], **TESTS}}}
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
    return result, tip


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("repositories", nargs="+", type=Path)
    parser.add_argument("--changes", type=int, default=25, help="First-parent changes to check in each repository")
    parser.add_argument("--branch", default="origin/main", help="Branch whose history is used (default: origin/main)")
    parser.add_argument("--output", type=Path, required=True,
                        help="New private folder for raw output; it must not exist and must be outside every repository")
    parser.add_argument("--tips", type=Path,
                        help="tips.txt from an earlier run's --output: read each history from the commit it names for "
                             "that repository, not from --branch, so that the same changes are measured again")
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
                               text=True, check=False, env=git_environment())
        if found.returncode == 0 and Path(found.stdout.strip()).resolve() != repo:
            parser.error("give each repository by its root folder")
    if any(output == repo or repo in output.parents for repo in repositories):
        parser.error("--output must be outside every repository")
    pinned = None
    if args.tips is not None:
        pinned = read_tips(args.tips, len(repositories))
        if pinned is None:
            parser.error("--tips must hold one full commit for each repository, in the order given")
    try:
        output.mkdir(mode=0o700)  # A new folder of our own: nothing already in it can redirect a write.
    except FileExistsError:
        parser.error("--output must not exist yet")
    labels = {f"repository-{number}": repo for number, repo in enumerate(repositories, 1)}
    write_new(output / "repositories.json", json.dumps({label: str(repo) for label, repo in labels.items()}, indent=1))
    summary, tips, incomplete = {}, [], 0
    for number, (label, repo) in enumerate(labels.items()):
        try:
            summary[label], tip = scenario([args.python, "-m", "finassist"], label, repo,
                                           pinned[number] if pinned else args.branch, args.changes, output,
                                           git_environment())
            tips.append(tip)
        except Incomplete as failure:
            incomplete += 1
            summary[label] = {"incomplete": str(failure)}
            print(f"== {label}: INCOMPLETE ({failure})", flush=True)
    write_new(output / "summary.json", json.dumps(summary, indent=1))
    if not incomplete:  # Of a whole run only: a shorter list would pin fewer repositories than it claims.
        write_new(output / "tips.txt", "".join(tip + "\n" for tip in tips))
    measured = [label for label, item in summary.items() if "variants" in item]
    total = sum(summary[label]["changes"] for label in measured)
    for variant in VARIANTS:
        ready = sum(summary[label]["variants"][variant]["ready"] for label in measured)
        set_up = sum(summary[label]["variants"][variant]["ready_but_for_authorization"] for label in measured)
        if total:
            print(f"ALL {variant:12} ready {ready}/{total} ({100 * ready / total:.0f}%) "
                  f"| set up {set_up}/{total} ({100 * set_up / total:.0f}%)")
    print(f"repositories measured: {len(measured)} | incomplete: {incomplete}")
    if not incomplete:
        print(f"reference set: {fingerprint(tips, args.changes)} ({len(tips)} repositories, {args.changes} changes each)")
    return 2 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
