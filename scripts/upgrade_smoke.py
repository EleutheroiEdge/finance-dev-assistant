"""Exercise pinned public historical wheels against a local candidate, using synthetic data."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import venv

from packaging.version import InvalidVersion, Version

from ci_install import ROOT

FIXTURES = ROOT / "examples/upgrade-fixtures"
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_FLOOR_CODES = ("unknown_config_option", "minimum_version_required")
# A synthetic confidential figure for the gate check, and a placeholder for the key variable the example policy
# names: doctor checks that the variable is set, never its value, and calls no provider.
FIGURE, PLACEHOLDER = "7341906", "placeholder-not-a-key"


def environment(home):
    # No provider keys, user Python paths, pip configuration, system Git configuration or real home settings.
    names = ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP")
    result = {key: os.environ[key] for key in names if key in os.environ}
    result.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / "config"),
                  XDG_CACHE_HOME=str(home / "cache"), APPDATA=str(home / "appdata"),
                  LOCALAPPDATA=str(home / "localappdata"), PYTHONIOENCODING="utf-8",
                  PYTHONDONTWRITEBYTECODE="1", PIP_CONFIG_FILE=os.devnull,
                  PIP_DISABLE_PIP_VERSION_CHECK="1", FINASSIST_NO_UPDATE_CHECK="1", GIT_CONFIG_NOSYSTEM="1")
    return result


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version_key(version):
    match = _VERSION.fullmatch(version) if isinstance(version, str) else None
    if match is None:
        raise RuntimeError("Invalid pinned historical wheel manifest")
    return tuple(int(part) for part in match.groups())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("Historical wheel redirects are not allowed")


def historical_wheel(record, directory):
    """The pinned wheel's file in the cache, downloaded once and written whole, never through a link."""
    version_key(record["version"])
    url = urllib.parse.urlsplit(record["url"])
    expected = f"finledgerpoli-{record['version']}-py3-none-any.whl"
    if (record["filename"] != expected
            or url.scheme != "https" or url.netloc != "files.pythonhosted.org"
            or url.query or url.fragment or not url.path.endswith("/" + expected)
            or not isinstance(record["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
            or type(record["size"]) is not int or not 0 < record["size"] <= 2_000_000
            or type(record.get("store_schema")) is not int or record["store_schema"] < 0
            or type(record.get("schema_guard")) is not bool or record.get("floor_code") not in _FLOOR_CODES):
        raise RuntimeError("Invalid pinned historical wheel manifest")
    if directory.is_symlink():
        raise RuntimeError("The historical wheel cache is a link")
    target = directory / expected
    if target.is_symlink():
        raise RuntimeError("Cached historical wheel is a link")
    if not target.exists():
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(record["url"], timeout=30) as response:
            data = response.read(record["size"] + 1)
        if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise RuntimeError("Historical wheel bytes do not match the reviewed PyPI hash")
        # Whole or not at all: a reader sharing the cache never sees a partial file, and none is left behind.
        handle = tempfile.NamedTemporaryFile(dir=directory, prefix=".download-", delete=False)
        try:
            with handle:
                handle.write(data)
            os.replace(handle.name, target)
        finally:
            Path(handle.name).unlink(missing_ok=True)
    if (target.is_symlink() or not target.is_file() or target.stat().st_size != record["size"]
            or file_hash(target) != record["sha256"]):
        raise RuntimeError("Cached historical wheel hash mismatch")
    return target


def run(python, *args, cwd, env, expected_exit=0):
    result = subprocess.run([str(python), "-I", *map(str, args)], cwd=cwd, env=env,
                            capture_output=True, text=True, encoding="utf-8", shell=False,
                            timeout=90, check=False)
    if result.returncode != expected_exit:
        raise RuntimeError(f"Upgrade check failed ({result.returncode}): {result.stderr}")
    return result


def cli(python, *args, cwd, env, expected_exit=0):
    result = run(python, "-m", "finassist", *args, cwd=cwd, env=env, expected_exit=expected_exit)
    return json.loads(result.stderr if expected_exit == 2 else result.stdout)


def install(python, wheel, sha256, *, cwd, env):
    """Install a wheel as the `finledgerpoli` distribution, by the hash it was pinned or verified to, never one read
    again from disk: pip refuses a file that changed since, or one whose metadata names another distribution, which
    would install beside the old version instead of upgrading it."""
    wheel = wheel.resolve()
    with tempfile.TemporaryDirectory(prefix="install-", dir=cwd) as directory:
        requirement = Path(directory) / "wheel.txt"
        requirement.write_text(f"finledgerpoli @ {wheel.as_uri()} --hash=sha256:{sha256}\n", encoding="utf-8",
                               newline="\n")
        run(python, "-m", "pip", "install", "--require-hashes", "--no-deps", "--force-reinstall",
            "-r", requirement, cwd=cwd, env=env)


def git(repo, *args, env):
    return subprocess.run(["git", "-c", "user.name=Synthetic Tester", "-c", "user.email=tester@example.invalid",
                           "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", "-C", str(repo), *args],
                          env=env, capture_output=True, text=True, check=True, timeout=60, shell=False).stdout.strip()


def commit(repo, message, *, env):
    """Commit every change in the repository and return the new commit."""
    git(repo, "add", "-A", env=env)
    git(repo, "commit", "-q", "-m", message, env=env)
    return git(repo, "rev-parse", "HEAD", env=env)


def gate_verdicts(python, root, policies, pins, changes, *, env):
    """Each policy's doctor verdict on each change, pinned by its recorded bytes: status, blocker codes, policy
    SHA-256 and exit status."""
    verdicts = {}
    for name, policy in policies.items():
        for change, (base, head) in changes.items():
            done = subprocess.run([str(python), "-I", "-m", "finassist", "doctor", "--policy-file", str(policy),
                                   "--policy-sha256", pins[policy], "--repo", str(root / "gate-repo"),
                                   "--base", base, "--head", head], cwd=root, env=env, capture_output=True,
                                  text=True, encoding="utf-8", shell=False, timeout=90, check=False)
            if done.returncode not in (0, 1):  # ready, or blocked with a report
                raise RuntimeError(f"Upgrade gate check failed ({done.returncode}): {done.stderr}")
            report = json.loads(done.stdout)
            verdicts[(name, change)] = (report["status"], sorted(item["code"] for item in report.get("blockers", [])),
                                        report["policy"]["sha256"], done.returncode)
    return verdicts


def exercise_gate(candidate, record, wheel, python, root, env):
    """A gate policy of that version's era, as published in its examples, and the same policy with a private figure
    file, give the same verdicts before and after the upgrade, and their pins stay valid: the bytes are never
    changed. A clean change is ready; a change that adds the listed figure is refused."""
    name = record["gate_policy"]
    if not isinstance(name, str) or Path(name).name != name or not (FIXTURES / name).is_file():
        raise RuntimeError("Invalid pinned historical gate policy fixture")
    repo, private = root / "gate-repo", root / "gate-private"
    (repo / "src").mkdir(parents=True)
    private.mkdir()
    published = (FIXTURES / name).read_bytes()
    gate_env = dict(env, **{json.loads(published)["model_review"]["api_key_env"]: PLACEHOLDER})
    plain, listed, figures = private / "policy.json", private / "policy-figures.json", private / "figures.txt"
    plain.write_bytes(published)
    figures.write_text(FIGURE + "\n", encoding="utf-8", newline="\n")
    document = json.loads(published)
    document["model_review"]["forbidden_token_file"] = str(figures)  # absolute and outside the repository
    listed.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    git(repo, "init", "-q", "-b", "main", env=env)
    (repo / "src/cash.py").write_text("def total(a, b):\n    return a + b\n", encoding="utf-8", newline="\n")
    base = commit(repo, "Synthetic base", env=env)
    (repo / "src/cash.py").write_text("def total(a, b):\n    return a + b + 1\n", encoding="utf-8", newline="\n")
    clean = commit(repo, "Synthetic change", env=env)
    (repo / "src/cash.py").write_text(f"def total(a, b):\n    return a + b + {FIGURE}\n", encoding="utf-8",
                                      newline="\n")
    figure = commit(repo, "Synthetic change with the figure", env=env)
    policies = {"example": plain, "with-figure-file": listed}
    changes = {"clean": (base, clean), "figure": (clean, figure)}
    pins = {path: file_hash(path) for path in (plain, listed, figures)}
    install(python, wheel, record["sha256"], cwd=root, env=env)
    before = gate_verdicts(python, root, policies, pins, changes, env=gate_env)
    install(python, *candidate, cwd=root, env=env)
    after = gate_verdicts(python, root, policies, pins, changes, env=gate_env)
    assert {path: file_hash(path) for path in pins} == pins, "The upgrade changed a policy or figure file"
    assert after == before, f"Gate verdicts changed on upgrade: {before} -> {after}"
    assert after[("example", "clean")][0] == after[("example", "figure")][0] == "ready"
    assert after[("with-figure-file", "clean")][0] == "ready"
    assert after[("with-figure-file", "figure")][:2] == ("blocked", ["forbidden_token_present"])
    return {"gate_verdicts_unchanged": True, "gate_pins_unchanged": True}


def at_least(version, floor):
    """Whether an installed version, in canonical PEP 440 form, is at least `floor`, a pinned version's (major, minor,
    patch). 0.11.0rc1 and 0.10.0.post1 are at least 0.10.0; 0.10.0rc1 and 0.10.0.dev0 come before it; a spelling
    that is not canonical, such as 0.10.00 or 0.11.0-dirty, or one PyPI would not take, with an epoch or a local
    segment such as 0.10.0+dirty, is not a version this check accepts."""
    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    return (str(parsed) == version and parsed.epoch == 0 and parsed.local is None
            and parsed >= Version(".".join(map(str, floor))))


def check_schema_support(record, current):
    """Stop before anything is read when a historical reader that guards its evidence schema is behind the
    candidate's: what it must do with the migrated store has not been written into this check yet."""
    if record["store_schema"] < current and record["schema_guard"]:
        raise RuntimeError(f"{record['version']} guards its evidence schema ({record['store_schema']}), and the "
                           f"candidate writes {current}: extend this check for that downgrade first")


def exercise(candidate, record, wheel, root, newest):
    """`candidate` is the candidate wheel's path and the hash it was verified to when the check began; `newest` is
    the newest pinned version, which the candidate must not be older than."""
    project, home, virtual = root / "project", root / "home", root / "environment"
    project.mkdir(parents=True)
    home.mkdir()
    venv.EnvBuilder(with_pip=True).create(virtual)
    python = virtual / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    env = environment(home)
    run(python, "-m", "pip", "install", "--require-hashes", "--only-binary=:all:",
        "-r", ROOT / "requirements-action.lock", cwd=project, env=env)
    install(python, wheel, record["sha256"], cwd=project, env=env)
    config, state = project / "finassist.json", project / "state"
    observation = project / "observation.json"
    synthetic = json.loads((ROOT / "examples/evidence-observation.json").read_text(encoding="utf-8"))
    synthetic["value"] = "100"
    observation.write_text(json.dumps(synthetic), encoding="utf-8", newline="\n")
    assert run(python, "-m", "finassist", "--version", cwd=project, env=env).stdout.strip() == record["version"]
    cli(python, "init", "--output", config, cwd=project, env=env)
    original_config = config.read_bytes()
    golden = FIXTURES / (record["version"] + ".json")
    assert original_config == golden.read_bytes(), "Historical init output changed"
    assert cli(python, "--config", config, "demo", cwd=project, env=env)["status"] == "PASS"
    entry = cli(python, "--config", config, "evidence", "add", "--input", observation,
                "--state-dir", state, cwd=project, env=env)
    cli(python, "--config", config, "evidence", "approve", "--id", entry["id"],
        "--approve-hash", entry["hash"], "--state-dir", state, cwd=project, env=env)
    original_store = state / "evidence.sqlite"
    original_hash = file_hash(original_store)

    def latest():
        return cli(python, "--config", config, "evidence", "latest", "--entity", "Fictional Example",
                   "--metric", "revenue", "--state-dir", state, cwd=project, env=env)["observation"]["value"]

    install(python, *candidate, cwd=project, env=env)
    run(python, "-m", "pip", "check", cwd=project, env=env)  # the candidate's declared dependencies are satisfied
    candidate_version = run(python, "-m", "finassist", "--version", cwd=project, env=env).stdout.strip()
    assert at_least(candidate_version, newest), f"The candidate {candidate_version} is older than a published version"
    assert candidate[0].name.startswith(f"finledgerpoli-{candidate_version}-"), "The wheel's name and version differ"
    current = int(run(python, "-c", "from finassist import evidence_schema; "
                      "print(evidence_schema.SUPPORTED_EVIDENCE_SCHEMA)", cwd=project, env=env).stdout)
    check_schema_support(record, current)
    assert config.read_bytes() == original_config
    assert cli(python, "--config", config, "doctor", cwd=project, env=env)["provider"] == "offline"
    assert cli(python, "--config", config, "demo", cwd=project, env=env)["status"] == "PASS"
    # A floor the old version met is met by the candidate too.
    met = project / "minimum-met.json"
    met.write_text(json.dumps({**json.loads(original_config), "min_version": record["version"]}), encoding="utf-8",
                   newline="\n")
    assert cli(python, "--config", met, "doctor", cwd=project, env=env)["provider"] == "offline"
    # The store's schema is the one the manifest pins for that version, never what the candidate says it is.
    found = cli(python, "--config", config, "evidence", "verify", "--state-dir", state, cwd=project, env=env)
    assert found["verified"] and found["schema_version"] == record["store_schema"] <= current
    assert file_hash(original_store) == original_hash
    listing = sorted(path.name for path in state.iterdir())
    plan = cli(python, "--config", config, "evidence", "migrate", "--state-dir", state, "--dry-run", cwd=project,
               env=env)
    assert not plan["written"] and file_hash(original_store) == original_hash
    assert sorted(path.name for path in state.iterdir()) == listing  # a dry run writes nothing at all
    if record["store_schema"] < current:
        # An older store: explicit migration keeps the original and writes a new file the candidate reads.
        assert plan["target_schema_version"] == current
        migrated = cli(python, "--config", config, "evidence", "migrate", "--state-dir", state, cwd=project, env=env)
        target = Path(migrated["destination"])
        assert migrated["written"] and Path(migrated["backup"]) == original_store and target != original_store
        assert target == Path(plan["destination"]) and target.parent.resolve() == state.resolve() and target.is_file()
        assert file_hash(original_store) == original_hash
        assert cli(python, "--config", config, "evidence", "verify", "--state-dir", state, cwd=project,
                   env=env)["schema_version"] == current
        stores, historical_value = (original_store, target), "100"
    else:
        # A store already at the current schema: nothing to migrate, and a real migration writes nothing at all.
        assert "target_schema_version" not in plan
        migrated = cli(python, "--config", config, "evidence", "migrate", "--state-dir", state, cwd=project, env=env)
        assert not migrated["written"] and file_hash(original_store) == original_hash
        assert sorted(path.name for path in state.iterdir()) == listing
        stores, historical_value = (original_store,), "120"
    assert latest() == "100"  # the candidate reads the upgraded store
    revision = json.loads(observation.read_text(encoding="utf-8"))
    revision["value"] = "120"
    revision_path = project / "revision.json"
    revision_path.write_text(json.dumps(revision), encoding="utf-8", newline="\n")
    added = cli(python, "--config", config, "evidence", "add", "--input", revision_path, "--supersedes", entry["id"],
                "--state-dir", state, cwd=project, env=env)
    cli(python, "--config", config, "evidence", "approve", "--id", added["id"], "--approve-hash", added["hash"],
        "--state-dir", state, cwd=project, env=env)
    assert latest() == "120"  # and its own revision supersedes the old observation
    snapshots = {path: file_hash(path) for path in stores}
    if historical_value == "100":
        assert snapshots[original_store] == original_hash
    # Real historical code reads the store it knows without changing any file: an older reader sees the stale,
    # intact original (it cannot know the new filename and has no retroactive schema guard); a reader of the current
    # schema sees the candidate's revision.
    install(python, wheel, record["sha256"], cwd=project, env=env)
    assert latest() == historical_value
    assert {path: file_hash(path) for path in snapshots} == snapshots
    floor = project / "minimum.json"
    floor.write_text('{"min_version":"999.0.0","future_unknown":true}', encoding="utf-8", newline="\n")
    historical_floor = cli(python, "--config", floor, "doctor", cwd=project, env=env, expected_exit=2)["code"]
    assert historical_floor == record["floor_code"]
    install(python, *candidate, cwd=project, env=env)
    assert cli(python, "--config", floor, "doctor", cwd=project, env=env, expected_exit=2)["code"] == "minimum_version_required"
    # A simulated guarded reader one schema behind refuses the store a current writer has touched. The schema it
    # supports is set before the store module is imported, so it holds however that module reads it.
    run(python, "-c", f"""
import sys
from pathlib import Path
from finassist import evidence_schema
assert 'finassist.evidence_store' not in sys.modules, 'the store module was imported before the schema was set'
evidence_schema.SUPPORTED_EVIDENCE_SCHEMA = {current - 1}
from finassist.evidence_store import EvidenceStore
from finassist.errors import AssistantError
try:
    EvidenceStore(Path('state/evidence.sqlite'))
except AssistantError as error:
    assert error.code == 'evidence_store_newer_schema_upgrade_required'
else:
    raise AssertionError('Simulated older guarded reader opened a newer store')
""", cwd=project, env=env)
    assert {path: file_hash(path) for path in snapshots} == snapshots
    assert config.read_bytes() == original_config
    assert cli(python, "--config", config, "evidence", "verify", "--state-dir", state, cwd=project,
               env=env)["entries"] == 2
    assert latest() == "120"
    older = historical_value == "100"
    result = {"historical_version": record["version"], "config_byte_identical": True, "store_schema": record["store_schema"],
              "migration": "written beside the intact original" if older else "none needed",
              "historical_reader": "reads the intact original" if older else "reads the candidate's revision",
              "candidate_reads_upgraded_store": True, "candidate_dependencies_satisfied": True,
              "historical_reader_unchanged_files": True, "historical_floor_code": historical_floor,
              "guarded_downgrade_refused": True}
    if "gate_policy" in record:
        result.update(exercise_gate(candidate, record, wheel, python, root, env))
    return result


def exercise_upgrades(candidate, directory, *, cache=None):
    # Temporary roots can use OS aliases (notably /var on macOS). Pass only
    # the canonical owned staging path to installed CLIs; their link rejection
    # remains unchanged for project configuration and evidence inputs.
    # Neither the candidate nor the cache may be a link, checked before anything is resolved or created.
    if Path(candidate).is_symlink() or (cache is not None and Path(cache).is_symlink()):
        raise RuntimeError("The candidate wheel and the cache must not be links")
    if not (Path(candidate).name.startswith("finledgerpoli-") and Path(candidate).name.endswith(".whl")):
        raise RuntimeError("The candidate must be a finledgerpoli wheel")
    candidate = Path(candidate).resolve()
    directory = directory.resolve()
    manifest = json.loads((FIXTURES / "wheels.json").read_text(encoding="utf-8"))
    wheels = manifest.get("wheels") if isinstance(manifest, dict) else None
    keys = [version_key(row.get("version") if isinstance(row, dict) else None) for row in wheels or []]
    if manifest.get("distribution") != "finledgerpoli" or not keys or keys != sorted(set(keys)):
        raise RuntimeError("The pinned historical versions must be distinct and listed in release order")
    cache = Path(cache).resolve() if cache is not None else directory / "historical-wheels"
    cache.mkdir(parents=True, exist_ok=True)
    # The candidate is installed by the hash it has now, so a file changed during the check is refused.
    pinned_candidate = (candidate, file_hash(candidate))
    rows = []
    for record in wheels:
        wheel = historical_wheel(record, cache)
        rows.append(exercise(pinned_candidate, record, wheel, directory / record["version"], keys[-1]))
    print(json.dumps({"installed_upgrade_smoke": "PASS", "synthetic_only": True, "upgrades": rows}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate_wheel", type=Path)
    parser.add_argument("--cache", type=Path, help="Optional cache; pinned bytes are always verified")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="finassist-upgrade-smoke-") as directory:
        exercise_upgrades(args.candidate_wheel, Path(directory), cache=args.cache)
