"""Exercise pinned public historical wheels against a local candidate, using synthetic data."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import venv

from ci_install import ROOT


def environment(home):
    # No provider keys, user Python paths, pip configuration or real home settings.
    names = ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP")
    result = {key: os.environ[key] for key in names if key in os.environ}
    result.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / "config"),
                  XDG_CACHE_HOME=str(home / "cache"), APPDATA=str(home / "appdata"),
                  LOCALAPPDATA=str(home / "localappdata"), PYTHONIOENCODING="utf-8",
                  PYTHONDONTWRITEBYTECODE="1", PIP_CONFIG_FILE=os.devnull,
                  PIP_DISABLE_PIP_VERSION_CHECK="1", FINASSIST_NO_UPDATE_CHECK="1")
    return result


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("Historical wheel redirects are not allowed")


def historical_wheel(record, directory):
    url = urllib.parse.urlsplit(record["url"])
    expected = f"finledgerpoli-{record['version']}-py3-none-any.whl"
    if (record["version"] not in {"0.3.1", "0.4.0"} or record["filename"] != expected
            or url.scheme != "https" or url.netloc != "files.pythonhosted.org"
            or url.query or url.fragment or not url.path.endswith("/" + expected)
            or not 0 < record["size"] <= 2_000_000):
        raise RuntimeError("Invalid pinned historical wheel manifest")
    target = directory / expected
    if not target.exists():
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(record["url"], timeout=30) as response:
            data = response.read(record["size"] + 1)
        if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise RuntimeError("Historical wheel bytes do not match the reviewed PyPI hash")
        target.write_bytes(data)
    if target.stat().st_size != record["size"] or file_hash(target) != record["sha256"]:
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


def install(python, wheel, *, cwd, env):
    wheel = wheel.resolve()
    with tempfile.TemporaryDirectory(prefix="install-", dir=cwd) as directory:
        requirement = Path(directory) / "wheel.txt"
        requirement.write_text(wheel.as_uri() + " --hash=sha256:" + file_hash(wheel) + "\n", encoding="utf-8")
        run(python, "-m", "pip", "install", "--require-hashes", "--no-deps", "--force-reinstall",
            "-r", requirement, cwd=cwd, env=env)


def exercise(candidate, record, wheel, root):
    project, home, virtual = root / "project", root / "home", root / "environment"
    project.mkdir(parents=True)
    home.mkdir()
    venv.EnvBuilder(with_pip=True).create(virtual)
    python = virtual / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    env = environment(home)
    run(python, "-m", "pip", "install", "--require-hashes", "--only-binary=:all:",
        "-r", ROOT / "requirements-action.lock", cwd=project, env=env)
    install(python, wheel, cwd=project, env=env)
    config, state = project / "finassist.json", project / "state"
    observation = project / "observation.json"
    synthetic = json.loads((ROOT / "examples/evidence-observation.json").read_text(encoding="utf-8"))
    synthetic["value"] = "100"
    observation.write_text(json.dumps(synthetic), encoding="utf-8")
    assert run(python, "-m", "finassist", "--version", cwd=project, env=env).stdout.strip() == record["version"]
    cli(python, "init", "--output", config, cwd=project, env=env)
    original_config = config.read_bytes()
    golden = ROOT / "examples/upgrade-fixtures" / (record["version"] + ".json")
    assert original_config == golden.read_bytes(), "Historical init output changed"
    assert cli(python, "--config", config, "demo", cwd=project, env=env)["status"] == "PASS"
    entry = cli(python, "--config", config, "evidence", "add", "--input", observation,
                "--state-dir", state, cwd=project, env=env)
    cli(python, "--config", config, "evidence", "approve", "--id", entry["id"],
        "--approve-hash", entry["hash"], "--state-dir", state, cwd=project, env=env)
    original_store = state / "evidence.sqlite"
    original_hash = file_hash(original_store)
    install(python, candidate, cwd=project, env=env)
    assert config.read_bytes() == original_config
    assert cli(python, "--config", config, "doctor", cwd=project, env=env)["provider"] == "offline"
    assert cli(python, "evidence", "verify", "--state-dir", state, cwd=project, env=env)["verified"]
    assert file_hash(original_store) == original_hash
    plan = cli(python, "evidence", "migrate", "--state-dir", state, "--dry-run", cwd=project, env=env)
    assert not plan["written"] and file_hash(original_store) == original_hash
    migrated = cli(python, "evidence", "migrate", "--state-dir", state, cwd=project, env=env)
    target = state / "evidence.v2.sqlite"
    assert migrated["written"] and Path(migrated["backup"]) == original_store
    assert file_hash(original_store) == original_hash and target.is_file()
    assert cli(python, "evidence", "verify", "--state-dir", state, cwd=project, env=env)["schema_version"] == 2
    revision = json.loads(observation.read_text(encoding="utf-8"))
    revision["value"] = "120"
    revision_path = project / "revision.json"
    revision_path.write_text(json.dumps(revision), encoding="utf-8")
    added = cli(python, "evidence", "add", "--input", revision_path, "--supersedes", entry["id"],
                "--state-dir", state, cwd=project, env=env)
    cli(python, "evidence", "approve", "--id", added["id"], "--approve-hash", added["hash"],
        "--state-dir", state, cwd=project, env=env)
    snapshots = {path: file_hash(path) for path in (original_store, target)}
    assert snapshots[original_store] == original_hash
    # Real historical code sees stale, intact original evidence. It cannot know
    # the new filename; it is not claimed to contain a retroactive schema guard.
    install(python, wheel, cwd=project, env=env)
    latest = cli(python, "--config", config, "evidence", "latest", "--entity", "Fictional Example",
                 "--metric", "revenue", "--state-dir", state, cwd=project, env=env)
    assert latest["observation"]["value"] == "100"
    assert {path: file_hash(path) for path in snapshots} == snapshots
    floor = project / "minimum.json"
    floor.write_text('{"min_version":"999.0.0","future_unknown":true}', encoding="utf-8")
    assert cli(python, "--config", floor, "doctor", cwd=project, env=env, expected_exit=2)["code"] == "unknown_config_option"
    install(python, candidate, cwd=project, env=env)
    assert cli(python, "--config", floor, "doctor", cwd=project, env=env, expected_exit=2)["code"] == "minimum_version_required"
    run(python, "-c", """
from pathlib import Path
from finassist import evidence_schema
from finassist.evidence_store import EvidenceStore
from finassist.errors import AssistantError
evidence_schema.SUPPORTED_EVIDENCE_SCHEMA = 1
try:
    EvidenceStore(Path('state/evidence.sqlite'))
except AssistantError as error:
    assert error.code == 'evidence_store_newer_schema_upgrade_required'
else:
    raise AssertionError('Simulated older guarded reader opened a newer store')
""", cwd=project, env=env)
    assert {path: file_hash(path) for path in snapshots} == snapshots
    assert config.read_bytes() == original_config
    assert cli(python, "evidence", "verify", "--state-dir", state, cwd=project, env=env)["entries"] == 2
    return {"historical_version": record["version"], "config_byte_identical": True,
            "original_store_byte_identical": True, "migrated_store_verified": True,
            "historical_downgrade_stale_intact": True, "guarded_downgrade_refused": True}


def exercise_upgrades(candidate, directory, *, cache=None):
    # Temporary roots can use OS aliases (notably /var on macOS). Pass only
    # the canonical owned staging path to installed CLIs; their link rejection
    # remains unchanged for project configuration and evidence inputs.
    directory = directory.resolve()
    manifest = json.loads((ROOT / "examples/upgrade-fixtures/wheels.json").read_text(encoding="utf-8"))
    if manifest["distribution"] != "finledgerpoli" or [row["version"] for row in manifest["wheels"]] != ["0.3.1", "0.4.0"]:
        raise RuntimeError("Expected both pinned historical versions")
    cache = cache or directory / "historical-wheels"
    cache.mkdir(parents=True, exist_ok=True)
    rows = []
    for record in manifest["wheels"]:
        wheel = historical_wheel(record, cache)
        rows.append(exercise(candidate, record, wheel, directory / record["version"]))
    print(json.dumps({"installed_upgrade_smoke": "PASS", "synthetic_only": True, "upgrades": rows}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate_wheel", type=Path)
    parser.add_argument("--cache", type=Path, help="Optional cache; pinned bytes are always verified")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="finassist-upgrade-smoke-") as directory:
        exercise_upgrades(args.candidate_wheel.resolve(), Path(directory), cache=args.cache)
