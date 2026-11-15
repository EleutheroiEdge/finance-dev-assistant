"""Offline checks of the installed-upgrade check's own rules: no wheel is downloaded or installed here."""

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "examples/upgrade-fixtures"


@pytest.fixture
def upgrade_smoke(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))  # it imports ci_install from its own folder
    import upgrade_smoke
    return upgrade_smoke


def test_the_manifest_pins_each_published_version_in_release_order(upgrade_smoke):
    manifest = json.loads((FIXTURES / "wheels.json").read_text(encoding="utf-8"))
    versions = [row["version"] for row in manifest["wheels"]]
    keys = [upgrade_smoke.version_key(version) for version in versions]
    assert manifest["distribution"] == "finledgerpoli" and keys == sorted(set(keys))
    assert {"0.9.0", "0.10.0"} <= set(versions)  # the published versions users run
    for row in manifest["wheels"]:
        assert re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) and 0 < row["size"] <= 2_000_000
        assert type(row["store_schema"]) is int and row["floor_code"] in upgrade_smoke._FLOOR_CODES
        assert type(row["schema_guard"]) is bool
        assert (FIXTURES / (row["version"] + ".json")).is_file()  # the golden init output
        if "gate_policy" in row:
            policy = json.loads((FIXTURES / row["gate_policy"]).read_text(encoding="utf-8"))
            assert policy["schema_version"] == 2 and policy["model_review"]["api_key_env"]


def _record(data, version="9.9.9"):
    name = f"finledgerpoli-{version}-py3-none-any.whl"
    return {"version": version, "filename": name, "url": f"https://files.pythonhosted.org/packages/00/{name}",
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "store_schema": 2, "schema_guard": True,
            "floor_code": "minimum_version_required"}


def test_a_cached_wheel_is_used_only_with_its_pinned_bytes_and_never_through_a_link(upgrade_smoke, tmp_path):
    data = b"synthetic wheel bytes"
    record = _record(data)
    cached = tmp_path / record["filename"]
    cached.write_bytes(data)
    assert upgrade_smoke.historical_wheel(record, tmp_path) == cached
    cached.write_bytes(b"synthetic wheel bytez")  # same size, other bytes
    with pytest.raises(RuntimeError, match="hash mismatch"):
        upgrade_smoke.historical_wheel(record, tmp_path)
    elsewhere = tmp_path / "elsewhere.whl"
    elsewhere.write_bytes(data)
    cached.unlink()
    try:
        cached.symlink_to(elsewhere)
    except OSError:
        pytest.skip("this system did not allow a symbolic link")
    with pytest.raises(RuntimeError, match="link"):
        upgrade_smoke.historical_wheel(record, tmp_path)


@pytest.mark.parametrize("change", [
    {"version": "0.9"}, {"sha256": "0" * 63}, {"size": 3_000_000}, {"store_schema": "2"}, {"store_schema": -1},
    {"schema_guard": "yes"}, {"floor_code": "other"},
    {"url": "https://example.invalid/finledgerpoli-9.9.9-py3-none-any.whl"},
], ids=["version", "hash", "size", "schema-text", "schema-negative", "guard-text", "floor", "host"])
def test_a_manifest_record_out_of_its_rules_refuses_before_anything_is_read(upgrade_smoke, tmp_path, change):
    record = {**_record(b"x"), **change}
    with pytest.raises(RuntimeError, match="Invalid pinned historical wheel manifest"):
        upgrade_smoke.historical_wheel(record, tmp_path)


def test_a_cache_that_is_a_link_refuses(upgrade_smoke, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "cache"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("this system did not allow a symbolic link")
    with pytest.raises(RuntimeError, match="cache is a link"):
        upgrade_smoke.historical_wheel(_record(b"x"), link)


def test_a_download_that_cannot_be_moved_into_place_leaves_nothing_behind(upgrade_smoke, tmp_path, monkeypatch):
    data = b"synthetic wheel bytes"

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exception):
            return False

        def read(self, size):
            return data[:size]

    class Opener:
        def open(self, url, timeout):
            return Response()

    def refuse(source, target):
        raise OSError("synthetic: the move failed")

    monkeypatch.setattr(upgrade_smoke.urllib.request, "build_opener", lambda *handlers: Opener())
    monkeypatch.setattr(upgrade_smoke.os, "replace", refuse)
    with pytest.raises(OSError, match="the move failed"):
        upgrade_smoke.historical_wheel(_record(data), tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_a_download_whose_write_fails_leaves_nothing_behind(upgrade_smoke, tmp_path, monkeypatch):
    data = b"synthetic wheel bytes"

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exception):
            return False

        def read(self, size):
            return data[:size]

    class Opener:
        def open(self, url, timeout):
            return Response()

    real = upgrade_smoke.tempfile.NamedTemporaryFile

    def failing(**options):
        handle = real(**options)

        def write(content):
            raise OSError("synthetic: the disk is full")

        handle.write = write
        return handle

    monkeypatch.setattr(upgrade_smoke.urllib.request, "build_opener", lambda *handlers: Opener())
    monkeypatch.setattr(upgrade_smoke.tempfile, "NamedTemporaryFile", failing)
    with pytest.raises(OSError, match="disk is full"):
        upgrade_smoke.historical_wheel(_record(data), tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("version,met", [
    ("0.10.0", True), ("0.11.0", True), ("0.11.0rc1", True), ("0.10.0.post1", True), ("1.0.0", True),
    ("0.10.0rc1", False), ("0.10.0a1", False), ("0.10.0.dev0", False), ("0.9.9", False), ("0.0.0", False),
    ("0.10.00", False), ("0.11.0-dirty", False), ("0.10.0+dirty", False), ("0.11.0+local1", False),
    ("1!0.1.0", False), ("unknown", False),
])
def test_the_candidate_must_not_be_older_than_a_published_version(upgrade_smoke, version, met):
    assert upgrade_smoke.at_least(version, (0, 10, 0)) is met


def test_a_guarded_reader_behind_the_candidates_schema_stops_the_check_first(upgrade_smoke):
    guarded = {"version": "0.9.0", "store_schema": 2, "schema_guard": True}
    with pytest.raises(RuntimeError, match=r"0\.9\.0 guards its evidence schema \(2\), and the candidate writes 3"):
        upgrade_smoke.check_schema_support(guarded, 3)
    upgrade_smoke.check_schema_support(guarded, 2)  # the same schema: nothing to settle
    upgrade_smoke.check_schema_support({**guarded, "store_schema": 0, "schema_guard": False}, 3)  # no guard


def test_a_candidate_that_is_a_link_or_not_a_finledgerpoli_wheel_refuses_before_anything_runs(upgrade_smoke,
                                                                                               tmp_path):
    wheel = tmp_path / "finledgerpoli-9.9.9-py3-none-any.whl"
    wheel.write_bytes(b"synthetic")
    other = tmp_path / "finassist-9.9.9-py3-none-any.whl"
    other.write_bytes(b"synthetic")
    with pytest.raises(RuntimeError, match="finledgerpoli wheel"):
        upgrade_smoke.exercise_upgrades(other, tmp_path / "work")
    try:
        (tmp_path / "link").mkdir()
        (tmp_path / "link" / wheel.name).symlink_to(wheel)
        (tmp_path / "dangling").symlink_to(tmp_path / "nowhere", target_is_directory=True)
    except OSError:
        pytest.skip("this system did not allow a symbolic link")
    with pytest.raises(RuntimeError, match="must not be links"):
        upgrade_smoke.exercise_upgrades(tmp_path / "link" / wheel.name, tmp_path / "work")
    with pytest.raises(RuntimeError, match="must not be links"):
        upgrade_smoke.exercise_upgrades(wheel, tmp_path / "work", cache=tmp_path / "dangling")
    assert not (tmp_path / "work").exists()


@pytest.mark.parametrize("version,wheel,refusal", [
    ("0.11.0+dirty", "finledgerpoli-0.11.0+dirty-py3-none-any.whl", "not a canonical version"),
    ("1!0.11.0", "finledgerpoli-1!0.11.0-py3-none-any.whl", "not a canonical version"),
    ("0.11.00", "finledgerpoli-0.11.00-py3-none-any.whl", "not a canonical version"),
    ("0.9.9", "finledgerpoli-0.9.9-py3-none-any.whl", "older than the newest published version, 0.10.0"),
    ("0.11.0", "finledgerpoli-0.12.0-py3-none-any.whl", "name and version differ"),
    ("0.11.0", "finledgerpoli-0.11.0rc1-py3-none-any.whl", "name and version differ"),
])
def test_each_refused_candidate_version_names_the_rule_it_broke(upgrade_smoke, version, wheel, refusal):
    with pytest.raises(RuntimeError, match=re.escape(refusal)):
        upgrade_smoke.check_candidate_version(version, wheel, (0, 10, 0))


def test_a_candidate_in_release_form_named_for_its_version_passes(upgrade_smoke):
    for version in ("0.10.0", "0.11.0", "0.11.0rc1", "0.10.0.post1"):
        upgrade_smoke.check_candidate_version(version, f"finledgerpoli-{version}-py3-none-any.whl", (0, 10, 0))


def _link(link, target):
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError:
        pytest.skip("this system did not allow a symbolic link")


def test_a_link_named_through_a_missing_folder_and_dotdot_still_refuses(upgrade_smoke, tmp_path):
    (tmp_path / "real").mkdir()
    _link(tmp_path / "leaf", tmp_path / "real")
    wheel = tmp_path / "finledgerpoli-9.9.9-py3-none-any.whl"
    wheel.write_bytes(b"synthetic")
    roundabout = tmp_path / "missing" / ".." / "leaf"
    with pytest.raises(RuntimeError, match="must not be links"):
        upgrade_smoke.unlinked(roundabout)
    with pytest.raises(RuntimeError, match="must not be links"):
        upgrade_smoke.exercise_upgrades(wheel, tmp_path / "work", cache=roundabout)
    assert not (tmp_path / "work").exists() and list((tmp_path / "real").iterdir()) == []


def test_a_default_cache_that_is_a_link_refuses(upgrade_smoke, tmp_path):
    wheel = tmp_path / "finledgerpoli-9.9.9-py3-none-any.whl"
    wheel.write_bytes(b"synthetic")
    (tmp_path / "real").mkdir()
    (tmp_path / "work").mkdir()
    _link(tmp_path / "work" / "historical-wheels", tmp_path / "real")
    with pytest.raises(RuntimeError, match="must not be links"):
        upgrade_smoke.exercise_upgrades(wheel, tmp_path / "work")
    assert list((tmp_path / "real").iterdir()) == []


def test_a_link_in_a_parent_folder_is_allowed(upgrade_smoke, tmp_path):
    (tmp_path / "real").mkdir()
    _link(tmp_path / "alias", tmp_path / "real")
    assert upgrade_smoke.unlinked(tmp_path / "alias" / "cache") == (tmp_path / "real").resolve() / "cache"


def test_a_relative_path_is_made_absolute_and_a_path_must_end_in_a_name(upgrade_smoke, tmp_path, monkeypatch):
    (tmp_path / "real").mkdir()
    monkeypatch.chdir(tmp_path / "real")
    assert upgrade_smoke.unlinked(Path("cache")) == (tmp_path / "real").resolve() / "cache"
    for ending in (tmp_path / "real" / "..", Path(".")):
        with pytest.raises(RuntimeError, match="must end in a file or folder name"):
            upgrade_smoke.unlinked(ending)


def test_the_script_checks_with_require_not_assert_so_python_dash_o_keeps_every_check(upgrade_smoke, tmp_path):
    tree = ast.parse((ROOT / "scripts/upgrade_smoke.py").read_text(encoding="utf-8"))
    assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Assert)] == []
    upgrade_smoke.require(True, "unused")
    with pytest.raises(RuntimeError, match="a failed check"):
        upgrade_smoke.require(False, "a failed check")
    # Started as the script starts every child, so no outer PYTHON* variable (PYTHONSAFEPATH, PYTHONOPTIMIZE)
    # changes the run and no bytecode is written; from a staged copy in a folder whose name is outside every ANSI code
    # page, so the traceback's path must come back as UTF-8; exit 3 if -O is not on; and the match is the exception
    # line, which a failed import in the same source line cannot produce.
    staged = tmp_path / ("Ren" + chr(0xE9) + "-" + chr(0x2014) + "-" + chr(0x2713)) / "scripts"
    staged.mkdir(parents=True)
    for name in ("upgrade_smoke.py", "ci_install.py"):
        (staged / name).write_bytes((ROOT / "scripts" / name).read_bytes())
    probe = ("import sys; sys.path.insert(0, sys.argv[1]); sys.flags.optimize or sys.exit(3); "
             "import upgrade_smoke; upgrade_smoke.require(False, 'a failed check')")
    optimized = subprocess.run([sys.executable, *upgrade_smoke.ISOLATED, "-O", "-c", probe, str(staged)],
                               cwd=tmp_path, env=upgrade_smoke.environment(tmp_path), capture_output=True,
                               text=True, encoding="utf-8", timeout=60, check=False)
    assert optimized.returncode == 1 and "RuntimeError: a failed check" in optimized.stderr, optimized.stderr
    assert staged.parent.name in optimized.stderr  # the traceback's path, decoded
    assert not (staged / "__pycache__").exists()  # nothing written beside the script


def test_a_failed_child_reports_its_stdout_when_its_stderr_is_empty(upgrade_smoke, tmp_path):
    code = "import sys; print('a blocked report'); sys.exit(1)"
    with pytest.raises(RuntimeError, match="a blocked report"):
        upgrade_smoke.run(sys.executable, "-c", code, cwd=tmp_path, env=upgrade_smoke.environment(tmp_path))


def test_an_isolated_child_prints_utf8_and_writes_no_bytecode(upgrade_smoke, tmp_path):
    text = "Ren" + chr(0xE9) + " " + chr(0x2014) + " " + chr(0x2713)  # outside every ANSI code page together
    code = (f"import sys; print({text!r}); "
            "raise SystemExit(0 if sys.dont_write_bytecode and sys.flags.utf8_mode else 3)")
    result = upgrade_smoke.run(sys.executable, "-c", code, cwd=tmp_path, env=upgrade_smoke.environment(tmp_path))
    assert result.stdout.strip() == text


def test_the_gate_check_starts_its_children_the_same_isolated_way(upgrade_smoke, tmp_path, monkeypatch):
    seen = []

    def run(command, **kwargs):
        seen.append(command)
        report = {"status": "ready", "blockers": [], "policy": {"sha256": "a" * 64}}
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(report), stderr="")

    monkeypatch.setattr(upgrade_smoke.subprocess, "run", run)
    policy = tmp_path / "policy.json"
    verdicts = upgrade_smoke.gate_verdicts("python", tmp_path, {"example": policy}, {policy: "b" * 64},
                                           {"clean": ("base", "head")}, env={})
    assert verdicts == {("example", "clean"): ("ready", [], "a" * 64, 0)}
    assert [command[1:5] for command in seen] == [list(upgrade_smoke.ISOLATED)]


@pytest.mark.parametrize("kind", ["missing", "folder"])
def test_a_candidate_that_is_not_an_existing_file_refuses_before_anything_is_created(upgrade_smoke, tmp_path, kind):
    wheel = tmp_path / "finledgerpoli-9.9.9-py3-none-any.whl"
    if kind == "folder":
        wheel.mkdir()
    with pytest.raises(RuntimeError, match="must be an existing file"):
        upgrade_smoke.exercise_upgrades(wheel, tmp_path / "work")
    assert not (tmp_path / "work").exists()


def test_a_windows_junction_counts_as_a_link(upgrade_smoke, tmp_path, monkeypatch):
    junction = tmp_path / "junction"
    junction.mkdir()
    real_lstat = os.lstat

    def lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if Path(path) == junction:  # as Windows reports a junction: a folder with a mount-point reparse tag
            return types.SimpleNamespace(st_mode=info.st_mode, st_reparse_tag=upgrade_smoke.JUNCTION_TAG)
        return info

    monkeypatch.setattr(upgrade_smoke.os, "lstat", lstat)
    assert upgrade_smoke.is_link(junction) and not upgrade_smoke.is_link(tmp_path)
    assert not upgrade_smoke.is_link(tmp_path / "missing" / "leaf")
    with pytest.raises(RuntimeError, match="must not be links"):
        upgrade_smoke.unlinked(junction)
    with pytest.raises(RuntimeError, match="cache is a link"):
        upgrade_smoke.historical_wheel(_record(b"x"), junction)


@pytest.mark.skipif(sys.platform != "win32", reason="directory junctions are a Windows feature")
def test_a_real_windows_junction_refuses(upgrade_smoke, tmp_path):
    import _winapi

    (tmp_path / "real").mkdir()
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(tmp_path / "real"), str(junction))
    assert upgrade_smoke.is_link(junction)
    with pytest.raises(RuntimeError, match="must not be links"):
        upgrade_smoke.unlinked(junction)


def test_a_wheel_is_installed_by_the_hash_it_was_pinned_to_not_one_read_again(upgrade_smoke, tmp_path, monkeypatch):
    wheel = tmp_path / "finledgerpoli-9.9.9-py3-none-any.whl"
    wheel.write_bytes(b"changed after it was verified")
    seen = []

    def run(python, *args, cwd, env, expected_exit=0):
        seen.append(Path(args[-1]).read_text(encoding="utf-8"))

    monkeypatch.setattr(upgrade_smoke, "run", run)
    pinned = "a" * 64
    upgrade_smoke.install("python", wheel, pinned, cwd=tmp_path, env=dict(os.environ))
    # Named as the distribution, so pip refuses a wheel whose metadata names another one.
    assert seen == ["finledgerpoli @ " + wheel.resolve().as_uri() + " --hash=sha256:" + pinned + "\n"]
