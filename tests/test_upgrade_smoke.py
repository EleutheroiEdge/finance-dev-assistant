"""Offline checks of the installed-upgrade check's own rules: no wheel is downloaded or installed here."""

import hashlib
import json
import os
from pathlib import Path
import re

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
