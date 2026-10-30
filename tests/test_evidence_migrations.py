"""Synthetic immutable-original migrations and guarded downgrade refusal."""

import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest

from finassist import evidence_schema
from finassist.errors import AssistantError
from finassist.evidence_schema import migrate_evidence_store, resolve_evidence_path, verify_evidence_store
from finassist.evidence_store import EvidenceStore
from finassist.cli import main
from test_evidence_store import observation


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def legacy_store(tmp_path):
    path = tmp_path / "evidence.sqlite"
    with EvidenceStore(path) as store:
        first = store.add(observation())
        store.decide(first["id"], first["hash"], status="approved")
    # Reproduce the actual historical header on synthetic current-layout data.
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=0")
    return path


def test_loading_legacy_store_does_not_migrate_or_rewrite(legacy_store):
    before = file_hash(legacy_store)
    with EvidenceStore(legacy_store) as store:
        assert store.verify() == {"verified": True, "schema_version": 0, "entries": 1, "decisions": 1}
        assert store.latest_approved("Fictional Example", "revenue")["observation"]["value"] == "100"
    assert file_hash(legacy_store) == before
    assert list(legacy_store.parent.iterdir()) == [legacy_store]


def test_dry_run_preserves_original_then_explicit_copy_preserves_lineage(legacy_store):
    before = file_hash(legacy_store)
    plan = migrate_evidence_store(legacy_store)
    assert plan["changed"] and not plan["written"]
    assert Path(plan["backup"]) == legacy_store
    assert not Path(plan["destination"]).exists() and file_hash(legacy_store) == before
    result = migrate_evidence_store(legacy_store, dry_run=False)
    target = legacy_store.with_name("evidence.v2.sqlite")
    assert result["written"] and Path(result["destination"]) == target
    assert file_hash(legacy_store) == before
    assert resolve_evidence_path(legacy_store) == target
    assert verify_evidence_store(legacy_store) == {"verified": True, "schema_version": 2, "entries": 1, "decisions": 1}
    with EvidenceStore(legacy_store) as store:
        assert store.path == target
        assert store.latest_approved("Fictional Example", "revenue")["observation"]["value"] == "100"
        revision = store.add(observation("120"), supersedes=1)
        store.decide(revision["id"], revision["hash"], status="approved")
    assert file_hash(legacy_store) == before
    assert verify_evidence_store(target)["entries"] == 2
    assert not migrate_evidence_store(legacy_store, dry_run=False)["changed"]


def test_new_store_records_schema_and_guard_refuses_newer_without_writes(tmp_path, monkeypatch):
    path = tmp_path / "evidence.sqlite"
    with EvidenceStore(path) as store:
        assert store.verify()["schema_version"] == 2
    before = file_hash(path)
    monkeypatch.setattr(evidence_schema, "SUPPORTED_EVIDENCE_SCHEMA", 1)
    with pytest.raises(AssistantError, match="evidence_store_newer_schema_upgrade_required"):
        EvidenceStore(path)
    assert file_hash(path) == before
    assert list(tmp_path.iterdir()) == [path]


def test_older_guarded_reader_never_falls_back_to_original(legacy_store, monkeypatch):
    migrate_evidence_store(legacy_store, dry_run=False)
    target = legacy_store.with_name("evidence.v2.sqlite")
    before = {p.name: file_hash(p) for p in (legacy_store, target)}
    monkeypatch.setattr(evidence_schema, "SUPPORTED_EVIDENCE_SCHEMA", 1)
    with pytest.raises(AssistantError, match="evidence_store_newer_schema_upgrade_required"):
        EvidenceStore(legacy_store)
    assert before == {p.name: file_hash(p) for p in (legacy_store, target)}


def test_newer_header_and_filename_both_fail_closed(legacy_store):
    before = file_hash(legacy_store)
    future = legacy_store.with_name("evidence.v3.sqlite")
    future.write_bytes(legacy_store.read_bytes())
    with pytest.raises(AssistantError, match="evidence_store_newer_schema_upgrade_required"):
        EvidenceStore(legacy_store)
    assert file_hash(legacy_store) == before
    future.unlink()
    with sqlite3.connect(legacy_store) as connection:
        connection.execute("PRAGMA user_version=99")
    changed = file_hash(legacy_store)
    with pytest.raises(AssistantError, match="evidence_store_newer_schema_upgrade_required"):
        EvidenceStore(legacy_store)
    assert file_hash(legacy_store) == changed


def test_busy_source_and_corruption_refuse_migration(legacy_store):
    sidecar = Path(str(legacy_store) + "-wal")
    sidecar.write_bytes(b"synthetic sidecar")
    with pytest.raises(AssistantError, match="evidence_store_busy_close_writers"):
        migrate_evidence_store(legacy_store, dry_run=False)
    assert not legacy_store.with_name("evidence.v2.sqlite").exists()
    sidecar.unlink()
    with sqlite3.connect(legacy_store) as connection:
        connection.execute("DROP TRIGGER immutable_evidence")
        connection.execute("UPDATE entries SET hash='invalid'")
    before = file_hash(legacy_store)
    with pytest.raises(AssistantError, match="evidence_store_(integrity_failed|schema_invalid)"):
        migrate_evidence_store(legacy_store, dry_run=False)
    assert file_hash(legacy_store) == before
    assert not legacy_store.with_name("evidence.v2.sqlite").exists()


def test_existing_destination_is_never_overwritten(legacy_store):
    target = legacy_store.with_name("evidence.v2.sqlite")
    target.write_bytes(b"synthetic unrelated content")
    with pytest.raises(AssistantError):
        migrate_evidence_store(legacy_store, dry_run=False)
    assert target.read_bytes() == b"synthetic unrelated content"


def test_cli_dry_run_is_read_only_then_explicit_migration_and_verify(legacy_store, capsys):
    before = file_hash(legacy_store)
    args = ["evidence", "migrate", "--state-dir", str(legacy_store.parent)]
    assert main(args + ["--dry-run"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert not report["written"] and list(legacy_store.parent.iterdir()) == [legacy_store]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["written"]
    assert file_hash(legacy_store) == before
    assert main(["evidence", "verify", "--state-dir", str(legacy_store.parent)]) == 0
    assert json.loads(capsys.readouterr().out)["schema_version"] == 2


def test_doctor_fix_migrates_only_explicitly_and_preserves_config_bytes(legacy_store, capsys):
    config = legacy_store.parent / "finassist.json"
    original = b'{ "profile" : "general" }\r\n'
    config.write_bytes(original)
    before = file_hash(legacy_store)
    assert main(["--config", str(config), "doctor", "--fix", "--state-dir", str(legacy_store.parent)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["fixes"]["evidence"]["written"] and not report["network_called"]
    assert not report["fixes"]["configuration"]["written"]
    assert config.read_bytes() == original and file_hash(legacy_store) == before


def test_doctor_future_schema_preflight_preserves_every_file(legacy_store, capsys, monkeypatch):
    monkeypatch.chdir(legacy_store.parent)
    with sqlite3.connect(legacy_store) as connection:
        connection.execute("PRAGMA user_version=99")
    before = file_hash(legacy_store)
    assert main(["doctor", "--fix", "--state-dir", str(legacy_store.parent)]) == 2
    assert "evidence_store_newer_schema_upgrade_required" in capsys.readouterr().err
    assert list(legacy_store.parent.iterdir()) == [legacy_store] and file_hash(legacy_store) == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX read-only mode preservation; Windows inherits ACLs")
def test_newer_readonly_store_refusal_preserves_permissions_and_bytes(tmp_path, monkeypatch):
    path = tmp_path / "evidence.v2.sqlite"
    with EvidenceStore(path):
        pass
    path.chmod(0o400)
    before, mode = file_hash(path), path.stat().st_mode
    monkeypatch.setattr(evidence_schema, "SUPPORTED_EVIDENCE_SCHEMA", 1)
    with pytest.raises(AssistantError, match="evidence_store_newer_schema_upgrade_required"):
        EvidenceStore(path)
    assert path.stat().st_mode == mode and file_hash(path) == before


def test_interrupted_initialization_closes_connection(tmp_path, monkeypatch):
    def fail(_self):
        raise AssistantError("synthetic_init_failure")

    monkeypatch.setattr(EvidenceStore, "_create_schema", fail)
    instance = EvidenceStore.__new__(EvidenceStore)
    with pytest.raises(AssistantError, match="synthetic_init_failure"):
        instance.__init__(tmp_path / "evidence.sqlite")
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        instance.db.execute("SELECT 1")


def test_dry_run_cannot_be_ignored_for_a_mutation(legacy_store, capsys):
    before = file_hash(legacy_store)
    assert main(["evidence", "add", "--dry-run", "--state-dir", str(legacy_store.parent)]) == 2
    assert "evidence_dry_run_requires_migrate" in capsys.readouterr().err
    assert list(legacy_store.parent.iterdir()) == [legacy_store] and file_hash(legacy_store) == before


@pytest.mark.parametrize("filename,expected", [
    ("evidence", "evidence.v2"), ("evidence.v1", "evidence.v2"),
    ("evidence.v1.db", "evidence.v2.db"), ("evidence.v1.sqlite", "evidence.v2.sqlite"),
])
def test_explicit_versioned_paths_migrate_the_logical_root(tmp_path, filename, expected):
    source = tmp_path / filename
    with EvidenceStore(tmp_path / "seed.sqlite"):
        pass
    source.write_bytes((tmp_path / "seed.sqlite").read_bytes())
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA user_version=1")
    before = file_hash(source)
    report = migrate_evidence_store(source, dry_run=False)
    assert Path(report["destination"]) == tmp_path / expected
    assert file_hash(source) == before
    assert verify_evidence_store(tmp_path / expected)["schema_version"] == 2


@pytest.mark.parametrize("suffix", ["", ".sqlite"])
@pytest.mark.parametrize("version", [3, 1_000_000])
def test_future_named_sibling_never_falls_back_even_without_extension(tmp_path, suffix, version):
    logical = tmp_path / ("evidence" + suffix)
    with EvidenceStore(logical):
        pass
    future = tmp_path / (f"evidence.v{version}" + suffix)
    future.write_bytes(logical.read_bytes())
    before = {path: file_hash(path) for path in (logical, future)}
    with pytest.raises(AssistantError, match="evidence_store_newer_schema_upgrade_required"):
        EvidenceStore(logical)
    assert {path: file_hash(path) for path in before} == before
