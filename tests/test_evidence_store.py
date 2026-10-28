import sqlite3

import pytest

from finassist.errors import AssistantError
from finassist.evidence_store import EvidenceStore


def observation(value="100"):
    return {
        "entity": "Fictional Example",
        "metric": "revenue",
        "value": value,
        "unit": "USD",
        "period_start": "2025-01-01T00:00:00Z",
        "period_end": "2025-12-31T00:00:00Z",
        "published_at": "2026-02-01T00:00:00Z",
        "retrieved_at": "2026-02-02T00:00:00Z",
        "source": "fictional-filing",
        "period_kind": "annual",
    }


def test_only_explicitly_approved_revision_is_read(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        first = store.add(observation())
        with pytest.raises(AssistantError, match="approved_evidence_absent"):
            store.latest_approved("Fictional Example", "revenue")
        store.decide(first["id"], first["hash"], status="approved")
        revision = store.add(observation("120"), supersedes=first["id"])
        assert store.latest_approved("Fictional Example", "revenue")["observation"]["value"] == "100"
        store.decide(revision["id"], revision["hash"], status="approved")
        assert store.latest_approved("Fictional Example", "revenue")["observation"]["value"] == "120"


def test_content_never_updates_and_approval_is_not_model_data(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        with pytest.raises(AssistantError, match="approval_cannot_be_supplied_in_content"):
            store.add({**observation(), "status": "approved"})
        item = store.add(observation())
        with pytest.raises(sqlite3.IntegrityError, match="immutable_evidence"):
            store.db.execute("UPDATE entries SET payload='{}' WHERE id=?", (item["id"],))
        with pytest.raises(sqlite3.IntegrityError, match="immutable_evidence"):
            store.db.execute("DELETE FROM entries WHERE id=?", (item["id"],))
        store.db.rollback()
        with pytest.raises(AssistantError, match="evidence_approval_hash_mismatch"):
            store.decide(item["id"], "wrong", status="approved")
        store.decide(item["id"], item["hash"], status="rejected")
        with pytest.raises(AssistantError, match="evidence_decision_already_recorded"):
            store.decide(item["id"], item["hash"], status="approved")


def test_revisions_do_not_fork_or_change_entity(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        first = store.add(observation())
        with pytest.raises(AssistantError, match="evidence_revision_required"):
            store.add(observation("120"))
        with pytest.raises(AssistantError, match="evidence_lineage_mismatch"):
            store.add({**observation("120"), "entity": "Other Fictional Entity"}, supersedes=first["id"])
        store.add(observation("120"), supersedes=first["id"])
        with pytest.raises(AssistantError, match="evidence_revision_already_exists"):
            store.add(observation("130"), supersedes=first["id"])


def test_periods_and_units_are_not_silently_collapsed(tmp_path):
    with EvidenceStore(tmp_path / "evidence.db") as store:
        annual = store.add(observation())
        store.decide(annual["id"], annual["hash"], status="approved")
        quarter_data = {**observation("25"), "period_start": "2025-10-01T00:00:00Z", "period_kind": "quarter"}
        with pytest.raises(AssistantError, match="evidence_lineage_mismatch"):
            store.add(quarter_data, supersedes=annual["id"])
        quarter = store.add(quarter_data)
        store.decide(quarter["id"], quarter["hash"], status="approved")
        with pytest.raises(AssistantError, match="evidence_scope_ambiguous"):
            store.latest_approved("Fictional Example", "revenue")
        assert (
            store.latest_approved("Fictional Example", "revenue", period_kind="quarter")["observation"][
                "value"
            ]
            == "25"
        )
