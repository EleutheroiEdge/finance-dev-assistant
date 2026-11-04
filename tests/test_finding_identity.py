"""Synthetic identity contract; no model or filesystem transport."""

import pytest

from finassist.errors import AssistantError
from finassist.finding_identity import finding_identifier


def example():
    return {"severity": "high", "file": "src/cash.py", "line": 2,
            "claim": "Deposits subtract from cash",
            "evidence_status": "source-reference-validated-not-reproduced"}


def test_identity_is_stable_for_the_same_request_and_ordered_finding():
    finding = example()
    first = finding_identifier("a" * 64, 0, finding)
    assert first == finding_identifier("a" * 64, 0, dict(reversed(list(finding.items()))))
    assert first == finding_identifier("a" * 64, 0, {**finding, "id": "untrusted-input-id"})
    assert finding == example()  # Deriving an id does not modify the caller.
    assert first.startswith("f-") and len(first) == 66


def test_changed_request_position_or_claim_has_a_distinct_identity():
    baseline = finding_identifier("a" * 64, 0, example())
    variants = [finding_identifier("b" * 64, 0, example()),
                finding_identifier("a" * 64, 1, example()),
                finding_identifier("a" * 64, 0, {**example(), "claim": "Deposits disappear"})]
    assert len(set([baseline, *variants])) == 4


@pytest.mark.parametrize("request_hash,index", [(None, 0), ("a" * 63, 0), ("A" * 64, 0),
                                          ("a" * 64, True), ("a" * 64, -1), ("a" * 64, 50)])
def test_invalid_binding_is_refused(request_hash, index):
    with pytest.raises(AssistantError, match="^finding_identity_invalid$"):
        finding_identifier(request_hash, index, example())


@pytest.mark.parametrize("patch", [{"severity": []}, {"severity": "unknown"}, {"line": True},
                                   {"file": ""}, {"claim": ""}, {"unexpected": "ignored?"},
                                   {"evidence_status": "confirmed"}])
def test_invalid_projection_is_refused_without_echoing_input(patch):
    with pytest.raises(AssistantError, match="^finding_identity_invalid$"):
        finding_identifier("a" * 64, 0, {**example(), **patch})
