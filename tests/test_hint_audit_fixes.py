"""Defects found while writing a hint for every error code (#69): each now has a code, not a crash."""

import json
from pathlib import Path
import subprocess

import pytest

from conftest import command
from finassist import posix_process, runner
from finassist.cli import main
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.evaluation import score
from finassist.scope import build_packet
from finassist.security import canonical, digest
from finassist.workflow_state import _read_document


def _evaluation() -> dict:
    data = {"provider": "fictional", "cases": [{"id": "positive", "expected_defect": True}]}
    return {**data, "evaluation_hash": digest(canonical(data))}


@pytest.mark.parametrize("outcomes", [["positive"], "positive", 7, None])
def test_score_refuses_outcomes_that_are_not_an_object(outcomes):
    result = _evaluation()
    with pytest.raises(AssistantError, match="invalid_adjudication"):
        score(result, {"evaluation_hash": result["evaluation_hash"], "outcomes": outcomes})


def test_score_through_the_cli_reports_a_code_instead_of_a_traceback(tmp_path, capsys):
    result = _evaluation()
    evaluation, labels = tmp_path / "evaluation.json", tmp_path / "labels.json"
    evaluation.write_text(json.dumps(result), encoding="utf-8")
    labels.write_text(json.dumps({"evaluation_hash": result["evaluation_hash"], "outcomes": ["positive"]}),
                      encoding="utf-8")
    assert main(["--audit-dir", str(tmp_path / "audit"), "score", "--evaluation", str(evaluation),
                 "--labels", str(labels), "--output", str(tmp_path / "score.json")]) == 2
    record = json.loads(capsys.readouterr().err)
    assert record["code"] == "invalid_adjudication" and record["hint"]


def test_no_process_starts_where_it_could_not_be_supervised(tmp_path, monkeypatch):
    if runner.os.name == "nt":
        pytest.skip("Windows uses job objects, not the POSIX non-reaping wait.")
    monkeypatch.setattr(posix_process, "non_reaping_wait_available", lambda: False)
    monkeypatch.setattr(runner, "non_reaping_wait_available", lambda: False)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("the recipe must not start"))
    with pytest.raises(AssistantError, match="non_reaping_wait_required"):
        runner.run_bounded(["true"], cwd=tmp_path, env={}, timeout=5)


def test_the_wait_check_matches_the_observer():
    available = posix_process.non_reaping_wait_available()
    assert available == ((hasattr(posix_process.os, "waitid") and hasattr(posix_process.os, "WNOWAIT"))
                         or hasattr(posix_process.select, "kqueue"))


def test_plan_refuses_more_than_2000_changed_files_before_reading_any(repository, monkeypatch):
    repo, base, _head = repository
    for index in range(2001):
        (repo / "src" / f"m{index:04d}.py").write_text(f"VALUE = {index}\n", encoding="utf-8", newline="\n")
    command(repo, "add", "src")
    command(repo, "commit", "-q", "-m", "Synthetic wide change")
    head = command(repo, "rev-parse", "HEAD")
    from finassist import scope

    monkeypatch.setattr(scope, "read_entry", lambda *args, **kwargs: pytest.fail("no file may be read"))
    with pytest.raises(AssistantError, match="packet_file_count_limit"):
        build_packet(repo, base, head, Config())


@pytest.mark.parametrize("content", [b"{not json", b"\xff\xfe\x00", b"[" * 100_000, b"[1, 2]"])
def test_a_damaged_workflow_file_is_reported_as_changed(tmp_path, content):
    path = tmp_path / "run.json"
    path.write_bytes(content)
    with pytest.raises(AssistantError, match="workflow_artifact_missing_or_changed"):
        _read_document(path)


def test_a_valid_workflow_file_still_reads(tmp_path):
    path = tmp_path / "run.json"
    path.write_text('{"workflow_schema": 1}', encoding="utf-8")
    assert _read_document(Path(path)) == {"workflow_schema": 1}
