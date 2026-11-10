"""CI runs each pull request commit once, and its tests as parallel groups of whole files."""

import io
from pathlib import Path
import urllib.error

import pytest
import yaml

from scripts import ci_install, ci_test

ROOT = Path(__file__).resolve().parent.parent


def _files(tmp_path, sizes: dict[str, int]) -> list[Path]:
    tests = tmp_path / "tests"
    tests.mkdir()
    for name, size in sizes.items():
        (tests / name).write_text("#" * size, encoding="utf-8")
    return sorted(tests.glob("test_*.py"))


def test_every_file_lands_in_exactly_one_group_and_the_deal_repeats(tmp_path):
    files = _files(tmp_path, {f"test_{number:02d}.py": 100 * (number % 7 + 1) for number in range(23)})
    groups = ci_test.deal(files, 4)
    assert len(groups) == 4 and sorted(file for group in groups for file in group) == files
    assert groups == ci_test.deal(list(reversed(files)), 4)  # Order in does not change the deal.
    weights = [sum(file.stat().st_size for file in group) for group in groups]
    assert max(weights) - min(weights) <= 700  # Within one largest file of each other.


def test_fewer_files_than_groups_leaves_no_empty_group(tmp_path):
    groups = ci_test.deal(_files(tmp_path, {"test_a.py": 10, "test_b.py": 20}), 4)
    assert [len(group) for group in groups] == [1, 1]


def test_the_real_suite_is_dealt_whole(tmp_path):
    files = sorted((ROOT / "tests").glob("test_*.py"))
    groups = ci_test.deal(files, ci_test.default_groups())
    assert sorted(file for group in groups for file in group) == files
    assert 1 <= ci_test.default_groups() <= ci_test.MAX_GROUPS


def _suite(tmp_path, bodies: dict[str, str]) -> list[Path]:
    tests = tmp_path / "tests"
    tests.mkdir()
    for name, body in bodies.items():
        (tests / name).write_text(body, encoding="utf-8")
    return sorted(tests.glob("test_*.py"))


def test_a_failing_group_fails_the_run_and_its_output_is_shown(tmp_path, capsys):
    files = _suite(tmp_path, {"test_fine.py": "def test_fine():\n    assert True\n",
                              "test_broken.py": "def test_broken_synthetic():\n    assert 1 == 2\n"})
    assert ci_test.run(ci_test.deal(files, 2), [], root=tmp_path) == 1
    shown = capsys.readouterr().out
    assert "2 groups" in shown and "1 failed" in shown
    assert "FAILED (exit 1)" in shown and "test_broken_synthetic" in shown
    assert "1 passed" in shown  # The other group still ran to the end and reported.


def test_every_group_passing_is_success_and_groups_do_not_share_a_temporary_directory(tmp_path, capsys):
    body = ("def test_writes(tmp_path_factory):\n"
            "    base = tmp_path_factory.getbasetemp()\n"
            "    (base / 'marker.txt').write_text(__file__, encoding='utf-8')\n"
            "    assert (base / 'marker.txt').read_text(encoding='utf-8') == __file__\n")
    files = _suite(tmp_path, {"test_one.py": body, "test_two.py": body, "test_three.py": body})
    assert ci_test.run(ci_test.deal(files, 3), [], root=tmp_path) == 0
    shown = capsys.readouterr().out
    assert "3 groups" in shown and "0 failed" in shown and shown.count("1 passed") == 3


def test_extra_arguments_reach_every_pytest_process(tmp_path, capsys):
    files = _suite(tmp_path, {"test_one.py": "def test_kept():\n    pass\n\n\ndef test_dropped():\n    assert False\n"})
    assert ci_test.run(ci_test.deal(files, 1), ["-k", "kept"], root=tmp_path) == 0
    assert "1 passed, 1 deselected" in capsys.readouterr().out


def test_the_group_count_is_bounded(capsys):
    for value in ("0", str(ci_test.MAX_GROUPS + 1)):
        with pytest.raises(SystemExit):
            ci_test.main(["--groups", value])
    capsys.readouterr()


def test_the_workflow_checks_a_pull_request_commit_once_and_cancels_what_it_replaces():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    triggers = workflow.get("on", workflow.get(True))  # YAML reads a bare `on` key as true.
    assert triggers == {"push": {"branches": ["main"]}, "pull_request": None}
    assert workflow["concurrency"] == {
        "group": "checks-${{ github.event.pull_request.number || github.sha }}",
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
    }


def test_the_workflow_runs_the_suite_through_the_parallel_runner_on_every_platform():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    commands = [step.get("run") for step in workflow["jobs"]["test"]["steps"]]
    assert "python scripts/ci_test.py" in commands and "python -m pytest -q" not in commands
    assert len(workflow["jobs"]["test"]["strategy"]["matrix"]["include"]) == 9  # One step serves all nine rows.


def _flaky(failures: int, error: Exception, calls: list):
    def urlopen(*args, **kwargs):
        calls.append(args)
        if len(calls) <= failures:
            raise error
        return io.BytesIO(b"synthetic payload")
    return urlopen


def test_a_download_is_tried_again_after_a_network_failure(monkeypatch, capsys):
    calls, pauses = [], []
    monkeypatch.setattr(ci_install.urllib.request, "urlopen",
                        _flaky(2, urllib.error.URLError("synthetic name resolution failure"), calls))
    monkeypatch.setattr(ci_install.time, "sleep", pauses.append)
    assert ci_install.fetch("https://registry.npmjs.org/synthetic") == b"synthetic payload"
    assert len(calls) == 3 and pauses == [5, 10]
    assert "attempt 1 of 3 failed (URLError)" in capsys.readouterr().out


def test_a_download_that_keeps_failing_stops_after_three_attempts(monkeypatch):
    calls = []
    monkeypatch.setattr(ci_install.urllib.request, "urlopen", _flaky(9, TimeoutError("synthetic"), calls))
    monkeypatch.setattr(ci_install.time, "sleep", lambda seconds: None)
    with pytest.raises(TimeoutError):
        ci_install.fetch("https://registry.npmjs.org/synthetic")
    assert len(calls) == 3


def test_an_http_error_status_is_never_retried(monkeypatch):
    calls = []
    error = urllib.error.HTTPError("https://registry.npmjs.org/synthetic", 404, "Not Found", {}, None)
    monkeypatch.setattr(ci_install.urllib.request, "urlopen", _flaky(9, error, calls))
    monkeypatch.setattr(ci_install.time, "sleep", lambda seconds: pytest.fail("An HTTP status must not wait and retry"))
    with pytest.raises(urllib.error.HTTPError):
        ci_install.fetch("https://registry.npmjs.org/synthetic")
    assert len(calls) == 1


def test_a_retried_download_is_still_checked_against_its_pinned_digest(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ci_install.urllib.request, "urlopen",
                        _flaky(1, urllib.error.URLError("synthetic"), calls))
    monkeypatch.setattr(ci_install.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(ci_install, "pnpm_target", lambda: "linux-x64")
    with pytest.raises(RuntimeError, match="integrity mismatch"):
        ci_install.unpack_pnpm(tmp_path)
    assert len(calls) == 2
