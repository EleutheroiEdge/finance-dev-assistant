"""CI runs each pull request commit once, and its tests as parallel groups of whole files."""

import ast
import io
from pathlib import Path
import subprocess
import sys
import tomllib
import urllib.error

import pytest
import yaml

from scripts import ci_install, ci_test

ROOT = Path(__file__).resolve().parent.parent
MARK = "@pytest.mark." + ci_test.ALONE  # Built here so this file is not itself taken for one with such tests.


def _suite(tmp_path, bodies: dict[str, str]) -> list[Path]:
    for name, body in bodies.items():
        file = tmp_path / "tests" / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(body, encoding="utf-8")
    return ci_test.discover(tmp_path)


def _passing(name: str = "test_fine") -> str:
    return f"def {name}():\n    assert True\n"


def test_every_file_lands_in_exactly_one_group_and_the_deal_repeats(tmp_path):
    files = _suite(tmp_path, {f"test_{number:02d}.py": "#" * (100 * (number % 7 + 1)) for number in range(23)})
    groups = ci_test.deal(files, 4)
    assert len(groups) == 4 and sorted(file for group in groups for file in group) == files
    assert groups == ci_test.deal(list(reversed(files)), 4)  # Order in does not change the deal.
    weights = [sum(file.stat().st_size for file in group) for group in groups]
    assert max(weights) - min(weights) <= 700  # Within one largest file of each other.


def test_fewer_files_than_groups_leaves_no_empty_group(tmp_path):
    groups = ci_test.deal(_suite(tmp_path, {"test_a.py": "#" * 10, "test_b.py": "#" * 20}), 4)
    assert [len(group) for group in groups] == [1, 1]


LAYOUT = {"test_top.py": _passing("test_top"), "plain_test.py": _passing("test_suffix"),
          "integration/test_nested.py": _passing("test_nested"), "integration/deep/more_test.py": _passing("test_deep"),
          "helpers.py": "VALUE = 1\n", "conftest.py": "", ".hidden/test_hidden.py": _passing("test_hidden"),
          "build/test_built.py": _passing("test_built"), "__pycache__/test_cached.py": _passing("test_cached")}


def test_discovery_finds_exactly_what_pytest_collects_at_any_depth(tmp_path):
    """Nested directories and the *_test.py pattern, checked against pytest's own collection."""
    found = {file.relative_to(tmp_path).as_posix() for file in _suite(tmp_path, LAYOUT)}
    assert found == {"tests/test_top.py", "tests/plain_test.py", "tests/integration/test_nested.py",
                     "tests/integration/deep/more_test.py"}
    collected = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "tests"],
                               cwd=tmp_path, capture_output=True, text=True, check=True).stdout
    assert {line.split("::")[0] for line in collected.splitlines() if "::" in line} == found


def test_the_whole_command_runs_nested_and_suffix_named_tests(tmp_path, capsys):
    _suite(tmp_path, LAYOUT)
    assert ci_test.main(["--groups", "2"], root=tmp_path) == 0
    shown = capsys.readouterr().out
    assert "2 groups in" in shown and "0 failed" in shown
    assert sum(int(line.split(": ")[-1].split(" passed")[0]) for line in shown.splitlines() if " passed" in line) == 4


def test_the_real_suite_is_dealt_whole():
    files = ci_test.discover()
    assert len(files) >= 80 and all(file.is_file() for file in files)
    groups = ci_test.deal(files, ci_test.default_groups())
    assert sorted(file for group in groups for file in group) == files
    assert 1 <= ci_test.default_groups() <= ci_test.MAX_GROUPS


@pytest.mark.parametrize("setting", ['python_files = ["check_*.py"]', 'norecursedirs = ["slow"]',
                                     'testpaths = ["tests", "more"]'])
def test_a_pytest_setting_that_changes_collection_stops_the_runner(tmp_path, setting):
    _suite(tmp_path, {"test_top.py": _passing()})
    (tmp_path / "pyproject.toml").write_text(f"[tool.pytest.ini_options]\n{setting}\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="pytest's default rules"):
        ci_test.main(["--groups", "1"], root=tmp_path)


def test_this_projects_pytest_settings_match_the_runner():
    ci_test.check_settings()
    settings = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pytest"]["ini_options"]
    assert settings["testpaths"] == ["tests"]
    assert any(marker.startswith(ci_test.ALONE + ":") for marker in settings["markers"])


def test_a_failing_group_fails_the_run_and_its_output_is_shown(tmp_path, capsys):
    files = _suite(tmp_path, {"test_fine.py": _passing(),
                              "test_broken.py": "def test_broken_synthetic():\n    assert 1 == 2\n"})
    assert ci_test.run(ci_test.deal(files, 2), [], root=tmp_path) == 1
    shown = capsys.readouterr().out
    assert "2 groups" in shown and "1 failed" in shown
    assert "FAILED (exit 1)" in shown and "test_broken_synthetic" in shown
    assert "1 passed" in shown  # The other group still ran to the end and reported.


def test_a_group_with_nothing_to_run_fails_rather_than_passing_quietly(tmp_path, capsys):
    files = _suite(tmp_path, {"test_empty.py": "VALUE = 1\n", "test_fine.py": _passing()})
    assert ci_test.run(ci_test.deal(files, 2), [], root=tmp_path) == 1
    assert "FAILED (exit 5)" in capsys.readouterr().out


def test_every_group_passing_is_success_and_groups_do_not_share_a_temporary_directory(tmp_path, capsys):
    body = ("def test_writes(tmp_path_factory):\n"
            "    base = tmp_path_factory.getbasetemp()\n"
            "    (base / 'marker.txt').write_text(__file__, encoding='utf-8')\n"
            "    assert (base / 'marker.txt').read_text(encoding='utf-8') == __file__\n")
    files = _suite(tmp_path, {"test_one.py": body, "test_two.py": body, "test_three.py": body})
    assert ci_test.run(ci_test.deal(files, 3), [], root=tmp_path) == 0
    shown = capsys.readouterr().out
    assert "3 groups" in shown and "0 failed" in shown and shown.count("1 passed") == 3


def test_time_limited_tests_run_once_by_themselves_after_the_groups(tmp_path, capsys):
    """Each such test checks that no group's working directory is still being written while it runs."""
    timed = ("import pytest\n\n\n"
             f"{MARK}\n"
             "def test_timed(tmp_path_factory):\n"
             "    import time\n"
             "    scratch = tmp_path_factory.getbasetemp().parent.parent\n"
             "    before = sorted((path.name, path.stat().st_size) for path in scratch.glob('g*/out.txt'))\n"
             "    time.sleep(1)\n"
             "    assert before and before == sorted((path.name, path.stat().st_size) for path in scratch.glob('g*/out.txt'))\n"
             "\n\ndef test_ordinary():\n    pass\n")
    files = _suite(tmp_path, {"test_timed.py": timed, "test_other.py": _passing()})
    assert ci_test.run(ci_test.deal(files, 2), [], root=tmp_path) == 0
    lines = capsys.readouterr().out.splitlines()
    alone = [line for line in lines if line.startswith("time-limited tests, alone")]
    assert len(alone) == 1 and "1 passed, 1 deselected" in alone[0]
    assert lines.index(alone[0]) > max(index for index, line in enumerate(lines) if line.startswith("group "))
    assert any("1 passed, 1 deselected" in line for line in lines if line.startswith("group "))
    assert "2 groups and the time-limited tests in" in lines[-1] and "0 failed" in lines[-1]


def test_a_failing_time_limited_test_fails_the_run(tmp_path, capsys):
    timed = f"import pytest\n\n\n{MARK}\ndef test_too_slow_synthetic():\n    assert False\n\n\ndef test_ordinary():\n    pass\n"
    files = _suite(tmp_path, {"test_timed.py": timed})
    assert ci_test.run(ci_test.deal(files, 1), [], root=tmp_path) == 1
    shown = capsys.readouterr().out
    assert "time-limited tests, alone: 1 files" in shown and "test_too_slow_synthetic" in shown


def test_every_test_that_times_itself_is_marked_to_run_alone():
    """A test that compares elapsed wall-clock time with a limit fails on a busy runner unless it runs alone."""
    clock = "perf_" + "counter"  # Built here so this test is not one of those it looks for.
    timed, marked = set(), set()
    for file in ci_test.discover():
        text = file.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                name = f"{file.name}::{node.name}"
                if clock in ast.get_source_segment(text, node):
                    timed.add(name)
                if any(ast.unparse(decorator) == "pytest.mark." + ci_test.ALONE for decorator in node.decorator_list):
                    marked.add(name)
    assert timed == marked == {
        "test_code_text.py::test_hostile_code_is_screened_in_bounded_time",
        "test_credential_references.py::test_a_reply_made_of_quotes_is_screened_in_bounded_time",
        "test_figure_matrix.py::test_dense_numeric_text_is_screened_in_bounded_time",
        "test_python_screening.py::test_long_zero_runs_screen_in_linear_time",
        "test_python_screening.py::test_many_numeric_credential_values_screen_in_linear_time",
        "test_python_screening.py::test_many_literals_screen_in_linear_time",
        "test_secret_scan_performance.py::test_policy_sized_hyphenated_tokens_scan_in_bounded_time",
    }


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
