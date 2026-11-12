"""The two commands as a user runs them: `state status` writes nothing, `doctor --format text` keeps the exits."""

import json
import os
from pathlib import Path
import subprocess
import sys

from conftest import command

ROOT = Path(__file__).parents[1]


def _run(cwd: Path, *arguments: str, home: Path, extra: dict | None = None) -> subprocess.CompletedProcess:
    environment = {**os.environ, "FINASSIST_NO_UPDATE_CHECK": "1", "HOME": str(home), "USERPROFILE": str(home),
                   "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"),
                   "APPDATA": str(home / "appdata"), "LOCALAPPDATA": str(home / "localappdata"),
                   "PYTHONPATH": str(ROOT / "src"), **(extra or {})}
    return subprocess.run([sys.executable, "-m", "finassist", *arguments], cwd=cwd, env=environment,
                          capture_output=True, text=True, check=False)


def _listing(root: Path) -> list[tuple[str, int]]:
    return sorted((str(path.relative_to(root)), path.stat().st_size) for path in root.rglob("*"))


def test_state_status_reports_and_writes_nothing_anywhere(tmp_path):
    work, home = tmp_path / "work", tmp_path / "home"
    work.mkdir()
    home.mkdir()
    state = work / ".finassist"
    state.mkdir()
    (state / "patches").mkdir()
    (state / "patches" / "one.patch").write_text("diff\n", encoding="utf-8", newline="\n")
    before = _listing(tmp_path)
    done = _run(work, "state", "status", home=home)
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    assert report["mode"] == "state-report" and report["exists"] is True
    assert [store["name"] for store in report["stores"]] == ["patches"]
    assert report["stores"][0]["files"] == 1
    assert set(report["user"]) == {"config", "cache"}
    # No audit ledger, no update cache, nothing in the home folder: the command only reads.
    assert _listing(tmp_path) == before
    missing = _run(work, "state", "status", "--state-dir", str(work / "absent"), "--no-user", home=home)
    assert missing.returncode == 0
    assert json.loads(missing.stdout)["exists"] is False and "user" not in json.loads(missing.stdout)
    assert not (work / "absent").exists() and _listing(tmp_path) == before


def test_doctor_text_format_prints_the_view_and_keeps_the_exit_codes(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("x = 1\n", encoding="utf-8", newline="\n")
    command(tmp_path, "init", "-q", "-b", "main", str(repo))
    command(repo, "config", "user.email", "cli@example.invalid")
    command(repo, "config", "user.name", "cli")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "base")
    base = command(repo, "rev-parse", "HEAD")
    (repo / "src" / "big.py").write_text("y = 2\n" * 40000, encoding="utf-8", newline="\n")
    (repo / "src" / "a.py").write_text("x = 2\n", encoding="utf-8", newline="\n")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "change")
    head = command(repo, "rev-parse", "HEAD")
    for arguments in (["doctor"], ["doctor", "--repo", str(repo), "--base", base, "--head", head]):
        as_json = _run(repo, *arguments, home=home)
        as_text = _run(repo, *arguments, "--format", "text", home=home)
        assert as_text.returncode == as_json.returncode, arguments
        json.loads(as_json.stdout.splitlines()[-1])  # JSON stays the default.
        assert not as_text.stdout.lstrip().startswith("{") and as_text.stdout.startswith("finassist doctor")
    blocked = _run(repo, "doctor", "--repo", str(repo), "--base", base, "--head", head, "--format", "text", home=home)
    assert blocked.returncode == 1 and "file_limit_exceeded" in blocked.stdout and "Remedies:" in blocked.stdout


def test_plain_doctor_text_shows_the_installation_blockers_and_warnings(tmp_path):
    home, no_tools = tmp_path / "home", tmp_path / "no-tools"
    home.mkdir()
    no_tools.mkdir()
    # No Git on the search path: the installation check blocks, and both formats exit 1.
    as_json = _run(tmp_path, "doctor", home=home, extra={"PATH": str(no_tools)})
    as_text = _run(tmp_path, "doctor", "--format", "text", home=home, extra={"PATH": str(no_tools)})
    report = json.loads(as_json.stdout.splitlines()[-1])
    assert as_json.returncode == as_text.returncode == 1, as_text.stderr
    assert [blocker["code"] for blocker in report["environment"]["blockers"]] == ["git_executable_missing"]
    assert "Status: BLOCKED - 1 blocker" in as_text.stdout and "1. git_executable_missing" in as_text.stdout
    assert "Fix: " in as_text.stdout and "healthy" not in as_text.stdout
    assert "fix every blocker listed" in as_text.stdout
    # A proxy setting that provider calls do not use is a warning: it is shown, and the exit status stays 0.
    warned = _run(tmp_path, "doctor", "--format", "text", home=home,
                  extra={"HTTPS_PROXY": "http://proxy.invalid:3128"})
    assert warned.returncode == 0, warned.stdout
    assert "provider_proxy_not_used" in warned.stdout and "variables: " in warned.stdout
    assert "HTTPS_PROXY" in warned.stdout and "Status: healthy" not in warned.stdout
