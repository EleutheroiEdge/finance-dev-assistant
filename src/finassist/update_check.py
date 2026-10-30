"""One fixed public GET, private daily reservations, and a bounded opt-in notifier."""

from datetime import datetime, timezone
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
import uuid

import httpx

from . import installed_version
from .errors import AssistantError
from .platform_support import clean_environment
from .security import regular_path
from .update_settings import checks_disabled, update_setting, user_directory

PYPI_URL = "https://pypi.org/pypi/finledgerpoli/json"
MAX_BYTES = 1_000_000
INTERVAL = 86_400
STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def _cache() -> Path:
    return user_directory("cache") / "update-check.sqlite"


def _valid_version(value) -> bool:
    return isinstance(value, str) and len(value) <= 80 and STABLE.fullmatch(value) is not None


def _read(connection) -> dict | None:
    row = connection.execute("SELECT value FROM update_check WHERE id=1").fetchone()
    if row is None:
        return None
    data = json.loads(row[0])
    if (not isinstance(data, dict) or set(data) != {"claim", "started", "state", "latest"}
            or not isinstance(data["claim"], str) or not re.fullmatch(r"[a-f0-9]{32}", data["claim"])
            or type(data["started"]) not in {int, float} or not 0 <= data["started"] < 100_000_000_000
            or data["state"] not in {"pending", "dispatched", "complete", "failed"}
            or (data["latest"] is not None and not _valid_version(data["latest"]))
            or (data["state"] == "complete") != (data["latest"] is not None)):
        raise ValueError("invalid update cache")
    return data


def _write(connection, data):
    connection.execute("INSERT OR REPLACE INTO update_check(id,value) VALUES(1,?)", (json.dumps(data),))


def cached_check() -> dict | None:
    try:
        path = regular_path(_cache())
        if not path.is_file() or path.stat().st_size > 1_000_000:
            return None
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.05)) as connection:
            return _read(connection)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, AssistantError):
        return None


def check_report(record=None, *, reason="not-requested") -> dict:
    installed = installed_version()
    latest = record.get("latest") if record else None
    checked = bool(record and record["state"] == "complete" and _valid_version(installed))
    newer = checked and tuple(map(int, latest.split("."))) > tuple(map(int, installed.split(".")))
    return {"status": ("update-available" if newer else "up-to-date") if checked else "not checked",
            "installed_version": installed, "latest_version": latest if checked else None,
            "checked_at": datetime.fromtimestamp(record["started"], timezone.utc).isoformat() if record else None,
            "stale": bool(record and time.time() - record["started"] >= INTERVAL),
            "reason": None if checked else (record["state"] if record else reason)}


def reserve_check(*, force=False, now=None) -> str | None:
    """An atomic pending record counts toward the daily limit, even if the worker dies."""
    path = regular_path(_cache())
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.exists() and (not path.is_file() or path.stat().st_size > 1_000_000):
        raise AssistantError("update_cache_unavailable")
    now = time.time() if now is None else now
    with closing(sqlite3.connect(path, timeout=0.05)) as connection, connection:
        path.chmod(0o600)
        connection.execute("CREATE TABLE IF NOT EXISTS update_check(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL)")
        connection.execute("BEGIN IMMEDIATE")
        previous = _read(connection)
        if not force and previous and now - previous["started"] < INTERVAL:
            return None
        claim = uuid.uuid4().hex
        _write(connection, {"claim": claim, "started": now, "state": "pending", "latest": None})
        return claim


def fetch_latest(*, transport=None) -> str:
    deadline = time.monotonic() + 4
    # No proxies, netrc, cookies, user identifiers, retries or redirects.
    with httpx.Client(timeout=2.0, follow_redirects=False, trust_env=False,
                      transport=transport or httpx.HTTPTransport(retries=0, trust_env=False)) as client:
        with client.stream("GET", PYPI_URL, headers={"Accept": "application/json", "User-Agent": "finledgerpoli-update-check"}) as response:
            if response.status_code != 200:
                raise ValueError("update check unavailable")
            data = bytearray()
            for chunk in response.iter_bytes(chunk_size=65_536):
                if time.monotonic() > deadline or len(data) + len(chunk) > MAX_BYTES:
                    raise ValueError("update check limit")
                data.extend(chunk)
    document = json.loads(data)
    latest = document["info"]["version"]
    if not _valid_version(latest):
        raise ValueError("invalid stable version")
    return latest


def perform_check(claim: str, *, transport=None) -> None:
    path = regular_path(_cache())
    if checks_disabled():
        return
    with closing(sqlite3.connect(path, timeout=0.05)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        record = _read(connection)
        if not record or record["claim"] != claim or record["state"] != "pending":
            return
        record["state"] = "dispatched"
        _write(connection, record)
    # The durable dispatched transition precedes the sole request. A repeated
    # worker invocation cannot send it again. Failed/uncertain checks are cached.
    try:
        latest, state = fetch_latest(transport=transport), "complete"
    except (httpx.HTTPError, OSError, ValueError, TypeError, KeyError, RecursionError):
        latest, state = None, "failed"
    with closing(sqlite3.connect(path, timeout=0.05)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        current = _read(connection)
        if current and current["claim"] == claim and current["state"] == "dispatched":
            _write(connection, {**current, "state": state, "latest": latest})


def check_once(*, network_allowed: bool, transport=None) -> dict:
    if not network_allowed or checks_disabled():
        return check_report(reason="network-disabled" if not network_allowed else "disabled-by-environment")
    try:
        claim = reserve_check(force=True)
        perform_check(claim, transport=transport)
        return check_report(cached_check())
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, AssistantError):
        return check_report(reason="cache-unavailable")


def _claim_notice() -> bool:
    day = datetime.now(timezone.utc).date().isoformat()
    with closing(sqlite3.connect(regular_path(_cache()), timeout=0.05)) as connection, connection:
        connection.execute("CREATE TABLE IF NOT EXISTS update_notices(day TEXT PRIMARY KEY)")
        connection.execute("BEGIN IMMEDIATE")
        return connection.execute("INSERT OR IGNORE INTO update_notices(day) VALUES(?)", (day,)).rowcount == 1


def maybe_notify(*, network_allowed: bool, command: str, stderr=None) -> None:
    """Show only cached notices; a detached one-shot worker never delays a command for HTTP."""
    stderr = sys.stderr if stderr is None else stderr
    # Skip state-sensitive/read-only command contracts, including doctor --fix,
    # CI gates and all workflows. No notifier activity accompanies those paths.
    if (command not in {"doctor", "demo", "init"} or not network_allowed
            or checks_disabled() or any(name in os.environ for name in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD"))
            or not all(stream.isatty() for stream in (sys.stdin, sys.stdout, stderr))):
        return
    try:
        if update_setting() != "notify":
            return
        cached = check_report(cached_check())
        if cached["status"] == "update-available" and _claim_notice():
            from .updater import installation

            info = installation()
            command_text = info["upgrade_command"] or "Run finassist guide upgrading."
            print(f"finledgerpoli {cached['latest_version']} is available. {command_text}", file=stderr)
        claim = reserve_check()
        if claim is None:
            return
        env = clean_environment()
        names = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CACHE_HOME")
        env.update({name: os.environ[name] for name in names if name in os.environ})
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {"start_new_session": True}
        subprocess.Popen([sys.executable, "-I", "-m", "finassist.update_check", claim],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True, env=env, **options)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, AssistantError):
        # A notice is advisory. Cache/launch failures never change command outcome
        # or release the reservation for another automatic attempt that day.
        return


if __name__ == "__main__":
    if len(sys.argv) == 2 and re.fullmatch(r"[a-f0-9]{32}", sys.argv[1]):
        try:
            if update_setting() == "notify":
                perform_check(sys.argv[1])
        except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, AssistantError):
            pass
