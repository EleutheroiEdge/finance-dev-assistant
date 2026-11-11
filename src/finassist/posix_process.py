"""Observe child exit without freeing its PID before process-group cleanup."""

import errno
import os
import select
import subprocess
import sys
import time

from .errors import AssistantError
from .platform_support import find_tool, clean_environment


def zombie_group_only(pid):
    """Darwin can refuse signals to zombies. Never ignore a live group member."""
    try:
        result = subprocess.run(
            [find_tool("ps"), "-x", "-o", "stat=", "-g", str(pid)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=2,
            check=False,
            env=clean_environment(),
            shell=False,
        )
        rows = result.stdout.split()
        return result.returncode == 0 and bool(rows) and all(row.startswith("Z") for row in rows)
    except (OSError, subprocess.SubprocessError, AssistantError):
        return False


SIGNAL_SETTLE_SECONDS = 1.0  # How long a refused group signal is retried while the leader finishes exiting.


def signal_group(pid: int, sig: int, observer, *, platform: str = sys.platform) -> None:
    """Signal a child's process group. A group that is gone, or only a zombie on macOS, needs none.

    macOS refuses to signal a group whose only member is a zombie. A leader that is exiting can
    be refused a moment before its exit is reported or `ps` shows it as a zombie, so the signal
    is tried again for a short time. The refusal is accepted only once the exit has been
    observed and every member is a zombie: a live member is never left unsignalled silently.
    """
    deadline = time.monotonic() + SIGNAL_SETTLE_SECONDS
    while True:
        try:
            os.killpg(pid, sig)
            return
        except ProcessLookupError:
            return
        except PermissionError:
            if platform != "darwin" or observer is None:
                raise
            if observer.poll() and zombie_group_only(pid):
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def non_reaping_wait_available() -> bool:
    """Whether this platform can observe a child's exit without reaping it."""
    return (hasattr(os, "waitid") and hasattr(os, "WNOWAIT")) or hasattr(select, "kqueue")


class ExitObserver:
    def __init__(self, pid):
        self.pid = pid
        self.exited = False
        self.queue = None
        if hasattr(os, "waitid") and hasattr(os, "WNOWAIT"):
            self.kind = "waitid"
        elif hasattr(select, "kqueue"):
            self.kind = "kqueue"
            self.queue = select.kqueue()
            event = select.kevent(
                pid,
                filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                fflags=select.KQ_NOTE_EXIT,
            )
            try:
                self.queue.control([event], 0, 0)
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    self.exited = True
                else:
                    self.close()
                    raise
        else:
            raise AssistantError("non_reaping_wait_required")

    def poll(self):
        if not self.exited:
            if self.kind == "waitid":
                self.exited = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
            else:
                self.exited = bool(self.queue.control([], 1, 0))
        return self.exited

    def close(self):
        if self.queue is not None:
            self.queue.close()
