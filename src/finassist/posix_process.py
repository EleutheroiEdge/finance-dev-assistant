"""Observe child exit without freeing its PID before process-group cleanup."""

import errno
import os
import select
import subprocess

from .errors import AssistantError
from .platform_support import find_tool, clean_environment


def zombie_group_only(pid):
    """Darwin can refuse signals to zombies. Never ignore a live group member."""
    try:
        result = subprocess.run(
            [find_tool("ps"), "-o", "stat=", "-g", str(pid)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=2,
            check=False,
            env=clean_environment(),
            shell=False,
        )
        return result.returncode in {0, 1} and all(row.startswith("Z") for row in result.stdout.split())
    except (OSError, subprocess.SubprocessError, AssistantError):
        return False


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
