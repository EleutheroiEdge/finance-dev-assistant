"""Bounded native Windows process supervision for explicitly trusted commands.

Job objects provide cleanup after attachment, not an untrusted-code sandbox.
The container daemon is independently cleaned/inspected by the recipe runner.
"""

import ctypes
from ctypes import wintypes
import queue
import subprocess
import threading
import time

from .errors import AssistantError


class Job:
    def __init__(self):
        class Basic(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_longlong),
                ("job_time", ctypes.c_longlong),
                ("flags", wintypes.DWORD),
                ("min_working", ctypes.c_size_t),
                ("max_working", ctypes.c_size_t),
                ("active", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD),
            ]

        class Counters(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_ulonglong)
                for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")
            ]

        class Limits(ctypes.Structure):
            _fields_ = [
                ("basic", Basic),
                ("io", Counters),
                ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t),
                ("peak_process", ctypes.c_size_t),
                ("peak_job", ctypes.c_size_t),
            ]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self.api.SetInformationJobObject.restype = wintypes.BOOL
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.AssignProcessToJobObject.restype = wintypes.BOOL
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise AssistantError("windows_job_unavailable")
        limits = Limits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise AssistantError("windows_job_unavailable")

    def attach(self, process):
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise AssistantError("windows_job_attachment_failed")

    def close(self):
        if self.handle:
            handle = self.handle
            self.handle = None
            if not self.api.CloseHandle(handle):
                raise AssistantError("windows_job_cleanup_failed")


def run_windows(argv, *, cwd, env, timeout, max_bytes):
    started = time.monotonic()
    job = Job()
    process = None
    reader = None
    stopped = threading.Event()
    blocks = queue.Queue(maxsize=8)
    output = bytearray()
    timed_out = overflow = False

    def enqueue(value):
        while not stopped.is_set():
            try:
                blocks.put(value, timeout=0.02)
                return
            except queue.Full:
                pass

    def consume():
        try:
            while not stopped.is_set():
                block = process.stdout.read1(65536)
                if not block:
                    break
                enqueue(block)
        finally:
            enqueue(None)

    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        job.attach(process)
        reader = threading.Thread(target=consume, daemon=True)
        reader.start()
        drained = False
        while True:
            try:
                block = blocks.get(timeout=0.02)
                if block is None:
                    drained = True
                else:
                    room = max_bytes - len(output)
                    output.extend(block[:room])
                    overflow = len(block) > room
            except queue.Empty:
                pass
            if process.poll() is not None:
                # Kill attached descendants even if they inherited the output
                # pipe. The reader can then drain remaining bytes to EOF.
                job.close()
            if overflow or (drained and process.poll() is not None):
                break
            if time.monotonic() - started > timeout:
                timed_out = True
                break
    finally:
        job.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            stopped.set()
            if reader is not None:
                reader.join(timeout=5)
            process.stdout.close()
    return {
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "output_limit_exceeded": overflow,
        "passed": process.returncode == 0 and not timed_out and not overflow,
        "output": output.decode("utf-8", errors="replace"),
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
