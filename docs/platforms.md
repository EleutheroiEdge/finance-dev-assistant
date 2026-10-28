# Windows, macOS and Linux

Use Python 3.11+ and native Git. Install the Python package in a virtual environment;
the README provides commands for PowerShell and POSIX shells without changing
machine execution policies. Git, GitHub CLI, Docker and Podman are discovered on
PATH, including native executables on Windows. Batch-file tool shims are refused;
subprocesses never use `shell=True`. No tool installation or login occurs implicitly.

## Text, paths and temporary files

Configuration and report text is UTF-8. Reads accept CRLF through universal
newlines; new text files use LF. Git source packets and backups preserve original
bytes, including CRLF, so hashes remain tied to committed blobs. Missing encoding
arguments are checked by Ruff PLW1514. Native pathlib paths and argument arrays
preserve spaces and Unicode without shell quoting or drive-path rewriting.

SQLite uses its native file locking and a bounded busy timeout. Each thread or
operation owns and closes its connection. Readiness holds one transaction across
verified ledger reads. Temporary directories use the standard platform-aware
cleanup, after child processes and file/database handles are closed. Regression
tests exercise read-only temporary files and a Unicode database directory.

## Private state and Git metadata

Private audit/evidence/output files use owner-only modes on POSIX. On Windows,
permissions inherit from directory ACLs; a numeric chmod is not equivalent.
**Use a private user-owned directory and review its access list before storing
private data.** This is also shown by `doctor`. The package does not silently
alter Windows security settings or claim that inherited ACLs are private.

Committed executable and symlink modes come from Git objects on every OS, even
when the worktree cannot represent them. Links and reparse/junction paths are
rejected rather than followed. Native symlink creation tests report a clear skip
when Windows denies that privilege; Git-object rejection tests still run.

Native Windows lacks the POSIX executable bit. A worktree-only mode-changing patch
(or a newly created executable file) is refused with
`executable_mode_change_not_supported`; it is never silently discarded or staged.
Use the project's explicit Git index/mode workflow for those changes. Ordinary
source-byte patches and guarded rollback work without changing the index.

## Recipe execution and Docker Desktop

Local execution requires explicit trusted-code approval. Linux observes child exit
without reaping until process-group cleanup; macOS uses its native process-exit
queue when waitid is unavailable. Windows uses a job object and bounded pipe
reader. These are supervision mechanisms, not untrusted-code security sandboxes.

Docker Desktop on Windows/macOS must use Linux containers and a shared native
source directory. Bind mounts use a literal `--mount` argument with a forward-slash
host path, preserving Windows drive letters and spaces. The container sees only
the exported source at `/workspace`, read-only, plus bounded scratch at `/tmp`.
The host CLI consumes its existing Docker context configuration internally;
credentials/configuration files are not copied into source or the container.
Rootless Podman retains its runtime-directory selector. Images must already be
present at their approved digest; automatic pulls are disabled.

CI runs native tests, lint, demo and clean installed-wheel smoke on Windows/macOS
and three Linux Python versions. Actual container isolation remains a Linux job.
The container smoke prints a clear skip when not on Linux or when the runtime/
daemon is unavailable; a skip never establishes isolation success. The required
Linux job uses `--require-runtime`, so missing isolation capability fails CI.
Unit tests
exercise mount formatting and cleanup without needing a daemon on every OS.

References: [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/),
[Windows job objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[Python OS interfaces](https://docs.python.org/3/library/os.html).
