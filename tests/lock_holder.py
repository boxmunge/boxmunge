"""Hold a real boxmunge flock from another process, for concurrency tests.

The project lock is an advisory ``flock`` on ``state/<project>.lock``. These
helpers take that same lock from a separate process, exactly as a concurrent
deploy, scan, or health tick would, so tests exercise the real lock rather
than a mock of it.
"""
from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from boxmunge.fileutil import LockError, project_lock
from boxmunge.paths import BoxPaths

_HOLDER = r"""
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o664)
fcntl.flock(fd, fcntl.LOCK_EX)
print("held", flush=True)
sys.stdin.read()
"""


@contextmanager
def hold_lock(lock_path: Path) -> Iterator[None]:
    """Hold an exclusive flock on ``lock_path`` in a child process."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, str(lock_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "held"
        yield
    finally:
        assert proc.stdin is not None
        proc.stdin.close()
        proc.wait(timeout=10)


@contextmanager
def hold_project_lock(name: str, paths: BoxPaths) -> Iterator[None]:
    """Hold ``name``'s project lock in a child process."""
    with hold_lock(paths.project_lock_file(name)):
        yield


def project_lock_is_held(name: str, paths: BoxPaths) -> bool:
    """True if some open file description currently holds the project lock.

    Opens a fresh descriptor, so it also reports a lock held by this very
    process (flock locks belong to the open file description, not the
    process).
    """
    try:
        with project_lock(name, paths):
            return False
    except LockError:
        return True
