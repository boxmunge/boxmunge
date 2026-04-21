"""File utilities — atomic writes and project locking."""

import fcntl
import os
import pwd
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def _chown_deploy(path: str) -> None:
    """Best-effort chown to the deploy user when running as root."""
    if os.getuid() != 0:
        return
    try:
        pw = pwd.getpwnam("deploy")
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except (KeyError, OSError):
        pass


def atomic_write_text(path: Path, content: str, mode: int | None = None) -> None:
    """Write content to path atomically via temp file + rename.

    Creates parent directories if needed. Uses fsync for durability
    and os.rename for atomicity (same-filesystem guarantee).
    If mode is provided, the temp file is chmod'd before rename so
    the final file is never visible with wrong permissions.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.stem}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp_path, mode)
        os.rename(tmp_path, path)
        _chown_deploy(str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


class LockError(Exception):
    """Raised when a project lock cannot be acquired."""


@contextmanager
def project_lock(project_name: str, paths: "BoxPaths") -> Iterator[None]:
    """Acquire an exclusive per-project lock. Non-blocking.

    Raises LockError if another operation holds the lock.
    Lock files are left on disk after release (advisory flock).
    """
    lock_path = paths.project_lock_file(project_name)
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise LockError(
            f"Another operation is in progress for '{project_name}'. "
            f"Try again shortly."
        )
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
