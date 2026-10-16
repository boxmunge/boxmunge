# SPDX-License-Identifier: Apache-2.0
"""Process-safe daily rotation of the operational log, and finding its files.

Root processes (timers, the upgrade shim) and deploy processes (the shell,
long-lived MCP sessions) all append to logs/boxmunge.log. When each process
owned a TimedRotatingFileHandler they rotated independently: one renamed the
file while the others kept appending to the renamed archive, so new events
vanished from every query of the active file.

Here every write and every rotation happens under one flock on the logs
directory. The active file holds one UTC day, the day of its first entry: a
write stamped with a later day first renames it to ``boxmunge.log.<that day>``
(the name TimedRotatingFileHandler used, so its archives keep counting).
The day comes from the entries rather than the file's mtime, which is the
time of the write and can fall after midnight for an entry stamped before it.
A writer whose open file was renamed away notices the inode change and
reopens before writing (WatchedFileHandler semantics), still under the lock,
so no line can land in an archive after it was rotated.
"""

from __future__ import annotations

import fcntl
import grp
import json
import logging
import logging.handlers
import os
import re
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ARCHIVE_DAYS = 90


def archive_path(active: Path, day: date) -> Path:
    return active.with_name(f"{active.name}.{day.isoformat()}")


def _archives(active: Path) -> list[tuple[date, Path]]:
    """Archives of ``active``, oldest first."""
    pattern = re.compile(rf"{re.escape(active.name)}\.(\d{{4}}-\d{{2}}-\d{{2}})")
    found = []
    for p in active.parent.iterdir():
        m = pattern.fullmatch(p.name)
        if m:
            found.append((date.fromisoformat(m.group(1)), p))
    return sorted(found)


def log_files(active: Path, since: datetime | None = None) -> list[Path]:
    """The log files that can hold entries at or after ``since``, oldest first.

    Without ``since``, every archive and the active file. An archive named for
    day D holds entries from D; archives written by the old per-process
    handler were named by local date, so one extra day is read to cover a box
    not running in UTC. Callers still filter entries by timestamp.
    """
    if not active.parent.exists():
        return []
    files = [
        p for day, p in _archives(active)
        if since is None or day >= since.date() - timedelta(days=1)
    ]
    if active.exists():
        files.append(active)
    return files


@contextmanager
def _logs_dir_locked(directory: Path) -> Iterator[None]:
    # Locking the directory rather than a lock file: every writer can already
    # open it, so there is no third file whose ownership root and deploy must
    # agree on.
    fd = os.open(directory, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _first_entry_day(active: Path) -> date | None:
    """UTC day of the file's first entry, or None while it is empty."""
    with open(active, "rb") as f:
        line = f.readline()
    if not line.strip():
        return None
    try:
        return date.fromisoformat(json.loads(line)["ts"][:10])
    except (ValueError, KeyError, TypeError) as e:
        raise ValueError(
            f"{active}: the first line is not a boxmunge log entry ({e}), so "
            "its day is unknown and it cannot be rotated. Move the file aside; "
            "logging resumes in a fresh file."
        ) from e


def _archive(active: Path, day: date, keep: int) -> None:
    """Move the active file to its day's archive and prune old archives.

    Caller holds the logs directory lock.
    """
    target = archive_path(active, day)
    if target.exists():
        # Only an old-version process, still running across an upgrade, can
        # have archived this day already. Merge rather than overwrite it.
        with open(active, "rb") as src, open(target, "ab") as dst:
            shutil.copyfileobj(src, dst)
        os.unlink(active)
    else:
        os.rename(active, target)
    for _, old in _archives(active)[:-keep]:
        old.unlink()


class SharedLogFileHandler(logging.handlers.WatchedFileHandler):
    """Append-only log handler, safe across processes and users.

    The file is shared between root and the deploy group: each new file is
    chgrp'd to deploy and chmod'd 0o664 so writers in either context can
    append, whichever created it.
    """

    def __init__(self, path: Path, keep: int = ARCHIVE_DAYS) -> None:
        self.keep = keep
        super().__init__(path, encoding="utf-8")

    def _open(self):  # type: ignore[override]
        old_umask = os.umask(0o002)
        try:
            stream = super()._open()
        finally:
            os.umask(old_umask)
        # Best-effort: a caller that is neither the owner nor root cannot
        # change these, and the file is already open and writable for it.
        try:
            os.chown(self.baseFilename, -1, grp.getgrnam("deploy").gr_gid)
        except (KeyError, OSError):
            pass
        try:
            os.chmod(self.baseFilename, 0o664)
        except OSError:
            pass
        return stream

    def _rotate_if_due(self, active: Path, record_day: date) -> None:
        # Read on every write, not cached per inode: an unlinked file's inode
        # can be reused by the next active file. Writes are infrequent.
        try:
            day = _first_entry_day(active)
        except FileNotFoundError:
            return
        if day is not None and day < record_day:
            _archive(active, day, self.keep)

    def emit(self, record: logging.LogRecord) -> None:
        active = Path(self.baseFilename)
        record_day = datetime.fromtimestamp(record.created, timezone.utc).date()
        try:
            with _logs_dir_locked(active.parent):
                self._rotate_if_due(active, record_day)
                super().emit(record)  # reopens first if the inode changed
        except Exception:
            self.handleError(record)
