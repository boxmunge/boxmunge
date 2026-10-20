# SPDX-License-Identifier: Apache-2.0
"""The barrier before a journal save: what the journal records as done is on disk.

The journal's own write is durable (journal.save_journal), but what it
records is not, until its filesystem is flushed: a daemon's first start
creates its databases (BuildKit's cache.db among them) in the page cache,
and a power cut seconds after the journal said `switched` left a torn
bolt file the next dockerd panicked on. So every save during the migration
and its rollback first flushes each filesystem that holds Docker's root
(the remapped one too), containerd's, the image tarballs and the box.

syncfs(2), not sync(2): sync returns nothing, so a failed write-back would
pass unseen; syncfs reports it (Linux 5.8 and later), and the save stops.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path

from boxmunge.paths import BoxPaths
from boxmunge.userns.daemon_config import DEFAULT_DATA_ROOT, SYSTEM_CONTAINERD_ROOT
from boxmunge.userns.journal import Journal


class NotDurable(Exception):
    """A filesystem could not be flushed: the journal must not move on."""


def syncfs(path: Path) -> None:
    """Flush the filesystem holding ``path``; OSError with its write-back error."""
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        if libc.syncfs(fd) != 0:
            err = ctypes.get_errno()
            raise OSError(err, f"syncfs({path}): {os.strerror(err)}")
    finally:
        os.close(fd)


def _device(path: Path) -> int:
    return os.stat(path).st_dev


def _filesystems(paths: BoxPaths, j: Journal, images_dir: Path) -> list[Path]:
    """One directory per filesystem: the box and Docker's root always; the
    rest where they exist (no containerd store, no tarballs yet)."""
    s = j.offset
    optional = [Path(DEFAULT_DATA_ROOT) / f"{s}.{s}", Path(SYSTEM_CONTAINERD_ROOT),
                Path(j.prior_store.get("store_root") or SYSTEM_CONTAINERD_ROOT), images_dir]
    seen, out = set(), []
    for d in [paths.root, Path(DEFAULT_DATA_ROOT), *(d for d in optional if d.is_dir())]:
        dev = _device(d)
        if dev not in seen:
            seen.add(dev)
            out.append(d)
    return out


def barrier(paths: BoxPaths, j: Journal, images_dir: Path) -> None:
    """Before the journal records `j`: every filesystem it depends on, flushed."""
    for d in _filesystems(paths, j, images_dir):
        try:
            syncfs(d)
        except OSError as e:
            raise NotDurable(
                f"cannot flush the filesystem holding {d} before journalling {j.phase}: {e}. "
                f"The journal stays at the last step that reached the disk; check the disk "
                f"(dmesg), then run the same command again") from e
