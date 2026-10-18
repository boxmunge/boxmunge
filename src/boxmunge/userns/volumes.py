# SPDX-License-Identifier: Apache-2.0
"""Volumes between the two daemon roots: recreated verbatim, data moved by rename.

A volume is first created on the target daemon with its driver and every
label exactly as recorded (Docker silently returns an existing volume of
the same name, so the labels are verified), then Docker's fresh empty
`_data` is replaced by the old one with one same-filesystem rename(2),
which replaces an empty directory atomically: at no instant is `_data`
missing on the target (a daemon drops a volume whose `_data` is missing
when it starts). A move is idempotent: after a crash between the rename
and its journal entry, the data is found already in place.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from boxmunge.data_helper import volume_labels
from boxmunge.docker_run import run as _run
from boxmunge.fileutil import fsync_dir
from boxmunge.userns.inventory import VolumeEntry


class VolumeError(Exception):
    """A volume could not be recreated or moved as recorded."""


def data_dir(root: Path, name: str) -> Path:
    return root / "volumes" / name / "_data"


def recreate(entry: VolumeEntry) -> None:
    """Create `entry` on the running daemon, or find it already there with
    exactly its labels. Idempotent."""
    if entry.driver != "local" or entry.options:
        raise VolumeError(f"volume {entry.name}: only plain local volumes are carried")
    labels = [arg for k, v in sorted(entry.labels.items()) for arg in ("--label", f"{k}={v}")]
    _run(["docker", "volume", "create", "--driver", "local", *labels, entry.name], capture=True)
    got = volume_labels(entry.name)
    if got != entry.labels:
        raise VolumeError(f"volume {entry.name} has labels {got!r}, not the recorded "
                          f"{entry.labels!r} (Docker returns an existing volume of that name "
                          f"unchanged); remove the stray volume and resume")


def _real_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except FileNotFoundError:
        return False


def move(src_root: Path, dst_root: Path, name: str) -> None:
    src, dst = data_dir(src_root, name), data_dir(dst_root, name)
    if not os.path.lexists(src):
        if _real_dir(dst):
            return  # moved before a crash
        raise VolumeError(f"volume {name}: neither {src} nor {dst} holds its data")
    if not _real_dir(src):
        raise VolumeError(f"{src} is not a directory; refusing to move it")
    if os.path.lexists(dst):
        if not _real_dir(dst) or any(os.scandir(dst)):
            raise VolumeError(f"{dst} is not the empty directory Docker just created; "
                              f"refusing to replace it")
    elif not _real_dir(dst.parent):
        raise VolumeError(f"{dst.parent} does not exist: create volume {name} on the "
                          f"target daemon first")
    os.rename(src, dst)  # replaces the empty dst in one step
    fsync_dir(dst.parent)
    fsync_dir(src.parent)
