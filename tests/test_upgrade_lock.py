# SPDX-License-Identifier: Apache-2.0
"""upgrade_lock takes the shim's lock: one upgrade at a time, whatever deploy does.

upgrade.lock is in root-only upgrade-root/, so deploy, who can write
upgrade-state/, cannot replace it to let a second upgrade run. Every shim an
upgrade may start from (0.11.0 on) holds it. The shim's side is
tests/shim/test_upgrade_lock.sh.
"""
from __future__ import annotations

import fcntl
import os
import stat
from pathlib import Path

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.upgrade_state import UpgradeInProgress, UpgradeStateError, upgrade_lock


def _hold(path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def _try(paths: BoxPaths) -> None:
    with upgrade_lock(paths):
        pass


def test_the_lock_held_means_an_upgrade_is_running(paths: BoxPaths) -> None:
    fd = _hold(paths.upgrade_lock)
    try:
        with pytest.raises(UpgradeInProgress):
            _try(paths)
    finally:
        os.close(fd)
    _try(paths)


def test_nothing_deploy_can_write_takes_part(paths: BoxPaths) -> None:
    """A file at the name shims before 0.11.7 also locked, in the
    deploy-writable upgrade-state/, neither stalls an upgrade nor is made."""
    deploys = paths.upgrade_state / "upgrade.lock"
    fd = _hold(deploys)
    try:
        _try(paths)
    finally:
        os.close(fd)
    deploys.unlink()
    _try(paths)
    assert not deploys.exists()


def test_the_lock_is_root_only(paths: BoxPaths) -> None:
    _try(paths)
    assert stat.S_IMODE(paths.upgrade_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.upgrade_lock.stat().st_mode) == 0o600


def test_a_linked_upgrade_root_is_refused(paths: BoxPaths, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    paths.upgrade_root.parent.mkdir(parents=True, exist_ok=True)
    paths.upgrade_root.symlink_to(elsewhere)
    with pytest.raises(UpgradeStateError, match="upgrade-root is a symlink.*Remove it"):
        _try(paths)
    assert list(elsewhere.iterdir()) == []
