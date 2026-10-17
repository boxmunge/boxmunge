# SPDX-License-Identifier: Apache-2.0
"""upgrade_lock takes the shim's locks: one upgrade at a time, whatever deploy does.

upgrade.lock is in root-only upgrade-root/, so deploy, who can write
upgrade-state/, cannot replace it to let a second upgrade run. The legacy
upgrade-state/upgrade.lock is taken too, because a shim up to 0.10.1 holds
only that while it upgrades a box to this release. The shim's side is
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


@pytest.mark.parametrize("which", ["upgrade_lock", "legacy_upgrade_lock"])
def test_either_lock_held_means_an_upgrade_is_running(paths: BoxPaths, which: str) -> None:
    fd = _hold(getattr(paths, which))
    try:
        with pytest.raises(UpgradeInProgress):
            _try(paths)
    finally:
        os.close(fd)
    _try(paths)


def test_replacing_the_deploy_writable_lock_does_not_let_a_second_upgrade_run(
        paths: BoxPaths) -> None:
    held = [_hold(paths.upgrade_lock), _hold(paths.legacy_upgrade_lock)]
    try:
        # What deploy can do in upgrade-state/ while an upgrade holds its lock.
        paths.legacy_upgrade_lock.rename(paths.upgrade_state / "moved-away")
        paths.legacy_upgrade_lock.write_text("")
        with pytest.raises(UpgradeInProgress):
            _try(paths)
    finally:
        for fd in held:
            os.close(fd)


def test_the_lock_is_root_only(paths: BoxPaths) -> None:
    _try(paths)
    assert stat.S_IMODE(paths.upgrade_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.upgrade_lock.stat().st_mode) == 0o600
    assert paths.legacy_upgrade_lock.is_file()


def test_a_linked_upgrade_root_is_refused(paths: BoxPaths, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    paths.upgrade_root.parent.mkdir(parents=True, exist_ok=True)
    paths.upgrade_root.symlink_to(elsewhere)
    with pytest.raises(UpgradeStateError, match="upgrade-root is a symlink.*Remove it"):
        _try(paths)
    assert list(elsewhere.iterdir()) == []
