# SPDX-License-Identifier: Apache-2.0
"""The jobs gate: running jobs hold it shared, an upgrade holds it exclusive."""
from __future__ import annotations

import fcntl
import os
import threading
import time
from pathlib import Path

import pytest

from boxmunge.api import job_gate
from boxmunge.api.job_gate import GateTimeout, job_gate as gate, upgrade_holds_gate
from boxmunge.fileutil import open_shared_lockfile
from boxmunge.paths import BoxPaths


@pytest.fixture
def paths(tmp_path: Path) -> BoxPaths:
    return BoxPaths(root=tmp_path / "box")


def _hold(paths: BoxPaths, mode: int) -> int:
    fd = open_shared_lockfile(paths.jobs_gate)
    fcntl.flock(fd, mode)
    return fd


def _release(fd: int) -> None:
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def test_free_gate_is_not_held(paths: BoxPaths) -> None:
    assert upgrade_holds_gate(paths) is False


def test_exclusive_holder_is_seen_as_upgrade(paths: BoxPaths) -> None:
    fd = _hold(paths, fcntl.LOCK_EX)
    try:
        assert upgrade_holds_gate(paths) is True
    finally:
        _release(fd)
    assert upgrade_holds_gate(paths) is False


def test_job_gate_yields_not_waited_when_free(paths: BoxPaths) -> None:
    with gate(paths) as waited:
        assert waited is False


def test_job_gate_yields_waited_after_exclusive_release(
    paths: BoxPaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(job_gate, "GATE_POLL_SECONDS", 0.05)
    fd = _hold(paths, fcntl.LOCK_EX)
    threading.Timer(0.3, _release, args=(fd,)).start()
    with gate(paths) as waited:
        assert waited is True


def test_job_gate_times_out(paths: BoxPaths, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(job_gate, "GATE_POLL_SECONDS", 0.05)
    monkeypatch.setattr(job_gate, "UPGRADE_GATE_WAIT_SECONDS", 0.2)
    fd = _hold(paths, fcntl.LOCK_EX)
    try:
        start = time.monotonic()
        with pytest.raises(GateTimeout, match="upgrade"):
            with gate(paths):
                pass
        assert time.monotonic() - start < 2
    finally:
        _release(fd)


def test_shared_holders_do_not_block_each_other(paths: BoxPaths) -> None:
    with gate(paths) as first:
        with gate(paths) as second:
            assert (first, second) == (False, False)
            assert upgrade_holds_gate(paths) is False


def test_gate_is_held_shared_for_the_block(paths: BoxPaths) -> None:
    with gate(paths):
        fd = open_shared_lockfile(paths.jobs_gate)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
