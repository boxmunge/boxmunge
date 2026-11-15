# SPDX-License-Identifier: Apache-2.0
"""The jobs gate: new jobs are refused while a platform upgrade runs.

state/jobs/gate.lock is held shared by every running job, from before its
claim to after its finish, and exclusively by the upgrade shim. An upgrade
therefore waits for running jobs, and a job waits for a running upgrade.
"""
from __future__ import annotations

import errno
import fcntl
import os
import time
from contextlib import contextmanager
from typing import Iterator

from boxmunge.fileutil import open_shared_lockfile
from boxmunge.paths import BoxPaths

GATE_POLL_SECONDS = 1
UPGRADE_GATE_WAIT_SECONDS = 3600

UPGRADE_REFUSAL = (
    "boxmunge is being upgraded, so new jobs are refused until the upgrade "
    "finishes (usually within 15 minutes). Follow it with: boxmunge log "
    "--component upgrade. Then run the same call again."
)


class GateTimeout(Exception):
    """The upgrade held the jobs gate for the whole wait."""


def _try_shared(fd: int) -> bool:
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            return False
        raise
    return True


def upgrade_holds_gate(paths: BoxPaths) -> bool:
    """True if an upgrade holds the gate exclusively right now."""
    fd = open_shared_lockfile(paths.jobs_gate)
    try:
        return not _try_shared(fd)
    finally:
        os.close(fd)  # closing also drops a shared lock just taken


@contextmanager
def job_gate(paths: BoxPaths) -> Iterator[bool]:
    """Hold the gate shared for the block; yield True if it had to wait."""
    fd = open_shared_lockfile(paths.jobs_gate)
    try:
        waited = False
        deadline = time.monotonic() + UPGRADE_GATE_WAIT_SECONDS
        while not _try_shared(fd):
            waited = True
            if time.monotonic() >= deadline:
                raise GateTimeout(
                    f"{UPGRADE_REFUSAL} (waited {UPGRADE_GATE_WAIT_SECONDS} "
                    f"seconds for the upgrade to release the jobs gate.)"
                )
            time.sleep(GATE_POLL_SECONDS)
        yield waited
    finally:
        os.close(fd)
