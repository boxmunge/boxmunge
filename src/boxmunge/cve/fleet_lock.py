# SPDX-License-Identifier: Apache-2.0
"""One fleet-wide CVE run at a time: the nightly `security scan` and the KEV
watch's tick each hold ``state/.cve-fleet.lock`` for their whole run, so a
watch rescan and a fleet scan never judge, quarantine or hold the same
projects at once (the circuit breaker counts a run's quarantines as a unit).
The watch does not wait for it (it skips the tick); the fleet scan waits up
to ``FLEET_WAIT_SECONDS`` and then fails, rather than run beside the watch.
"""
from __future__ import annotations

import fcntl
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager

from boxmunge.fileutil import open_shared_lockfile
from boxmunge.paths import BoxPaths

FLEET_WAIT_SECONDS = 600.0
_POLL_SECONDS = 2.0


class FleetLockBusy(Exception):
    """Another fleet-wide CVE run holds the lock."""


@contextmanager
def fleet_lock(paths: BoxPaths, *, wait_seconds: float = 0.0) -> Iterator[None]:
    """Hold the fleet lock for the block. Raises FleetLockBusy if it is not
    free within ``wait_seconds`` (0: do not wait)."""
    fd = open_shared_lockfile(paths.cve_fleet_lock)
    try:
        # Counted polls, not a clock: the wait is approximate by design.
        attempts = int(wait_seconds / _POLL_SECONDS) + 1
        for attempt in range(attempts):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if attempt + 1 < attempts:
                    time.sleep(_POLL_SECONDS)
        else:
            raise FleetLockBusy(
                f"another CVE run (the nightly scan or the KEV watch) holds "
                f"{paths.cve_fleet_lock}")
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
