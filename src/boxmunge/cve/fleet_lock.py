# SPDX-License-Identifier: Apache-2.0
"""One fleet-wide CVE run at a time: the nightly `security scan` and the KEV
watch's tick each hold ``state/.cve-fleet.lock`` for their whole run, so a
watch rescan and a fleet scan never judge, quarantine or hold the same
projects at once (the circuit breaker counts a run's quarantines as a unit).
The watch does not wait for it (it skips the tick); the fleet scan blocks
until it is free. The wait is bounded by the watch service's
TimeoutStartSec (1h): systemd kills a stuck tick and the flock goes with it.
"""
from __future__ import annotations

import fcntl
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from boxmunge.fileutil import open_shared_lockfile
from boxmunge.paths import BoxPaths


class FleetLockBusy(Exception):
    """Another fleet-wide CVE run holds the lock."""


@contextmanager
def fleet_lock(paths: BoxPaths, *, wait: bool = False,
               on_wait: Callable[[], None] | None = None) -> Iterator[None]:
    """Hold the fleet lock for the block. With ``wait`` False, raises
    FleetLockBusy if it is held; with ``wait`` True, calls ``on_wait`` once
    and blocks until it is free."""
    fd = open_shared_lockfile(paths.cve_fleet_lock)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            if not wait:
                raise FleetLockBusy(
                    f"another CVE run (the nightly scan or the KEV watch) holds "
                    f"{paths.cve_fleet_lock}") from None
            if on_wait is not None:
                on_wait()
            fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
