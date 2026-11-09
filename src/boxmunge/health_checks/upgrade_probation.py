# SPDX-License-Identifier: Apache-2.0
"""Health check: has an expired upgrade probation been left unpromoted?

The health timer runs ``boxmunge-upgrade check-probation`` every five
minutes, and it promotes a probation once it expires. That runs as an
ignored ``ExecStartPre``, so if it keeps failing nothing else says so, and
the probation (with the deploy-shell and upgrade limits it brings) outlives
its window for good (#119). This reports it.

Warns, never errors: check-probation itself runs ``health``, and an exit of
2 during probation would roll the platform back.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.upgrade_state import UpgradeStateError, read_probation

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "upgrade-probation"

# Several timer fires (5 min apart, each allowing check-probation's 180 s
# health budget) before an unpromoted, expired probation counts as stuck.
PROMOTION_GRACE = timedelta(minutes=30)


def _ago(delta: timedelta) -> str:
    hours = int(delta.total_seconds() // 3600)
    return f"{hours} h" if hours else f"{int(delta.total_seconds() // 60)} min"


def check_upgrade_probation(paths: BoxPaths, *, now: datetime | None = None) -> HealthCheck:
    try:
        probation = read_probation(paths)
    except UpgradeStateError as e:
        return HealthCheck(NAME, "warn", f"cannot read the upgrade probation marker: {e}")
    if probation is None:
        return HealthCheck(NAME, "ok", "no release on probation")
    version = probation.get("version", "?")
    try:
        expires = datetime.fromisoformat(probation["expires_at"])
        if expires.tzinfo is None:
            raise ValueError("no timezone")
    except (KeyError, TypeError, ValueError) as e:
        return HealthCheck(
            NAME, "warn",
            f"{paths.probation} has no usable expires_at ({e}), so check-probation cannot "
            f"end the probation of {version}; repair it as root, or `sudo rm {paths.probation}` "
            f"to accept {version}")
    overdue = (now or datetime.now(timezone.utc)) - expires
    if overdue < PROMOTION_GRACE:
        until = expires.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return HealthCheck(NAME, "ok", f"{version} on probation until {until}")
    shim = paths.bin / "boxmunge-upgrade"
    return HealthCheck(
        NAME, "warn",
        f"the probation of {version} expired {_ago(overdue)} ago and was not promoted. "
        f"`sudo {shim} check-probation` shows why; to accept {version} now, "
        f"`sudo rm {paths.probation}`")
