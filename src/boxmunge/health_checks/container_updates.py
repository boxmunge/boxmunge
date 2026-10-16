# SPDX-License-Identifier: Apache-2.0
"""Health check: container update status."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


_STALE_THRESHOLD_HOURS = 48


def check_container_updates(paths: BoxPaths) -> HealthCheck:
    """Check container-update state across all targets.

    Returns warn (status 1) if any target is in 'failed' state OR if any
    target's last_check is older than 48 hours. ok otherwise.

    Note: returns warn, not error, because container update failures are
    orthogonal to platform health and should not trigger platform rollback
    during the platform probation window.
    """
    state_dir = paths.container_update_state
    if not state_dir.exists():
        return HealthCheck(name="container-updates", status="ok", detail="no state yet")

    failed: list[str] = []
    stale: list[str] = []
    unreadable: list[str] = []
    threshold = datetime.now(timezone.utc) - timedelta(hours=_STALE_THRESHOLD_HOURS)

    for state_file in sorted(state_dir.glob("*.json")):
        target = state_file.stem
        try:
            data = json.loads(state_file.read_text())
            last_check = data.get("last_check")
            # Python 3.10's fromisoformat does not accept a trailing Z.
            ts = (datetime.fromisoformat(last_check.removesuffix("Z") + "+00:00"
                                         if last_check.endswith("Z") else last_check)
                  if last_check else None)
            if ts is not None and ts.tzinfo is None:
                raise ValueError(f"last_check {last_check!r} has no timezone")
        except (json.JSONDecodeError, OSError, UnicodeDecodeError,
                AttributeError, TypeError, ValueError) as e:
            # A state file nobody can read hides whether updates are working.
            unreadable.append(f"{target} ({type(e).__name__}: {e})")
            continue
        if data.get("last_status") == "failed":
            failed.append(target)
        if ts is not None and ts < threshold:
            stale.append(target)

    problems = []
    if failed:
        problems.append(f"failed targets: {', '.join(failed)}")
    if stale:
        problems.append(f"stale (>48h since check): {', '.join(stale)}")
    if unreadable:
        problems.append(f"unreadable state in {state_dir}: {'; '.join(unreadable)}")
    if problems:
        return HealthCheck(name="container-updates", status="warn", detail="; ".join(problems))
    return HealthCheck(name="container-updates", status="ok", detail="all targets recent")
