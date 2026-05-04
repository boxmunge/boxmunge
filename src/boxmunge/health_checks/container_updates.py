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
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(hours=_STALE_THRESHOLD_HOURS)

    import logging
    logger = logging.getLogger("boxmunge")

    for state_file in sorted(state_dir.glob("*.json")):
        try:
            data = json.loads(state_file.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Skipping unreadable state file %s: %s", state_file, e)
            continue
        target = state_file.stem
        if data.get("last_status") == "failed":
            failed.append(target)
        last_check = data.get("last_check")
        if last_check:
            # Normalize trailing Z to +00:00 (Python <3.11 doesn't accept Z)
            normalized = last_check.replace("Z", "+00:00") if last_check.endswith("Z") else last_check
            try:
                ts = datetime.fromisoformat(normalized)
                if ts < threshold:
                    stale.append(target)
            except ValueError as e:
                logger.warning("Unparseable last_check in %s: %s (%s)", state_file, last_check, e)

    if failed:
        return HealthCheck(
            name="container-updates",
            status="warn",
            detail=f"failed targets: {', '.join(failed)}",
        )
    if stale:
        return HealthCheck(
            name="container-updates",
            status="warn",
            detail=f"stale (>48h since check): {', '.join(stale)}",
        )
    return HealthCheck(name="container-updates", status="ok", detail="all targets recent")
