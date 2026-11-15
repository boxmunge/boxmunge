# SPDX-License-Identifier: Apache-2.0
"""Health check: an urgent autofix stuck in the queue.

An urgent patch that has waited AUTOFIX_QUEUE_MAX_WAIT since its detection
has not started (the autofix unit does not start, or another operation
keeps holding the project). The scans stop holding its quarantine back and
alert it once a day; this check warns for as long as it lasts. Warns, never
errors (check-probation runs `health`).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.cve.autofix_policy import AUTOFIX_QUEUE_MAX_WAIT
from boxmunge.cve.autofix_record import queued_projects, read_queue_entry
from boxmunge.paths import InvalidProjectName
from boxmunge.state import StateError

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "autofix-queue"


def check_autofix_queue(paths: BoxPaths) -> HealthCheck:
    try:
        names = queued_projects(paths)
    except StateError as e:
        return HealthCheck(NAME, "warn", str(e))
    now = datetime.now(timezone.utc)
    problems = []
    for name in names:
        try:
            entry = read_queue_entry(paths, name)
        except (StateError, InvalidProjectName) as e:
            problems.append(f"{name}: {e}")
            continue
        if entry is not None and now - entry.detected_at >= AUTOFIX_QUEUE_MAX_WAIT:
            waited = int((now - entry.detected_at).total_seconds() // 60)
            problems.append(f"{name}: the urgent patch of {', '.join(entry.cves)} has waited "
                            f"{waited} min without starting (journalctl -u boxmunge-autofix)")
    if problems:
        return HealthCheck(NAME, "warn", "; ".join(problems))
    return HealthCheck(NAME, "ok", f"{len(names)} queued" if names else "nothing queued")
