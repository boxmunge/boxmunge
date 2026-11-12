# SPDX-License-Identifier: Apache-2.0
"""Health check: is each project's newest good backup recent?

Warns, from the evidence in state/backup (backup_evidence), when a project:
- has had no good snapshot for over 26 hours (a night it was rightly not
  backed up, paused or quarantined, counts as good);
- failed its last scheduled backup;
- once backup_remote is set and a scheduled sync has run with it, has a
  snapshot that has waited over 26 hours for its off-site copy;
or when the all-projects sync is failing, or a record cannot be read.

A warning, never an error: a stale backup is not a defect of the release,
and must not roll back a platform upgrade in probation. The alerts for the
same conditions are backup_alerts'.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from boxmunge.backup_alerts import (
    WARN_AFTER, awaiting_copy_since, last_good, remote_configured, stamp,
)
from boxmunge.backup_evidence import (
    Evidence, deployed_projects, project_evidence, sync_evidence,
)
from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.config import ConfigError
from boxmunge.state import StateError

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "backup-freshness"


def _hours(age: timedelta) -> int:
    return int(age.total_seconds() // 3600)


def _sync(paths: BoxPaths, problems: list[str]) -> Evidence | None:
    """The sync's record when off-site copies are expected, else None."""
    try:
        if not remote_configured(paths):
            return None
        sync = sync_evidence(paths)
    except ConfigError:
        return None   # the alerts check reports a config that cannot be read
    except StateError as e:
        problems.append(f"{e} (the next backup-sync replaces it)")
        return None
    if sync.failing_since is not None:
        problems.append(f"off-site sync failing since {stamp(sync.failing_since)}: "
                        f"{sync.failure} (fix the cause, then run: boxmunge backup-sync)")
    return sync


def _project_problems(project: str, e: Evidence, sync: Evidence | None,
                      now: datetime) -> list[str]:
    problems = []
    good = last_good(e)
    if e.failing_since is not None:
        problems.append(f"{project}: scheduled backup failing since "
                        f"{stamp(e.failing_since)}: {e.failure}")
    if good is not None and now - good > WARN_AFTER:
        problems.append(f"{project}: no good backup for {_hours(now - good)} h")
    waiting = awaiting_copy_since(e, sync) if sync is not None else None
    if waiting is not None and now - waiting > WARN_AFTER:
        problems.append(f"{project}: no off-site copy for {_hours(now - waiting)} h")
    return problems


def check_backup_freshness(paths: BoxPaths, *, now: datetime | None = None) -> HealthCheck:
    now = now or datetime.now(timezone.utc)
    problems: list[str] = []
    sync = _sync(paths, problems)
    recorded = 0
    for project in deployed_projects(paths):
        try:
            e = project_evidence(paths, project)
        except StateError as err:
            problems.append(f"{project}: {err} (its next backup replaces it)")
            continue
        recorded += last_good(e) is not None
        problems.extend(_project_problems(project, e, sync, now))
    if problems:
        return HealthCheck(NAME, "warn", "; ".join(problems))
    if not recorded:
        return HealthCheck(NAME, "ok", "no backups recorded yet")
    return HealthCheck(NAME, "ok", f"{recorded} project(s) backed up within 26 h")
