# SPDX-License-Identifier: Apache-2.0
"""Health check: is each project's newest good backup recent?

Warns, from where each project's backups stand (backup_standing), when a
project:
- is due a backup and has no snapshot on disk yet, or none taken within 26
  hours (a night it was rightly not backed up, paused or quarantined,
  counts as good);
- failed its last scheduled backup;
- has snapshots dated ahead of the clock (its old backups are not pruned);
- with backup_remote set: has snapshots and no successful off-site sync
  recorded yet, or, once a scheduled sync has run with the remote, a
  snapshot that has waited over 26 hours for its copy;
or when the all-projects sync is failing, a record cannot be read, or
state/backup looks unwritable (the five-minute backup alerts may be held).

A warning, never an error: none of these is a defect of the release, and
none must roll back a platform upgrade in probation. The alerts for the
same conditions are backup_alerts'.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from boxmunge.project_inventory import Inventory, classify, damaged_detail
from boxmunge.backup_evidence import Evidence, deployed_projects, sync_evidence, write_problem
from boxmunge.backup_standing import (
    WARN_AFTER, Standing, awaiting_copy_since, remote_configured, stamp, standing,
)
from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.config import ConfigError
from boxmunge.state import StateError

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "backup-freshness"


def _hours(age: timedelta) -> int:
    return int(age.total_seconds() // 3600)


def _state_problems(paths: BoxPaths) -> list[str]:
    try:
        problem = write_problem(paths)
    except OSError as e:
        problem = f"{paths.backup_state} cannot be examined: {e}"
    if problem is None:
        return []
    return [f"{problem}: backup state may not be recorded, and the five-minute backup "
            f"alerts may be held (the nightly runs still alert)"]


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


def _project_problems(s: Standing, sync: Evidence | None, now: datetime) -> list[str]:
    project, e = s.project, s.record
    problems = []
    if s.unreadable is not None:
        problems.append(f"{project}: {s.unreadable} (its next backup replaces it)")
    if s.ahead:
        problems.append(f"{project}: {s.ahead} snapshot(s) dated ahead of the clock, so its "
                        f"old backups are not pruned")
    if s.failing:
        problems.append(f"{project}: scheduled backup failing since "
                        f"{stamp(e.failing_since)}: {e.failure}")
    if s.due and s.last_good is None:
        problems.append(f"{project}: no backup yet")
    elif s.due and now - s.last_good > WARN_AFTER:
        problems.append(f"{project}: no good backup for {_hours(now - s.last_good)} h")
    if sync is not None and s.newest is not None:
        waiting = awaiting_copy_since(e, sync)
        if e.synced_at is None:
            problems.append(f"{project}: no successful off-site sync recorded yet")
        elif waiting is not None and now - waiting > WARN_AFTER:
            problems.append(f"{project}: no off-site copy for {_hours(now - waiting)} h")
    return problems


def check_backup_freshness(paths: BoxPaths, *, now: datetime | None = None) -> HealthCheck:
    now = now or datetime.now(timezone.utc)
    problems = _state_problems(paths)
    sync = _sync(paths, problems)
    fresh = 0
    for project in deployed_projects(paths):
        if classify(project, paths) is Inventory.DAMAGED:
            problems.append(f"{project}: {damaged_detail(project)}")
        try:
            s = standing(paths, project, now)
        except OSError as e:
            problems.append(f"{project}: its backups cannot be checked: {e}")
            continue
        fresh += s.due and s.last_good is not None and now - s.last_good <= WARN_AFTER
        problems.extend(_project_problems(s, sync, now))
    if problems:
        return HealthCheck(NAME, "warn", "; ".join(problems))
    if not fresh:
        return HealthCheck(NAME, "ok", "no project is due a backup")
    return HealthCheck(NAME, "ok", f"{fresh} project(s) backed up within 26 h")
