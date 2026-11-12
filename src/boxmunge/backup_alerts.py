# SPDX-License-Identifier: Apache-2.0
"""Backup alerts: a failed scheduled backup or sync, and backups gone stale.

From the evidence in state/backup (backup_evidence):
- a scheduled backup failed: priority 0, naming the project and the cause;
- a project has had no good snapshot for over 50 hours (two missed
  nights): priority 1. A night it was rightly not backed up (paused,
  quarantined) counts as good;
- once backup_remote is set and a scheduled sync has run with it: a
  project's snapshot has waited over 50 hours for its off-site copy,
  priority 1; and the all-projects sync failed, priority 0.

Each goes out once per continuing condition: `alerted` in the record holds
when the condition began, and is written only when the alert was delivered,
so an undelivered one is tried again on the next run. backup-all and
backup-sync deliver when they finish; check-all (the health timer) every
five minutes, which is what sends a 50-hour alert on time and retries.
The backup-freshness health check warns from the same evidence at 26 hours.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from boxmunge.backup_evidence import (
    Evidence, deployed_projects, mark_alerted, project_evidence, sync_evidence,
)
from boxmunge.config import ConfigError, load_config
from boxmunge.fileutil import exclusive_lock
from boxmunge.log import log_error
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

WARN_AFTER = timedelta(hours=26)
ALERT_AFTER = timedelta(hours=50)

Send = Callable[..., bool]   # notify's signature


@dataclass(frozen=True)
class Alert:
    kind: str      # the key under `alerted`
    ref: str       # when the condition began: one alert per value
    title: str
    body: str
    priority: int


def remote_configured(paths: BoxPaths) -> bool:
    """Whether backup_remote is set. Raises ConfigError."""
    return bool(load_config(paths).get("backup_remote"))


def last_good(e: Evidence) -> datetime | None:
    """When the project last had a good snapshot or was rightly without
    one; before any, when its scheduled backup began to fail."""
    good = [at for at in (e.snapshot_at, e.excused_at) if at is not None]
    return max(good) if good else e.failing_since


def awaiting_copy_since(e: Evidence, sync: Evidence) -> datetime | None:
    """Since when a snapshot of the project has been due an off-site copy:
    None when none waits, or no scheduled sync has run with a remote yet."""
    if e.unsynced_since is None or sync.expected_since is None:
        return None
    return max(e.unsynced_since, sync.expected_since)


def stamp(at: datetime) -> str:
    return at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def newest_snapshot(e: Evidence) -> str:
    if e.snapshot is None or e.snapshot_at is None:
        return "No good snapshot is recorded."
    return f"Newest good snapshot: {e.snapshot} ({stamp(e.snapshot_at)})."


def _project_alerts(project: str, e: Evidence, sync: Evidence | None,
                    now: datetime) -> list[Alert]:
    alerts = []
    if e.failing_since is not None:
        alerts.append(Alert(
            "failing", e.failing_since.isoformat(), f"{project}: scheduled backup failed",
            f"{e.failure}\n{newest_snapshot(e)}\n"
            f"Fix the cause, then run: boxmunge backup {project}", 0))
    good = last_good(e)
    if good is not None and now - good > ALERT_AFTER:
        why = (f"The scheduled backup has failed since {stamp(e.failing_since)}: {e.failure}"
               if e.failing_since is not None else
               "No scheduled backup has reported since. `boxmunge log --component backup` "
               "shows the last runs; `boxmunge health` shows whether the backup timer runs.")
        alerts.append(Alert(
            "stale", good.isoformat(), f"{project}: no good backup for over 50 hours",
            f"{newest_snapshot(e)}\n{why}", 1))
    waiting = awaiting_copy_since(e, sync) if sync is not None else None
    if waiting is not None and now - waiting > ALERT_AFTER:
        copied = (f"Last off-site copy of {project}: {stamp(e.synced_at)}."
                  if e.synced_at is not None else f"No off-site copy of {project} is recorded.")
        alerts.append(Alert(
            "unsynced", waiting.isoformat(), f"{project}: no off-site copy for over 50 hours",
            f"A snapshot has waited for its copy to backup_remote since {stamp(waiting)}. "
            f"{copied}\nRun: boxmunge backup-sync", 1))
    return alerts


def _sync_alerts(sync: Evidence) -> list[Alert]:
    if sync.failing_since is None:
        return []
    last = (f"Last good sync: {stamp(sync.synced_at)}." if sync.synced_at is not None
            else "No good sync is recorded.")
    return [Alert("failing", sync.failing_since.isoformat(), "Off-site backup sync failed",
                  f"{sync.failure}\n{last}\nFix the cause, then run: boxmunge backup-sync", 0)]


def _send_due(paths: BoxPaths, send: Send, project: str | None, alerted: dict[str, str],
              alerts: list[Alert]) -> None:
    for alert in alerts:
        if alerted.get(alert.kind) == alert.ref:
            continue
        if send(paths, alert.title, alert.body, component="backup", project=project,
                priority=alert.priority):
            mark_alerted(paths, project, alert.kind, alert.ref)


def _expected_sync(paths: BoxPaths) -> Evidence | None:
    """The sync's record when off-site copies are expected, else None. With
    a config that cannot be read nothing can be sent either (notify logs
    that), so the off-site alerts wait for a readable one."""
    try:
        return sync_evidence(paths) if remote_configured(paths) else None
    except ConfigError:
        return None
    except StateError as e:
        log_error("backup", f"{e}; off-site alerts wait for the next backup-sync, "
                  f"which replaces it", paths)
        return None


def deliver(paths: BoxPaths, send: Send, *, now: datetime | None = None) -> None:
    """Send every backup alert that is due and was not delivered yet."""
    now = now or datetime.now(timezone.utc)
    try:
        # Held across the sends: a second run waits, then finds them recorded.
        with exclusive_lock(paths.backup_state / ".alerts.lock"):
            sync = _expected_sync(paths)
            for project in deployed_projects(paths):
                try:
                    e = project_evidence(paths, project)
                except StateError as err:
                    log_error("backup", f"{err}; backup alerts for {project} wait for its "
                              f"next backup, which replaces it", paths, project=project)
                    continue
                _send_due(paths, send, project, e.alerted,
                          _project_alerts(project, e, sync, now))
            if sync is not None:
                _send_due(paths, send, None, sync.alerted, _sync_alerts(sync))
    except OSError as e:
        log_error("backup", f"Backup alerts were not checked: {e}", paths)


def alert_backups(paths: BoxPaths) -> None:
    """deliver, for check-all (root's health timer)."""
    deliver(paths, notify)
