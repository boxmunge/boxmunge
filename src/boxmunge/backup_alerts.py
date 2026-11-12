# SPDX-License-Identifier: Apache-2.0
"""Backup alerts: a failed scheduled backup or sync, and backups gone stale.

From where each project's backups stand (backup_standing):
- a scheduled backup failed: priority 0, naming the project and the cause;
- a project due a backup has had no good snapshot for over 50 hours (two
  missed nights): priority 1. The newest snapshot on disk says when the
  last good one was; a night the project was rightly not backed up
  (paused, quarantined) counts as good;
- once backup_remote is set and a scheduled sync has run with it: a
  project's snapshot has waited over 50 hours for its off-site copy,
  priority 1; and the all-projects sync failed, priority 0.

Each goes out once per continuing condition. `alerted` in the record holds
when the condition began: it is claimed before the alert is sent and
withdrawn if the alert was not delivered, so an undelivered one is tried
again on the next run. backup-all and backup-sync deliver when they
finish; check-all (the health timer) every five minutes, which is what
sends a 50-hour alert on time and retries.

When the claim cannot be written the same alert would go out on every run.
check-all's five-minute tick therefore sends nothing it cannot claim: it
logs why, and backup-freshness reports the unwritable state. A nightly run
sends it unclaimed (once a night at most) and reports the unwritten state
with its other unwritten changes (backup_evidence.reporting_unwritten).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from boxmunge.backup_evidence import (
    Evidence, Send, claim, deployed_projects, report_unwritten, sync_evidence, withdraw,
)
from boxmunge.backup_standing import (
    ALERT_AFTER, Standing, awaiting_copy_since, newest_snapshot, remote_configured,
    stamp, standing,
)
from boxmunge.config import ConfigError
from boxmunge.fileutil import exclusive_lock
from boxmunge.log import log_error
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError


@dataclass(frozen=True)
class Alert:
    kind: str      # the key under `alerted`
    ref: str       # when the condition began: one alert per value
    title: str
    body: str
    priority: int


def _project_alerts(s: Standing, sync: Evidence | None, now: datetime) -> list[Alert]:
    project, e = s.project, s.record
    alerts = []
    if s.failing:
        alerts.append(Alert(
            "failing", e.failing_since.isoformat(), f"{project}: scheduled backup failed",
            f"{e.failure}\n{newest_snapshot(s)}\n"
            f"Fix the cause, then run: boxmunge backup {project}", 0))
    # Before any good snapshot, the clock starts at the first failure.
    good = s.last_good or (e.failing_since if s.failing else None)
    if s.due and good is not None and now - good > ALERT_AFTER:
        why = (f"The scheduled backup has failed since {stamp(e.failing_since)}: {e.failure}"
               if s.failing else
               "No scheduled backup has reported since. `boxmunge log --component backup` "
               "shows the last runs; `boxmunge health` shows whether the backup timer runs.")
        alerts.append(Alert(
            "stale", good.isoformat(), f"{project}: no good backup for over 50 hours",
            f"{newest_snapshot(s)}\n{why}", 1))
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


def _unwritten(paths: BoxPaths, project: str | None, what: str, error: OSError,
               held: list[str] | None) -> None:
    if held is None:
        report_unwritten(paths, project, what, error)
    else:
        held.append(f"{project or 'the off-site sync'}: not recorded ({error}): {what}")


def _send(paths: BoxPaths, send: Send, project: str | None, alert: Alert) -> bool:
    return send(paths, alert.title, alert.body, component="backup", project=project,
                priority=alert.priority)


def _send_due(paths: BoxPaths, send: Send, project: str | None, alerted: dict[str, str],
              alerts: list[Alert], held: list[str] | None) -> None:
    """`held` is None for a scheduled run, which sends an alert it cannot
    claim; for the tick it gathers the ones it did not send for that."""
    for alert in alerts:
        if alerted.get(alert.kind) == alert.ref:
            continue
        try:
            claim(paths, project, alert.kind, alert.ref)
        except OSError as e:
            _unwritten(paths, project, f"that the alert '{alert.title}' was sent", e, held)
            if held is None:
                _send(paths, send, project, alert)
            continue
        if not _send(paths, send, project, alert):
            try:
                withdraw(paths, project, alert.kind, alert.ref)
            except OSError as e:
                _unwritten(paths, project,
                           f"that the alert '{alert.title}' was not delivered", e, held)


def _expected_sync(paths: BoxPaths) -> Evidence | None:
    """The sync's record when off-site copies are expected, else None. With
    a config that cannot be read nothing can be sent either (notify logs
    that), so the off-site alerts wait for a readable one. A record that
    cannot be read is backup-freshness's to report, not every tick's."""
    try:
        return sync_evidence(paths) if remote_configured(paths) else None
    except (ConfigError, StateError):
        return None


def _deliver(paths: BoxPaths, send: Send, now: datetime, held: list[str] | None) -> None:
    # Held across the sends: a second run waits, then finds them claimed.
    with exclusive_lock(paths.backup_state / ".alerts.lock"):
        sync = _expected_sync(paths)
        for project in deployed_projects(paths):
            try:
                s = standing(paths, project, now)
            except OSError as e:
                log_error("backup", f"Backup alerts for {project} were not checked: {e}",
                          paths, project=project)
                continue
            _send_due(paths, send, project, s.record.alerted,
                      _project_alerts(s, sync, now), held)
        if sync is not None:
            _send_due(paths, send, None, sync.alerted, _sync_alerts(sync), held)


def deliver(paths: BoxPaths, send: Send, *, now: datetime | None = None) -> None:
    """For a scheduled run (backup-all, backup-sync): send every backup
    alert that is due and was not delivered yet."""
    try:
        _deliver(paths, send, now or datetime.now(timezone.utc), held=None)
    except OSError as e:
        report_unwritten(paths, None, "which backup alerts were sent", e)


def alert_backups(paths: BoxPaths, *, now: datetime | None = None) -> None:
    """For check-all (root's health timer): send every backup alert that is
    due, was not delivered yet, and can be claimed."""
    held: list[str] = []
    try:
        _deliver(paths, notify, now or datetime.now(timezone.utc), held)
    except OSError as e:
        log_error("backup", f"Backup alerts were not checked: {e}", paths)
    if held:
        log_error("backup", f"{len(held)} backup alert(s) held: the backup state cannot be "
                  f"written, so each would be sent again every five minutes. `boxmunge "
                  f"health` (backup-freshness) reports that state, and the nightly runs "
                  f"alert. Held: {'; '.join(held)}", paths)
