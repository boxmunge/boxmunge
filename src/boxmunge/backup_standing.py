# SPDX-License-Identifier: Apache-2.0
"""Where a project's backups stand: what the backup alerts and the
backup-freshness check both judge.

Freshness goes by the snapshots in the project's backups directory. They
are there whether or not anything could be recorded, and each one's name
says when it was taken, so a box upgraded with yesterday's snapshot is
fresh, and a project whose backups stop is caught even when state/backup
cannot be written. The record (backup_evidence) adds what no snapshot
shows: a night the project was rightly not backed up, a failing scheduled
backup and its cause, the off-site copies, and which alerts went out.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from boxmunge.backup import AHEAD_SLACK, dated_snapshots
from boxmunge.backup_evidence import Evidence, project_evidence
from boxmunge.config import load_config
from boxmunge.fleet import PROJECT_INPUT_ERRORS
from boxmunge.lifecycle import is_blocked
from boxmunge.manifest import load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

WARN_AFTER = timedelta(hours=26)
ALERT_AFTER = timedelta(hours=50)


@dataclass(frozen=True)
class Standing:
    project: str
    record: Evidence                      # empty when there is none, or `unreadable`
    unreadable: str | None                # why the record cannot be read
    newest: tuple[datetime, str] | None   # the newest snapshot on disk: taken at, name
    ahead: int                            # snapshots named for a time ahead of the clock
    due: bool                             # tonight's backup should take a snapshot

    @property
    def failing(self) -> bool:
        """The scheduled backup failed and no snapshot was taken since."""
        failed = self.record.failed_at or self.record.failing_since
        return self.record.failing_since is not None and (
            self.newest is None or self.newest[0] < failed)

    @property
    def last_good(self) -> datetime | None:
        """When the project last had a good snapshot or was rightly without
        one; None when it never did."""
        good = [at for at in (self.newest and self.newest[0], self.record.excused_at)
                if at is not None]
        return max(good) if good else None


def backup_due(paths: BoxPaths, project: str) -> bool:
    """Whether tonight's scheduled backup should take a snapshot: the
    project is not paused, quarantined or mid-migration, and its manifest
    configures a backup. A project whose state or manifest cannot be read
    counts as due: the nightly backup fails on the same input and alerts,
    and until then its snapshots are held to the same age as any other's."""
    try:
        if is_blocked(project, paths) is not None:
            return False
        backup = load_manifest(paths.project_manifest(project)).get("backup") or {}
    except PROJECT_INPUT_ERRORS:
        return True
    return backup.get("type", "none") != "none"


def standing(paths: BoxPaths, project: str, now: datetime) -> Standing:
    """Raises OSError when the project's backups directory cannot be read."""
    try:
        record, unreadable = project_evidence(paths, project), None
    except StateError as e:
        record, unreadable = Evidence(), str(e)
    snapshots = dated_snapshots(paths.project_backups(project), project)
    taken = [(at, path.name) for at, _kind, path in snapshots if at - now <= AHEAD_SLACK]
    return Standing(project, record, unreadable, taken[-1] if taken else None,
                    len(snapshots) - len(taken), backup_due(paths, project))


def remote_configured(paths: BoxPaths) -> bool:
    """Whether backup_remote is set. Raises ConfigError."""
    return bool(load_config(paths).get("backup_remote"))


def awaiting_copy_since(e: Evidence, sync: Evidence) -> datetime | None:
    """Since when a snapshot of the project has been due an off-site copy:
    None when none waits, or no scheduled sync has run with a remote yet."""
    if e.unsynced_since is None or sync.expected_since is None:
        return None
    return max(e.unsynced_since, sync.expected_since)


def stamp(at: datetime) -> str:
    return at.strftime("%Y-%m-%d %H:%M UTC")


def newest_snapshot(s: Standing) -> str:
    if s.newest is None:
        return "No snapshot is on disk."
    return f"Newest good snapshot: {s.newest[1]} ({stamp(s.newest[0])})."
