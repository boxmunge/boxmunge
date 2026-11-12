# SPDX-License-Identifier: Apache-2.0
"""What the box knows about its backups, kept across runs.

state/backup/<project>.json, for each project:
  snapshot, snapshot_at     the newest snapshot a backup published;
  excused_at                when a scheduled backup last rightly took none
                            (the project was paused, quarantined or
                            mid-migration, or has no backup configured);
  failing_since, failed_at, failure
                            the scheduled backup has failed since then, last
                            at failed_at, for that cause. Gone after a good
                            snapshot or an excused night;
  synced_at                 when an off-site sync last copied its snapshots;
  unsynced_since            when the oldest snapshot no sync has copied was
                            published;
  alerted                   the conditions the operator was told of
                            (backup_alerts).
state/backup-sync.json holds the all-projects sync's own synced_at,
failing_since, failed_at, failure and alerted, and expected_since: when a
scheduled sync first ran with a remote configured.

Deploy writes these (backups, the sync) and so does root (check-all's
alerts, the userns migration's backups), so every change is a
read-modify-write under one lock. A record a writer cannot read is logged
and replaced; a reader gets a StateError naming the file. A change that
cannot be written is logged as an error and never fails the backup that
made it: the record then goes stale, which the freshness check reports.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.fileutil import exclusive_lock
from boxmunge.log import log_error
from boxmunge.paths import BoxPaths, InvalidProjectName
from boxmunge.state import StateError, read_state, write_state

_TIMES = ("snapshot_at", "excused_at", "failing_since", "failed_at", "synced_at",
          "unsynced_since", "expected_since")
_TEXTS = ("snapshot", "failure")
CAUSE_LIMIT = 600   # an alert carries the cause; a dump's stderr can be long


@dataclass(frozen=True)
class Evidence:
    snapshot: str | None = None
    snapshot_at: datetime | None = None
    excused_at: datetime | None = None
    failing_since: datetime | None = None
    failed_at: datetime | None = None
    failure: str | None = None
    synced_at: datetime | None = None
    unsynced_since: datetime | None = None
    expected_since: datetime | None = None
    alerted: dict[str, str] = field(default_factory=dict)


def _parse(record: dict[str, Any], path: Path) -> Evidence:
    values: dict[str, Any] = {}
    for key in _TIMES:
        raw = record.get(key)
        if raw is None:
            continue
        try:
            values[key] = datetime.fromisoformat(raw)
        except (TypeError, ValueError) as e:
            raise StateError(f"State file {path}: {key} is not a time ({raw!r})") from e
        if values[key].tzinfo is None:
            raise StateError(f"State file {path}: {key} has no timezone ({raw!r})")
    for key in _TEXTS:
        if not isinstance(record.get(key, ""), str):
            raise StateError(f"State file {path}: {key} is not text")
        values[key] = record.get(key)
    alerted = record.get("alerted", {})
    if not isinstance(alerted, dict) or not all(isinstance(v, str) for v in alerted.values()):
        raise StateError(f"State file {path}: alerted is not a mapping of text")
    return Evidence(alerted=dict(alerted), **values)


def project_evidence(paths: BoxPaths, project: str) -> Evidence:
    """The project's record; empty when it has none. Raises StateError."""
    path = paths.project_backup_state(project)
    return _parse(read_state(path), path)


def sync_evidence(paths: BoxPaths) -> Evidence:
    """The all-projects sync's record; empty when there is none. Raises StateError."""
    return _parse(read_state(paths.backup_sync_state), paths.backup_sync_state)


def deployed_projects(paths: BoxPaths) -> list[str]:
    """The projects backup-all visits. One whose name is no longer valid has
    no record (backup-all reports it every night)."""
    if not paths.projects.exists():
        return []
    names = []
    for entry in sorted(paths.projects.iterdir()):
        if entry.is_dir() and (entry / "manifest.yml").exists():
            try:
                paths.project_backup_state(entry.name)
            except InvalidProjectName:
                continue
            names.append(entry.name)
    return names


def _update(paths: BoxPaths, project: str | None, what: str,
            change: Callable[[dict[str, Any]], None]) -> None:
    """Apply `change` to the project's record (the sync's, for None)."""
    try:
        path = paths.project_backup_state(project) if project else paths.backup_sync_state
        with exclusive_lock(paths.backup_state / ".lock"):
            try:
                record = read_state(path)
                _parse(record, path)
            except StateError as e:
                log_error("backup", f"{e}; replacing it", paths, project=project)
                record = {}
            before = dict(record)
            change(record)
            if record != before:
                write_state(path, record)
    except (OSError, InvalidProjectName) as e:
        log_error("backup", f"Cannot record {what} ({e}); backup-freshness and the "
                  f"backup alerts go by the older record", paths, project=project)


def _now(now: datetime | None) -> str:
    return (now or datetime.now(timezone.utc)).isoformat()


def _clear_failure(record: dict[str, Any]) -> None:
    for key in ("failing_since", "failed_at", "failure"):
        record.pop(key, None)


def _set_failure(record: dict[str, Any], cause: str, at: str) -> None:
    record.setdefault("failing_since", at)
    record["failed_at"], record["failure"] = at, cause[:CAUSE_LIMIT]


def record_snapshot(paths: BoxPaths, project: str, name: str,
                    now: datetime | None = None) -> None:
    """A backup of any kind published `name`."""
    at = _now(now)

    def change(record: dict[str, Any]) -> None:
        record["snapshot"], record["snapshot_at"] = name, at
        record.setdefault("unsynced_since", at)
        _clear_failure(record)
    _update(paths, project, f"the snapshot {name}", change)


def record_excused(paths: BoxPaths, project: str, now: datetime | None = None) -> None:
    """A scheduled backup rightly took no snapshot. A project that never
    had a record (no backup configured) gets none."""
    at = _now(now)

    def change(record: dict[str, Any]) -> None:
        if record:
            record["excused_at"] = at
            _clear_failure(record)
    _update(paths, project, "the excused backup", change)


def record_failure(paths: BoxPaths, project: str, cause: str,
                   now: datetime | None = None) -> None:
    """A scheduled backup failed. `failing_since` keeps the first failure's time."""
    at = _now(now)
    _update(paths, project, "the failed backup", lambda record: _set_failure(record, cause, at))


def record_synced(paths: BoxPaths, projects: list[str], started: datetime,
                  now: datetime | None = None) -> None:
    """A sync that began at `started` copied these projects' snapshots. One
    published after it began may have been missed: it still awaits a copy."""
    at = _now(now)

    def change(record: dict[str, Any]) -> None:
        if "snapshot_at" not in record:
            return
        record["synced_at"] = at
        if datetime.fromisoformat(record["snapshot_at"]) > started:
            record["unsynced_since"] = record["snapshot_at"]
        else:
            record.pop("unsynced_since", None)
    for project in projects:
        _update(paths, project, "the off-site sync", change)


def record_sync_run(paths: BoxPaths, cause: str | None, now: datetime | None = None) -> None:
    """The all-projects sync ran with a remote configured: `cause` is why it
    failed, None when it succeeded."""
    at = _now(now)

    def change(record: dict[str, Any]) -> None:
        record.setdefault("expected_since", at)
        if cause is None:
            record["synced_at"] = at
            _clear_failure(record)
        else:
            _set_failure(record, cause, at)
    _update(paths, None, "the off-site sync", change)


def record_sync_not_expected(paths: BoxPaths) -> None:
    """The all-projects sync ran with no remote configured: no off-site
    copy is expected until one runs with a remote again."""
    def change(record: dict[str, Any]) -> None:
        record.pop("expected_since", None)
        _clear_failure(record)
    _update(paths, None, "the sync with no remote", change)


def mark_alerted(paths: BoxPaths, project: str | None, alert: str, ref: str) -> None:
    """The operator was told of the `alert` condition identified by `ref`."""
    def change(record: dict[str, Any]) -> None:
        record["alerted"] = {**record.get("alerted", {}), alert: ref}
    _update(paths, project, f"the delivered {alert} alert", change)
