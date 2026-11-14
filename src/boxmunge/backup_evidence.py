# SPDX-License-Identifier: Apache-2.0
"""What the box records about its backups, kept across runs.

How fresh a project's backups are is read from the snapshots on disk
(backup_standing), which are there whether or not anything here could be
written. These records hold what no snapshot shows.

state/backup/<project>.json, for each project:
  snapshot, snapshot_at     the newest snapshot a backup published (the
                            off-site sync goes by it);
  unbacked_since            when a project due a backup was first seen with
                            no snapshot and no record of one
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
  alerted                   the conditions whose alert a notifier accepted;
  pending                   the conditions whose alert was being sent, and
                            is not in `alerted` until it was accepted: one
                            still here under the alerts lock was abandoned
                            (backup_alerts).
state/backup-sync.json holds the all-projects sync's own synced_at,
failing_since, failed_at, failure and alerted, and expected_since: when a
scheduled sync first ran with a remote configured.

Deploy writes these (backups, the sync) and so does root (check-all's
alerts, the userns migration's backups), so every change is a
read-modify-write under one lock. A record a writer cannot read is logged
and replaced; a reader gets a StateError naming the file, which covers a
time no backup could have run at (out of range, or far ahead of the
clock). A writer drops only the entries that are wrong and keeps the rest.

A change that cannot be written never fails the backup that made it, and
is never kept quiet either: report_unwritten logs it, prints it, and
alerts, once per scheduled run (reporting_unwritten) or at once.
"""
from __future__ import annotations

import os
import stat
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from boxmunge.fileutil import exclusive_lock
from boxmunge.log import log_error
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths, InvalidProjectName
from boxmunge.project_inventory import project_dir_names
from boxmunge.state import StateError, read_state, write_state

_TIMES = ("snapshot_at", "excused_at", "unbacked_since", "failing_since", "failed_at", "synced_at",
          "unsynced_since", "expected_since")
_TEXTS = ("snapshot", "failure")
_MAPS = ("alerted", "pending")   # {condition: the ref its alert was for}
_FIELDS = (*_TIMES, *_TEXTS, *_MAPS)
STATE_LOCK, ALERTS_LOCK = ".lock", ".alerts.lock"   # in state/backup
# A time this far ahead of the clock was written before the clock stepped
# back: the record stands, and an alert delivered then still counts as sent.
_AHEAD_LIMIT = timedelta(days=2)
_EARLIEST = datetime(2020, 1, 1, tzinfo=timezone.utc)   # no boxmunge backup is older
CAUSE_LIMIT = 600   # an alert carries the cause; a dump's stderr can be long
_SHOWN, _SHOWN_LENGTH = 3, 250   # of the unwritten changes, in one alert

Send = Callable[..., bool]   # notify's signature
# The unwritten changes of the scheduled run in progress; None outside one.
_unwritten: ContextVar[list[str] | None] = ContextVar("unwritten_backup_state", default=None)


@dataclass(frozen=True)
class Evidence:
    snapshot: str | None = None
    snapshot_at: datetime | None = None
    excused_at: datetime | None = None
    unbacked_since: datetime | None = None
    failing_since: datetime | None = None
    failed_at: datetime | None = None
    failure: str | None = None
    synced_at: datetime | None = None
    unsynced_since: datetime | None = None
    expected_since: datetime | None = None
    alerted: dict[str, str] = field(default_factory=dict)
    pending: dict[str, str] = field(default_factory=dict)


def _time(raw: Any, key: str, path: Path) -> datetime:
    """A recorded time, in UTC. Raises StateError for anything else, and for
    a time no backup could have run at: arithmetic on one overflows, and
    one far ahead of the clock would keep a project fresh until the clock
    reached it."""
    try:
        at = datetime.fromisoformat(raw)
    except (TypeError, ValueError) as e:
        raise StateError(f"State file {path}: {key} is not a time ({raw!r})") from e
    if at.tzinfo is None:
        raise StateError(f"State file {path}: {key} has no timezone ({raw!r})")
    try:
        at = at.astimezone(timezone.utc)
        possible = _EARLIEST <= at <= datetime.now(timezone.utc) + _AHEAD_LIMIT
    except OverflowError:
        possible = False
    if not possible:
        raise StateError(f"State file {path}: {key} is not a time a backup could have "
                         f"run at ({raw!r}: before 2020, or over two days ahead of the clock)")
    return at


def _field(record: dict[str, Any], key: str, path: Path) -> Any:
    """The record's entry for `key`, as Evidence holds it. Raises StateError."""
    if key in _TIMES:
        return _time(record[key], key, path) if record.get(key) is not None else None
    if key in _TEXTS:
        if not isinstance(record.get(key, ""), str):
            raise StateError(f"State file {path}: {key} is not text")
        return record.get(key)
    refs = record.get(key, {})
    if not isinstance(refs, dict) or not all(isinstance(v, str) for v in refs.values()):
        raise StateError(f"State file {path}: {key} is not a mapping of text")
    return dict(refs)


def _parse(record: dict[str, Any], path: Path) -> Evidence:
    return Evidence(**{key: _field(record, key, path) for key in _FIELDS})


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
    names = []
    for name in project_dir_names(paths):
        try:
            paths.project_backup_state(name)
        except InvalidProjectName:
            continue
        names.append(name)
    return names


def write_problem(paths: BoxPaths) -> str | None:
    """What shows, without writing (`health` never writes), that a record
    may not be writable; None when nothing shows. It is what this process
    observed, not a verdict: root writes where deploy cannot and into
    blocks reserved for it, and a write can fail for a cause that does not
    show. The first write makes the directory, so a missing one is no
    problem. Raises OSError when the directory cannot be examined."""
    directory = paths.backup_state
    try:
        vfs = os.statvfs(directory)
    except FileNotFoundError:
        return None
    if not directory.is_dir():
        return f"{directory} is not a directory"
    for lock in (directory / STATE_LOCK, directory / ALERTS_LOCK):
        try:
            regular = stat.S_ISREG(lock.lstat().st_mode)
        except FileNotFoundError:
            continue
        if not regular:
            return f"{lock} is not a regular file (remove it: the next run makes its own)"
    if vfs.f_flag & os.ST_RDONLY:
        return f"{directory} is on a filesystem mounted read-only"
    if vfs.f_blocks and not vfs.f_bavail:
        return f"the filesystem of {directory} has no space left for unprivileged users"
    if vfs.f_files and not vfs.f_favail:
        return f"the filesystem of {directory} has no inodes left for unprivileged users"
    if not os.access(directory, os.W_OK | os.X_OK):
        return f"{directory} is not writable by the user running this check (uid {os.geteuid()})"
    return None


def report_unwritten(paths: BoxPaths, project: str | None, what: str,
                     error: Exception) -> None:
    """A change to the backup state could not be written. Said now, in the
    log and on stderr, and alerted: when the scheduled run in progress ends
    (reporting_unwritten), or now when there is none."""
    message = f"{project + ': not' if project else 'Not'} recorded ({error}): {what}"
    print(f"  WARN: {message}", file=sys.stderr)
    log_error("backup", message, paths, project=project)
    gathered = _unwritten.get()
    if gathered is None:
        _alert_unwritten(paths, notify, [message])
    else:
        gathered.append(message)


def _alert_unwritten(paths: BoxPaths, send: Send, unwritten: list[str]) -> None:
    lines = [line[:_SHOWN_LENGTH] for line in unwritten[:_SHOWN]]
    if len(unwritten) > _SHOWN:
        lines.append(f"... and {len(unwritten) - _SHOWN} more.")
    lines.append(f"The backups' own results stand. Make {paths.backup_state} writable; "
                 f"`boxmunge log --component backup` has every line.")
    send(paths, "Backup state cannot be written", "\n".join(lines), component="backup")


@contextmanager
def reporting_unwritten(paths: BoxPaths, send: Send) -> Iterator[None]:
    """For a scheduled run: the changes it could not write go out as one
    alert when it ends, not one each."""
    gathered: list[str] = []
    token = _unwritten.set(gathered)
    try:
        yield
    finally:
        _unwritten.reset(token)
        if gathered:
            _alert_unwritten(paths, send, gathered)


def _change(paths: BoxPaths, project: str | None,
            change: Callable[[dict[str, Any]], None]) -> None:
    """Apply `change` to the project's record (the sync's, for None).
    Raises OSError when it cannot be written."""
    path = paths.project_backup_state(project) if project else paths.backup_sync_state
    with exclusive_lock(paths.backup_state / STATE_LOCK):
        try:
            record = read_state(path)
        except StateError as e:
            log_error("backup", f"{e}; replacing it", paths, project=project)
            record = {}
        before = dict(record)
        for key in _FIELDS:   # only what is wrong goes: the rest still holds
            try:
                _field(record, key, path)
            except StateError as e:
                log_error("backup", f"{e}; dropping that entry", paths, project=project)
                del record[key]
        change(record)
        if record != before:
            write_state(path, record)


def _update(paths: BoxPaths, project: str | None, what: str,
            change: Callable[[dict[str, Any]], None]) -> None:
    """_change for a backup or a sync: one that cannot be written (or whose
    project name names no record) is reported, and the caller carries on."""
    try:
        _change(paths, project, change)
    except (OSError, InvalidProjectName) as e:
        report_unwritten(paths, project, what, e)


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
        record.pop("unbacked_since", None)
        record.setdefault("unsynced_since", at)
        _clear_failure(record)
    _update(paths, project, f"the snapshot {name}", change)


def record_excused(paths: BoxPaths, project: str, now: datetime | None = None) -> None:
    """A scheduled backup rightly took no snapshot."""
    at = _now(now)

    def change(record: dict[str, Any]) -> None:
        record["excused_at"] = at
        record.pop("unbacked_since", None)
        _clear_failure(record)
    _update(paths, project, "that tonight's backup was rightly skipped", change)


def record_failure(paths: BoxPaths, project: str, cause: str,
                   now: datetime | None = None) -> None:
    """A scheduled backup failed. `failing_since` keeps the first failure's time."""
    at = _now(now)
    _update(paths, project, f"the failed scheduled backup ({cause})",
            lambda record: _set_failure(record, cause, at))


def record_synced(paths: BoxPaths, projects: list[str], started: datetime,
                  now: datetime | None = None) -> None:
    """A sync that began at `started` copied these projects' snapshots. One
    published after it began may have been missed: it still awaits a copy."""
    at = _now(now)

    def change(record: dict[str, Any]) -> None:
        record["synced_at"] = at
        if "snapshot_at" in record and datetime.fromisoformat(record["snapshot_at"]) > started:
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
    _update(paths, None, f"the off-site sync's failure ({cause})" if cause
            else "the off-site sync", change)


def record_sync_not_expected(paths: BoxPaths) -> None:
    """The all-projects sync ran with no remote configured: no off-site
    copy is expected until one runs with a remote again."""
    def change(record: dict[str, Any]) -> None:
        record.pop("expected_since", None)
        _clear_failure(record)
    _update(paths, None, "the sync with no remote", change)


def start_unbacked_clock(paths: BoxPaths, project: str, now: datetime) -> None:
    """A project due a backup has none and no record of one: the 50-hour
    alert measures from now. Raises OSError when that cannot be written."""
    def change(record: dict[str, Any]) -> None:
        record.setdefault("unbacked_since", now.isoformat())
    _change(paths, project, change)


def mark_pending(paths: BoxPaths, project: str | None, alert: str, ref: str) -> None:
    """Record, before it is sent, that the `alert` condition identified by
    `ref` is being sent. It is not yet told: only mark_delivered says so, so
    a run interrupted mid-send is retried. Raises OSError when that cannot
    be written: the sender then knows it could not record the delivery either."""
    def change(record: dict[str, Any]) -> None:
        record["pending"] = {**record.get("pending", {}), alert: ref}
    _change(paths, project, change)


def mark_delivered(paths: BoxPaths, project: str | None, alert: str, ref: str) -> None:
    """A notifier accepted the alert: it is told, and no longer pending.
    Raises OSError."""
    def change(record: dict[str, Any]) -> None:
        record["alerted"] = {**record.get("alerted", {}), alert: ref}
        pending = dict(record.get("pending", {}))
        if pending.get(alert) == ref:
            del pending[alert]
        record["pending"] = pending
    _change(paths, project, change)
