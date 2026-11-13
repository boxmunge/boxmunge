"""Backup state that cannot be written (a full disk, a directory root owns)
is reported in that run, never fails the backup, and never repeats an alert
every five minutes.

A swallowed write left a project with no record, which read as healthy:
two failed nights told nobody. And a sent-mark that could not be written
re-sent its alert on every health tick. These run the real backup core;
only the dump, age, notify and the state write are stood in for.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import backup, backup_alerts, backup_evidence
from boxmunge.backup import BackupError
from boxmunge.backup_alerts import alert_backups, deliver
from boxmunge.backup_evidence import (
    project_evidence, record_excused, record_failure, record_synced,
)
from boxmunge.commands import backup_cmd
from boxmunge.commands.backup_cmd import list_snapshots, run_backup, run_backup_all
from boxmunge.health_checks.backup_freshness import check_backup_freshness
from tests.backup_alert_helpers import Alerts, backed_up_project, no_space, stored_snapshot
from tests.fake_system_container import fake_age

P = "shop"
T0 = datetime(2026, 11, 1, 2, 0, tzinfo=timezone.utc)
CAUSE = "pg_dump: connection to server failed"
UNWRITTEN = ("Backup state cannot be written", 0)
FAILED = ("shop: scheduled backup failed", 0)
STALE = ("shop: no good backup for over 50 hours", 1)

full_disk = patch.object(backup_evidence, "write_state", no_space)


@pytest.fixture
def project(paths, system_container) -> Path:
    system_container.handler = fake_age(paths)
    return backed_up_project(paths, P)


def _dump_fails(*a, **k):
    raise BackupError(CAUSE)


def _dump_works(paths_, project, *a, **k) -> Path:
    raw = paths_.project_backups(project) / ".dump-test"
    raw.write_bytes(b"rows")
    return raw


def _nightly(paths, alerts: Alerts, dump=_dump_fails) -> int:
    with patch.object(backup_cmd, "execute_dump", dump), \
            patch.object(backup_cmd, "notify", alerts):
        return run_backup_all(paths)


def test_each_failed_night_that_cannot_be_recorded_alerts_with_both_causes(
        paths, project) -> None:
    alerts = Alerts()
    with full_disk:
        assert (_nightly(paths, alerts), _nightly(paths, alerts)) == (1, 1)
    assert alerts.titles == [UNWRITTEN] * 2
    for _title, body, _priority in alerts.sent:
        assert "shop: not recorded" in body and CAUSE in body
        assert "No space left on device" in body and str(paths.backup_state) in body
    assert "not recorded" in paths.log_file.read_text()
    check = check_backup_freshness(paths, now=datetime.now(timezone.utc) + timedelta(days=30))
    assert (check.status, check.detail) == ("warn", "shop: no backup yet")


def test_a_good_backup_that_cannot_be_recorded_stands_and_says_so(paths, project) -> None:
    alerts = Alerts()
    with full_disk:
        assert _nightly(paths, alerts, _dump_works) == 0
    [snapshot] = list_snapshots(paths, P)
    [(title, body, _priority)] = alerts.sent
    assert title == UNWRITTEN[0] and f"the snapshot {snapshot.name}" in body
    assert "The backups' own results stand." in body
    assert check_backup_freshness(paths).status == "ok"      # the snapshot is on disk

    assert _nightly(paths, alerts, _dump_works) == 0         # writable again
    assert len(alerts.sent) == 1
    assert project_evidence(paths, P).snapshot in {s.name for s in list_snapshots(paths, P)}


def test_a_backup_by_hand_that_cannot_be_recorded_alerts_at_once(paths, project) -> None:
    alerts = Alerts()
    with full_disk, patch.object(backup_evidence, "notify", alerts), \
            patch.object(backup_cmd, "execute_dump", _dump_works):
        assert run_backup(P, paths) == 0
    assert alerts.titles == [UNWRITTEN] and len(list_snapshots(paths, P)) == 1


def test_backups_that_stop_are_caught_while_nothing_can_be_recorded(paths, project) -> None:
    stored_snapshot(paths, P, T0)
    late = T0 + timedelta(hours=51)
    alerts, unwritten = Alerts(), Alerts()
    with full_disk, patch.object(backup_evidence, "notify", unwritten):
        deliver(paths, alerts, now=late)                     # the nightly run's
    assert alerts.titles == [STALE]
    [(title, body, _priority)] = unwritten.sent
    assert title == UNWRITTEN[0]
    assert "that the alert 'shop: no good backup for over 50 hours' was sent" in body
    assert check_backup_freshness(paths, now=late).detail == "shop: no good backup for 51 h"


def test_the_health_tick_holds_an_alert_it_cannot_mark_as_sent(paths, project) -> None:
    """Sent unmarked, it went out again every five minutes."""
    record_failure(paths, P, CAUSE, now=T0)
    alerts = Alerts()
    with patch.object(backup_alerts, "notify", alerts):
        with full_disk:
            for tick in range(3):
                alert_backups(paths, now=T0 + timedelta(minutes=5 * tick))
        assert alerts.sent == []
        log = paths.log_file.read_text()
        assert log.count("1 backup alert(s) held") == 3
        assert "No space left on device" in log and FAILED[0] in log
        alert_backups(paths, now=T0 + timedelta(minutes=15))  # writable again
        alert_backups(paths, now=T0 + timedelta(minutes=20))
    assert alerts.titles == [FAILED]


def test_an_alert_is_marked_before_it_is_sent_and_unmarked_if_not_delivered(
        paths, project) -> None:
    record_failure(paths, P, CAUSE, now=T0)
    seen = []

    def refused(paths_, title, body, **k) -> bool:
        seen.append(dict(project_evidence(paths_, P).alerted))
        return False

    deliver(paths, refused, now=T0)
    assert seen == [{"failing": T0.isoformat()}]
    assert project_evidence(paths, P).alerted == {}


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_the_check_names_why_the_state_cannot_be_written_without_writing(paths, project) -> None:
    stored_snapshot(paths, P, datetime.now(timezone.utc) - timedelta(hours=1))
    assert check_backup_freshness(paths).status == "ok"      # no directory yet: no problem
    paths.backup_state.mkdir(parents=True)
    paths.backup_state.chmod(0o500)
    try:
        check = check_backup_freshness(paths)
        assert list(paths.backup_state.iterdir()) == []
    finally:
        paths.backup_state.chmod(0o700)
    assert check.status == "warn"
    assert check.detail == (
        f"{paths.backup_state} is not writable by the user running this check "
        f"(uid {os.geteuid()}): backup state may not be recorded, and the five-minute "
        f"backup alerts may be held (the nightly runs still alert)")


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_a_nightly_run_that_cannot_open_the_alerts_lock_still_alerts(paths, project) -> None:
    """No lock file and none can be made (as on a read-only filesystem):
    the run used to stop there and send only the unwritten-state alert."""
    stored_snapshot(paths, P, T0)
    late = T0 + timedelta(hours=51)
    paths.backup_state.mkdir(parents=True)
    paths.backup_state.chmod(0o500)
    alerts, unwritten, ticked = Alerts(), Alerts(), Alerts()
    try:
        with patch.object(backup_evidence, "notify", unwritten):
            deliver(paths, alerts, now=late)
        with patch.object(backup_alerts, "notify", ticked):
            alert_backups(paths, now=late)
    finally:
        paths.backup_state.chmod(0o700)
    assert alerts.titles == [STALE]
    assert {title for title, _priority in unwritten.titles} == {UNWRITTEN[0]}
    assert "Permission denied" in unwritten.sent[0][1]
    assert ticked.sent == []                                  # the tick holds: no storm
    assert "Backup alerts were not checked or sent" in paths.log_file.read_text()


def test_a_lock_that_is_not_a_regular_file_is_named_by_the_check(paths, project) -> None:
    stored_snapshot(paths, P, T0)
    late = T0 + timedelta(hours=51)
    paths.backup_state.mkdir(parents=True)
    lock = paths.backup_state / ".alerts.lock"
    lock.symlink_to("/dev/null")
    ticked, alerts = Alerts(), Alerts()
    with patch.object(backup_alerts, "notify", ticked):
        alert_backups(paths, now=late)
    assert ticked.sent == []
    detail = check_backup_freshness(paths, now=late).detail
    assert f"{lock} is not a regular file" in detail and "may be held" in detail
    with patch.object(backup_evidence, "notify", Alerts()):
        deliver(paths, alerts, now=late)                     # the nightly run goes on
        deliver(paths, alerts, now=late)                     # claimed: said once
    assert alerts.titles == [STALE]


def test_a_snapshot_stored_but_not_confirmed_on_disk_is_said_to_be_there(
        paths, project, capsys) -> None:
    def io_error(directory):
        raise OSError(5, "Input/output error")

    alerts = Alerts()
    with patch.object(backup, "fsync_dir", io_error):
        assert _nightly(paths, alerts, _dump_works) == 1
        capsys.readouterr()
        with patch.object(backup_cmd, "execute_dump", _dump_works):
            assert run_backup(P, paths) == 1
    names = [s.name for s in list_snapshots(paths, P)]
    [nightly] = [n for n in names if "-nightly" in n]
    [by_hand] = [n for n in names if "-manual" in n]
    assert sorted(f.name for f in paths.project_backups(P).iterdir()) == sorted(
        [nightly, by_hand])                                   # no temporary file left
    assert f"The snapshot {by_hand} is in place" in capsys.readouterr().err
    [(title, body, _priority)] = alerts.sent
    assert title == FAILED[0] and "Input/output error" in body
    assert f"The snapshot {nightly} is in place, but it could not be confirmed" in body
    assert "not stored" not in body and "No snapshot is on disk" not in body
    assert project_evidence(paths, P).snapshot == by_hand
    assert "no backup yet" not in check_backup_freshness(paths).detail


def test_a_record_written_while_the_clock_ran_ahead_still_counts(paths, project) -> None:
    """The clock stepped back two hours: the record read as damaged, the
    next change replaced it, and the 50-hour alert went out again."""
    now = datetime.now(timezone.utc)
    stored_snapshot(paths, P, now - timedelta(hours=60))
    alerts = Alerts()
    deliver(paths, alerts)
    assert len(alerts.sent) == 1
    record_synced(paths, [P], now, now=now + timedelta(hours=2))
    claimed = project_evidence(paths, P)
    stored_snapshot(paths, P, now - timedelta(hours=59))      # a new condition to claim
    deliver(paths, alerts)
    deliver(paths, alerts)
    assert len(alerts.sent) == 2
    after = project_evidence(paths, P)
    assert after.synced_at == claimed.synced_at == now + timedelta(hours=2)


def test_a_change_drops_only_the_entries_of_a_record_that_are_wrong(paths, project) -> None:
    record_excused(paths, P, now=T0)
    record_synced(paths, [P], T0, now=T0)
    path = paths.project_backup_state(P)
    path.write_text(json.dumps({**json.loads(path.read_text()),
                                "failing_since": "0001-01-01T00:00:00+12:00",
                                "failure": "planted", "alerted": {"stale": "x"}}))
    record_failure(paths, P, CAUSE, now=T0 + timedelta(hours=24))
    after = project_evidence(paths, P)
    assert (after.excused_at, after.synced_at, after.alerted) == (T0, T0, {"stale": "x"})
    assert (after.failing_since, after.failure) == (T0 + timedelta(hours=24), CAUSE)


def test_a_project_that_was_never_backed_up_gets_the_fifty_hour_alert(paths, project) -> None:
    """No snapshot, no failure, no night skipped: nothing to measure from,
    so it was silent for ever. The clock starts when it is first seen."""
    alerts = Alerts()
    deliver(paths, alerts, now=T0)
    assert alerts.sent == []
    deliver(paths, alerts, now=T0 + timedelta(hours=49))
    assert alerts.sent == []
    deliver(paths, alerts, now=T0 + timedelta(hours=51))
    deliver(paths, alerts, now=T0 + timedelta(hours=75))
    assert alerts.titles == [STALE]
    assert "No snapshot is on disk." in alerts.sent[0][1]


def test_the_tick_starts_that_clock_too_and_a_first_backup_ends_it(paths, project) -> None:
    ticked = Alerts()
    with patch.object(backup_alerts, "notify", ticked):
        alert_backups(paths, now=T0)
        alert_backups(paths, now=T0 + timedelta(hours=51))
    assert ticked.titles == [STALE]
    assert _nightly(paths, Alerts(), _dump_works) == 0
    assert check_backup_freshness(paths).status == "ok"
    assert project_evidence(paths, P).unbacked_since is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_a_never_backed_up_project_whose_clock_cannot_start_is_held_and_named(
        paths, project) -> None:
    paths.backup_state.mkdir(parents=True)
    paths.backup_state.chmod(0o500)
    try:
        with patch.object(backup_alerts, "notify", Alerts()):
            alert_backups(paths, now=T0)
    finally:
        paths.backup_state.chmod(0o700)
    assert "no backup yet" in check_backup_freshness(paths, now=T0).detail


def test_a_temporary_file_that_cannot_be_removed_is_named_not_called_a_flush_failure(
        paths, project, capsys) -> None:
    unlink = Path.unlink

    def stuck(self, *a, **k):
        if self.name.startswith(".encrypt-"):
            raise OSError(1, "Operation not permitted")
        return unlink(self, *a, **k)

    with patch.object(backup.Path, "unlink", stuck):
        with patch.object(backup_cmd, "execute_dump", _dump_works):
            assert run_backup(P, paths) == 1
    err = capsys.readouterr().err
    assert "is in place, but its temporary file" in err and "flushed" not in err
    assert len(list_snapshots(paths, P)) == 1
