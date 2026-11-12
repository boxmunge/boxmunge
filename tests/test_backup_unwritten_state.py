"""Backup state that cannot be written (a full disk, a directory root owns)
is reported in that run, never fails the backup, and never repeats an alert
every five minutes.

A swallowed write left a project with no record, which read as healthy:
two failed nights told nobody. And a sent-mark that could not be written
re-sent its alert on every health tick. These run the real backup core;
only the dump, age, notify and the state write are stood in for.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import backup_alerts, backup_evidence
from boxmunge.backup import BackupError
from boxmunge.backup_alerts import alert_backups, deliver
from boxmunge.backup_evidence import project_evidence, record_failure
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
    assert check.detail == (f"{paths.backup_state} cannot be written: Permission denied "
                            f"(EACCES): the five-minute backup alerts are held until it can be")
