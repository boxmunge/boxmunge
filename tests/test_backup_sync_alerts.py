"""The nightly off-site sync reaches the operator when it fails, and a
snapshot that waits two nights for its copy does too.

rclone runs in the stood-in system container; notify is stood in for.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

import boxmunge.system_container as sc
from boxmunge.backup_alerts import deliver
from boxmunge.backup_evidence import (
    Evidence, project_evidence, record_excused, record_snapshot, record_sync_run, record_synced,
    sync_evidence,
)
from boxmunge.commands import backup_sync_cmd
from boxmunge.commands.backup_sync_cmd import run_backup_sync
from boxmunge.health_checks.backup_freshness import check_backup_freshness
from tests.backup_alert_helpers import (
    CONFIG, REMOTE, Alerts, backed_up_at, backed_up_project, snapshot_name,
)

P = "shop"
T0 = datetime(2026, 11, 1, 2, 0, tzinfo=timezone.utc)
FIRST, SECOND = (snapshot_name(P, f"2026-11-0{day}T020000") for day in (1, 3))
UNSYNCED = ("shop: no off-site copy for over 50 hours", 1)
SYNC_FAILED = ("Off-site backup sync failed", 0)


def _ok(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def _rclone_fails(cmd: list[str]):
    raise sc.SystemContainerError("Command failed in system container: rclone: quota exceeded")


@pytest.fixture
def box(paths, system_container):
    """A box with backup_remote set, one project, and an rclone that works."""
    paths.config_file.write_text(CONFIG + REMOTE)
    backed_up_project(paths, P)
    system_container.handler = _ok
    return paths


def _sync(paths, alerts: Alerts, project: str | None = None) -> int:
    with patch.object(backup_sync_cmd, "notify", alerts):
        return run_backup_sync(paths, project)


def _two_snapshots_after_a_sync(paths) -> None:
    """The scheduled sync ran, then two nights' snapshots were published:
    the first still waits for its copy, and the newest is recent."""
    record_sync_run(paths, None, now=T0 - timedelta(hours=1))
    backed_up_at(paths, P, T0)
    backed_up_at(paths, P, T0 + timedelta(hours=48))


def test_a_failed_nightly_sync_alerts_once_with_the_cause(box, system_container) -> None:
    system_container.handler = _rclone_fails
    alerts = Alerts()
    assert _sync(box, alerts) == 1
    assert _sync(box, alerts) == 1
    [(title, body, priority)] = alerts.sent
    assert (title, priority) == SYNC_FAILED
    assert "quota exceeded" in body and "No good sync is recorded." in body
    assert "boxmunge backup-sync" in body
    assert check_backup_freshness(box).status == "warn"


def test_a_sync_alert_that_was_not_delivered_is_tried_again(box, system_container) -> None:
    system_container.handler = _rclone_fails
    alerts = Alerts()
    alerts.delivers = False
    _sync(box, alerts)
    deliver(box, alerts)                        # check-all's tick: still refused
    alerts.delivers = True
    deliver(box, alerts)
    deliver(box, alerts)
    assert alerts.titles == [SYNC_FAILED] * 3


def test_a_good_sync_ends_the_failure_and_a_later_one_alerts_again(
        box, system_container) -> None:
    alerts = Alerts()
    backed_up_at(box, P, datetime.now(timezone.utc) - timedelta(hours=1))
    system_container.handler = _rclone_fails
    _sync(box, alerts)
    assert "shop: no successful off-site sync recorded yet" in check_backup_freshness(box).detail
    system_container.handler = _ok
    assert _sync(box, alerts) == 0
    good = sync_evidence(box)
    assert good.failing_since is None and good.synced_at is not None
    assert check_backup_freshness(box).status == "ok"
    deliver(box, alerts)
    assert alerts.titles == [SYNC_FAILED]

    system_container.handler = _rclone_fails
    _sync(box, alerts)
    assert alerts.titles == [SYNC_FAILED] * 2
    assert "Last good sync: " in alerts.sent[1][1]


def test_a_one_project_sync_that_fails_is_the_operators_to_read(box, system_container) -> None:
    system_container.handler = _rclone_fails
    alerts = Alerts()
    assert _sync(box, alerts, P) == 1
    assert alerts.sent == [] and sync_evidence(box) == Evidence()


def test_a_snapshot_with_no_off_site_copy_for_two_nights_alerts_until_one_is_made(box) -> None:
    _two_snapshots_after_a_sync(box)
    alerts = Alerts()
    deliver(box, alerts, now=T0 + timedelta(hours=49))
    assert alerts.sent == []
    alerts.delivers = False
    deliver(box, alerts, now=T0 + timedelta(hours=51))
    alerts.delivers = True
    deliver(box, alerts, now=T0 + timedelta(hours=51, minutes=5))
    deliver(box, alerts, now=T0 + timedelta(hours=52))
    assert alerts.titles == [UNSYNCED] * 2
    assert "No off-site copy of shop is recorded." in alerts.sent[0][1]
    assert "boxmunge backup-sync" in alerts.sent[0][1]

    assert _sync(box, alerts) == 0              # the copy is made
    copied = project_evidence(box, P)
    assert copied.unsynced_since is None and copied.synced_at is not None
    deliver(box, alerts, now=datetime.now(timezone.utc) + timedelta(hours=100))
    assert [title for title, _p in alerts.titles[2:]] == [
        "shop: no good backup for over 50 hours"]      # nothing about the off-site copy


def test_a_one_project_sync_records_that_projects_copy_only(box) -> None:
    record_snapshot(box, P, FIRST, now=T0)
    assert _sync(box, Alerts(), P) == 0
    assert project_evidence(box, P).unsynced_since is None
    assert sync_evidence(box) == Evidence()     # not the scheduled sync: nothing expected yet


def test_a_snapshot_published_while_the_sync_ran_still_awaits_its_copy(box) -> None:
    record_snapshot(box, P, FIRST, now=T0)
    record_synced(box, [P], T0 - timedelta(minutes=1), now=T0 + timedelta(minutes=1))
    during = project_evidence(box, P)
    assert (during.unsynced_since, during.synced_at) == (T0, T0 + timedelta(minutes=1))
    record_synced(box, [P], T0 + timedelta(hours=1), now=T0 + timedelta(hours=1, minutes=1))
    assert project_evidence(box, P).unsynced_since is None


def test_with_no_remote_no_off_site_copy_is_expected(box) -> None:
    _two_snapshots_after_a_sync(box)
    box.config_file.write_text(CONFIG)
    alerts = Alerts()
    late = T0 + timedelta(hours=60)
    deliver(box, alerts, now=late)
    assert alerts.sent == [] and check_backup_freshness(box, now=late).status == "ok"
    # The nightly timer runs backup-sync on every box: no remote is not a failure.
    assert _sync(box, alerts) == 1
    assert alerts.sent == [] and sync_evidence(box).failing_since is None


def test_a_remote_set_later_starts_the_clock_at_its_first_scheduled_sync(box) -> None:
    """A box that ran for months with no remote has old snapshots with no
    copy: setting backup_remote must not alert for each of them at once."""
    backed_up_at(box, P, T0 - timedelta(hours=500))
    record_excused(box, P, now=T0 + timedelta(hours=40))   # keeps the 50-hour backup alert out of this
    alerts = Alerts()
    deliver(box, alerts, now=T0)                # remote set, no sync has run with it
    record_sync_run(box, "rclone copy to offsite:bucket failed", now=T0)
    deliver(box, alerts, now=T0 + timedelta(hours=49))
    assert alerts.titles == [SYNC_FAILED]
    deliver(box, alerts, now=T0 + timedelta(hours=51))
    assert alerts.titles == [SYNC_FAILED, UNSYNCED]


def test_a_config_that_cannot_be_read_fails_the_sync_and_records_nothing(box, capsys) -> None:
    box.config_file.write_text("hostname: [unclosed\n")
    alerts = Alerts()
    assert _sync(box, alerts) == 1
    assert "ERROR" in capsys.readouterr().err
    assert alerts.sent == [] and not box.backup_sync_state.exists()
