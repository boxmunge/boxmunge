"""backup-freshness: a warning when a project's newest good backup, or its
off-site copy, is over 26 hours old. Never an error (a platform upgrade in
probation rolls back on one)."""
from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.backup_evidence import (
    record_excused, record_failure, record_snapshot, record_sync_run, record_synced,
)
from boxmunge.commands import health_cmd
from boxmunge.commands.project_delete_cmd import project_state_files
from boxmunge.health_checks.backup_freshness import check_backup_freshness
from tests.backup_alert_helpers import CONFIG, REMOTE, backed_up_project, snapshot_name

P = "shop"
T0 = datetime(2026, 11, 1, 2, 0, tzinfo=timezone.utc)
STORED = snapshot_name(P, "2026-11-01T020000")


def _hours(n: float) -> datetime:
    return T0 + timedelta(hours=n)


@pytest.fixture
def box(paths):
    paths.config_file.write_text(CONFIG)
    backed_up_project(paths, P)
    return paths


def test_nothing_recorded_yet_is_ok(box) -> None:
    check = check_backup_freshness(box, now=T0)
    assert (check.name, check.status, check.detail) == (
        "backup-freshness", "ok", "no backups recorded yet")


def test_a_snapshot_warns_once_it_is_over_26_hours_old(box) -> None:
    backed_up_project(box, "blog")
    record_snapshot(box, P, STORED, now=T0)
    record_snapshot(box, "blog", snapshot_name("blog", "2026-11-02T020000"), now=_hours(24))
    fresh = check_backup_freshness(box, now=_hours(25))
    assert (fresh.status, fresh.detail) == ("ok", "2 project(s) backed up within 26 h")
    stale = check_backup_freshness(box, now=_hours(27))
    assert (stale.status, stale.detail) == ("warn", "shop: no good backup for 27 h")
    assert check_backup_freshness(box, now=_hours(500)).status == "warn"   # never an error


def test_a_failing_scheduled_backup_warns_with_its_cause(box) -> None:
    record_snapshot(box, P, STORED, now=T0)
    record_failure(box, P, "pg_dump: connection to server failed", now=_hours(24))
    check = check_backup_freshness(box, now=_hours(25))
    assert check.status == "warn"
    assert check.detail == ("shop: scheduled backup failing since 2026-11-02 02:00 UTC: "
                            "pg_dump: connection to server failed")
    record_snapshot(box, P, snapshot_name(P, "2026-11-02T030000"), now=_hours(25))
    assert check_backup_freshness(box, now=_hours(26)).status == "ok"


def test_a_night_the_project_was_rightly_not_backed_up_counts_as_good(box) -> None:
    record_snapshot(box, P, STORED, now=T0)
    record_excused(box, P, now=_hours(24))
    assert check_backup_freshness(box, now=_hours(40)).status == "ok"
    assert check_backup_freshness(box, now=_hours(51)).status == "warn"


def test_an_off_site_copy_is_expected_only_with_a_remote(box) -> None:
    record_sync_run(box, None, now=_hours(-1))
    record_snapshot(box, P, STORED, now=T0)
    record_snapshot(box, P, snapshot_name(P, "2026-11-02T020000"), now=_hours(24))
    assert check_backup_freshness(box, now=_hours(27)).status == "ok"

    box.config_file.write_text(CONFIG + REMOTE)
    assert check_backup_freshness(box, now=_hours(25)).status == "ok"
    waiting = check_backup_freshness(box, now=_hours(27))
    assert (waiting.status, waiting.detail) == ("warn", "shop: no off-site copy for 27 h")
    record_synced(box, [P], _hours(27), now=_hours(27))
    assert check_backup_freshness(box, now=_hours(28)).status == "ok"


def test_a_failing_sync_warns_with_its_cause(box) -> None:
    box.config_file.write_text(CONFIG + REMOTE)
    record_sync_run(box, "rclone copy to offsite:bucket failed: quota exceeded", now=T0)
    check = check_backup_freshness(box, now=_hours(1))
    assert check.status == "warn"
    assert "off-site sync failing since 2026-11-01 02:00 UTC" in check.detail
    assert "quota exceeded" in check.detail and "boxmunge backup-sync" in check.detail


def test_a_record_that_cannot_be_read_warns_and_names_the_file(box) -> None:
    box.backup_state.mkdir()
    box.project_backup_state(P).write_text('{"snapshot_at": "yesterday"}')
    check = check_backup_freshness(box, now=T0)
    assert check.status == "warn"
    assert str(box.project_backup_state(P)) in check.detail
    assert "its next backup replaces it" in check.detail
    record_snapshot(box, P, STORED, now=T0)
    assert check_backup_freshness(box, now=_hours(1)).status == "ok"


def test_health_runs_the_check() -> None:
    assert "check_backup_freshness" in inspect.getsource(health_cmd._checks)


def test_project_delete_removes_the_record(paths) -> None:
    assert paths.project_backup_state(P) in project_state_files(paths, P)
