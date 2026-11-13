"""backup-freshness: a warning when a project due a backup has no snapshot
on disk or none within 26 hours, or its off-site copy is as late. Never an
error (a platform upgrade in probation rolls back on one)."""
from __future__ import annotations

import inspect
import json
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.backup_alerts import deliver
from boxmunge.backup_evidence import (
    record_excused, record_failure, record_sync_run, record_synced,
)
from boxmunge.commands import health_cmd
from boxmunge.commands.project_delete_cmd import project_state_files
from boxmunge.health_checks.backup_freshness import check_backup_freshness
from tests.backup_alert_helpers import (
    CONFIG, REMOTE, Alerts, backed_up_at, backed_up_project, stored_snapshot,
)

P = "shop"
T0 = datetime(2026, 11, 1, 2, 0, tzinfo=timezone.utc)


def _hours(n: float) -> datetime:
    return T0 + timedelta(hours=n)


@pytest.fixture
def box(paths):
    paths.config_file.write_text(CONFIG)
    backed_up_project(paths, P)
    return paths


def test_a_project_due_a_backup_with_no_snapshot_is_named_never_ok(box) -> None:
    """No record used to mean healthy, for as long as none was written."""
    check = check_backup_freshness(box, now=T0)
    assert (check.name, check.status, check.detail) == (
        "backup-freshness", "warn", "shop: no backup yet")
    assert check_backup_freshness(box, now=_hours(24 * 30)).detail == "shop: no backup yet"
    backed_up_project(box, "blog")
    backed_up_at(box, "blog", T0)
    assert check_backup_freshness(box, now=_hours(1)).detail == "shop: no backup yet"


def test_a_box_upgraded_with_yesterdays_snapshot_is_fresh_until_its_backups_stop(box) -> None:
    """The snapshot on disk is the evidence: no record is needed."""
    name = stored_snapshot(box, P, T0)
    fresh = check_backup_freshness(box, now=_hours(25))
    assert (fresh.status, fresh.detail) == ("ok", "1 project(s) backed up within 26 h")
    assert check_backup_freshness(box, now=_hours(27)).detail == "shop: no good backup for 27 h"
    alerts = Alerts()
    deliver(box, alerts, now=_hours(49))
    assert alerts.sent == []
    deliver(box, alerts, now=_hours(51))
    assert alerts.titles == [("shop: no good backup for over 50 hours", 1)]
    assert name in alerts.sent[0][1]


def test_a_snapshot_warns_once_it_is_over_26_hours_old(box) -> None:
    backed_up_project(box, "blog")
    backed_up_at(box, P, T0)
    backed_up_at(box, "blog", _hours(24))
    fresh = check_backup_freshness(box, now=_hours(25))
    assert (fresh.status, fresh.detail) == ("ok", "2 project(s) backed up within 26 h")
    stale = check_backup_freshness(box, now=_hours(27))
    assert (stale.status, stale.detail) == ("warn", "shop: no good backup for 27 h")
    assert check_backup_freshness(box, now=_hours(500)).status == "warn"   # never an error


def test_a_failing_scheduled_backup_warns_with_its_cause_until_a_snapshot_is_taken(box) -> None:
    backed_up_at(box, P, T0)
    record_failure(box, P, "pg_dump: connection to server failed", now=_hours(24))
    check = check_backup_freshness(box, now=_hours(25))
    assert check.status == "warn"
    assert check.detail == ("shop: scheduled backup failing since 2026-11-02 02:00 UTC: "
                            "pg_dump: connection to server failed")
    stored_snapshot(box, P, _hours(25))         # taken, even if it could not be recorded
    assert check_backup_freshness(box, now=_hours(26)).status == "ok"


def test_a_night_the_project_was_rightly_not_backed_up_counts_as_good(box) -> None:
    backed_up_at(box, P, T0)
    record_excused(box, P, now=_hours(24))
    assert check_backup_freshness(box, now=_hours(40)).status == "ok"
    assert check_backup_freshness(box, now=_hours(51)).status == "warn"


def test_an_off_site_copy_is_expected_only_with_a_remote(box) -> None:
    record_sync_run(box, None, now=_hours(-1))
    backed_up_at(box, P, T0)
    assert check_backup_freshness(box, now=_hours(1)).status == "ok"

    box.config_file.write_text(CONFIG + REMOTE)
    first = check_backup_freshness(box, now=_hours(1))
    assert (first.status, first.detail) == (
        "warn", "shop: no successful off-site sync recorded yet")
    record_synced(box, [P], _hours(1), now=_hours(1))
    assert check_backup_freshness(box, now=_hours(2)).status == "ok"

    backed_up_at(box, P, _hours(24))            # this one waits for its copy
    backed_up_at(box, P, _hours(48))
    assert check_backup_freshness(box, now=_hours(49)).status == "ok"
    waiting = check_backup_freshness(box, now=_hours(51))
    assert (waiting.status, waiting.detail) == ("warn", "shop: no off-site copy for 27 h")
    record_synced(box, [P], _hours(51), now=_hours(51))
    assert check_backup_freshness(box, now=_hours(52)).status == "ok"


def test_a_failing_sync_warns_with_its_cause(box) -> None:
    box.config_file.write_text(CONFIG + REMOTE)
    record_sync_run(box, "rclone copy to offsite:bucket failed: quota exceeded", now=T0)
    check = check_backup_freshness(box, now=_hours(1))
    assert check.status == "warn"
    assert "off-site sync failing since 2026-11-01 02:00 UTC" in check.detail
    assert "quota exceeded" in check.detail and "boxmunge backup-sync" in check.detail


AHEAD = "2099-01-01T00:00:00+00:00"   # a fixed value: ids must match across xdist workers


@pytest.mark.parametrize("recorded", [
    "yesterday",
    "2026-11-01T02:00:00",              # no timezone
    "0001-01-01T00:00:00+12:00",        # overflows when compared
    "9999-12-31T23:59:59-12:00",
    "2019-12-31T23:59:59+00:00",        # before any boxmunge backup
    AHEAD,                              # would keep the project fresh until then
])
def test_a_record_that_cannot_be_read_warns_for_that_project_alone(box, recorded) -> None:
    backed_up_project(box, "blog")
    backed_up_at(box, "blog", T0)
    box.project_backup_state(P).write_text(json.dumps(
        {"snapshot_at": recorded, "failing_since": recorded, "failure": "planted"}))
    alerts = Alerts()
    deliver(box, alerts, now=_hours(1))
    assert alerts.sent == []
    check = check_backup_freshness(box, now=_hours(1))
    assert check.status == "warn" and "blog" not in check.detail
    assert str(box.project_backup_state(P)) in check.detail
    assert "its next backup replaces it" in check.detail
    backed_up_at(box, P, T0)
    assert check_backup_freshness(box, now=_hours(1)).status == "ok"
    deliver(box, alerts, now=_hours(51))        # the other project was still judged
    assert sorted(alerts.titles) == [("blog: no good backup for over 50 hours", 1),
                                     ("shop: no good backup for over 50 hours", 1)]


def test_health_runs_the_check() -> None:
    assert "check_backup_freshness" in inspect.getsource(health_cmd._checks)


def test_project_delete_removes_the_record(paths) -> None:
    assert paths.project_backup_state(P) in project_state_files(paths, P)
