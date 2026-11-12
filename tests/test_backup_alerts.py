"""A failed scheduled backup reaches the operator, once per continuing failure.

backup-all returned 1 for a failed project and told nobody: the unit failed
in the journal, and the operator learned of it when they needed the
snapshot. These run the real backup core; only the dump, age and notify
are stood in for.
"""
from __future__ import annotations

import inspect
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import backup_alerts
from boxmunge.backup import BackupError
from boxmunge.backup_alerts import deliver
from boxmunge.backup_evidence import project_evidence, record_failure, record_snapshot
from boxmunge.commands import backup_cmd, check_all
from boxmunge.commands.backup_cmd import list_snapshots, run_backup, run_backup_all
from boxmunge.health_checks.backup_freshness import check_backup_freshness
from boxmunge.pause import write_paused_state
from tests.backup_alert_helpers import Alerts, backed_up_project, snapshot_name
from tests.fake_system_container import fake_age

P = "shop"
T0 = datetime(2026, 11, 1, 2, 0, tzinfo=timezone.utc)
STORED = snapshot_name(P, "2026-11-01T020000")
CAUSE = "pg_dump: connection to server failed"


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


def test_a_failed_nightly_backup_alerts_with_the_project_and_the_cause(paths, project) -> None:
    alerts = Alerts()
    assert _nightly(paths, alerts) == 1
    [(title, body, priority)] = alerts.sent
    assert (title, priority) == ("shop: scheduled backup failed", 0)
    assert CAUSE in body
    assert "No good snapshot is recorded." in body
    assert "boxmunge backup shop" in body


def test_a_failure_that_continues_alerts_once(paths, project) -> None:
    alerts = Alerts()
    _nightly(paths, alerts)
    began = project_evidence(paths, P).failing_since
    _nightly(paths, alerts)
    deliver(paths, alerts)                      # check-all's five-minute tick
    assert len(alerts.sent) == 1
    after = project_evidence(paths, P)
    assert after.failing_since == began and after.failed_at > began


def test_an_alert_that_was_not_delivered_is_tried_again_until_it_is(paths, project) -> None:
    alerts = Alerts()
    alerts.delivers = False
    _nightly(paths, alerts)
    assert len(alerts.sent) == 1 and project_evidence(paths, P).alerted == {}
    deliver(paths, alerts)                      # Pushover still refuses
    assert len(alerts.sent) == 2
    alerts.delivers = True
    deliver(paths, alerts)
    assert len(alerts.sent) == 3
    deliver(paths, alerts)                      # delivered: said once
    assert len(alerts.sent) == 3
    assert alerts.sent[1:] == alerts.sent[:2]


def test_a_good_backup_ends_the_failure_and_a_later_one_alerts_again(paths, project) -> None:
    alerts = Alerts()
    _nightly(paths, alerts)
    assert _nightly(paths, alerts, _dump_works) == 0
    [snapshot] = list_snapshots(paths, P)
    good = project_evidence(paths, P)
    assert good.snapshot == snapshot.name
    assert (good.failing_since, good.failure) == (None, None)
    deliver(paths, alerts)
    assert len(alerts.sent) == 1

    _nightly(paths, alerts)
    assert alerts.titles == [("shop: scheduled backup failed", 0)] * 2
    assert f"Newest good snapshot: {snapshot.name}" in alerts.sent[1][1]


def test_a_backup_run_by_hand_that_works_ends_the_failure(paths, project) -> None:
    alerts = Alerts()
    _nightly(paths, alerts)
    with patch.object(backup_cmd, "execute_dump", _dump_works):
        assert run_backup(P, paths) == 0
    assert project_evidence(paths, P).failing_since is None
    assert check_backup_freshness(paths).status == "ok"


def test_a_manifest_that_cannot_be_read_alerts_and_the_other_project_is_backed_up(
        paths, project) -> None:
    backed_up_project(paths, "blog")
    (project / "manifest.yml").write_text("project: [unclosed\n")
    alerts = Alerts()
    assert _nightly(paths, alerts, _dump_works) == 1
    assert alerts.titles == [("shop: scheduled backup failed", 0)]
    assert len(list_snapshots(paths, "blog")) == 1


def test_two_missed_nights_alert_at_priority_one_once(paths, project) -> None:
    record_snapshot(paths, P, STORED, now=T0)
    alerts = Alerts()
    deliver(paths, alerts, now=T0 + timedelta(hours=49))
    assert alerts.sent == []
    alerts.delivers = False
    deliver(paths, alerts, now=T0 + timedelta(hours=51))
    alerts.delivers = True
    deliver(paths, alerts, now=T0 + timedelta(hours=51, minutes=5))
    deliver(paths, alerts, now=T0 + timedelta(hours=75))
    assert alerts.titles == [("shop: no good backup for over 50 hours", 1)] * 2
    assert STORED in alerts.sent[0][1]


def test_a_backup_failing_for_two_nights_says_so_in_the_stale_alert(paths, project) -> None:
    record_snapshot(paths, P, STORED, now=T0)
    record_failure(paths, P, CAUSE, now=T0 + timedelta(hours=24))
    record_failure(paths, P, CAUSE, now=T0 + timedelta(hours=48))
    alerts = Alerts()
    deliver(paths, alerts, now=T0 + timedelta(hours=51))
    assert alerts.titles == [("shop: scheduled backup failed", 0),
                             ("shop: no good backup for over 50 hours", 1)]
    assert CAUSE in alerts.sent[1][1] and "2026-11-02 02:00 UTC" in alerts.sent[1][1]


def test_a_paused_night_is_not_a_missed_one(paths, project) -> None:
    record_snapshot(paths, P, STORED, now=datetime.now(timezone.utc) - timedelta(hours=60))
    write_paused_state(P, paths)
    alerts = Alerts()
    assert _nightly(paths, alerts) == 0
    assert alerts.sent == []
    assert check_backup_freshness(paths).status == "ok"


def test_a_project_with_no_backup_configured_has_no_record_and_never_alerts(paths) -> None:
    backed_up_project(paths, "static", backup="none")
    alerts = Alerts()
    assert _nightly(paths, alerts) == 0
    deliver(paths, alerts, now=datetime.now(timezone.utc) + timedelta(hours=100))
    assert alerts.sent == [] and not paths.project_backup_state("static").exists()


def test_a_record_behind_a_link_is_not_read_and_the_next_backup_replaces_it(
        paths, project, tmp_path) -> None:
    planted = tmp_path / "planted.json"
    planted.write_text(json.dumps({"failing_since": T0.isoformat(), "failure": "planted"}))
    paths.backup_state.mkdir()
    paths.project_backup_state(P).symlink_to(planted)
    alerts = Alerts()
    deliver(paths, alerts)
    assert alerts.sent == []
    assert "Cannot read state file" in paths.log_file.read_text()

    assert _nightly(paths, alerts, _dump_works) == 0
    assert not paths.project_backup_state(P).is_symlink()
    assert project_evidence(paths, P).snapshot == list_snapshots(paths, P)[0].name
    assert json.loads(planted.read_text())["failure"] == "planted"


def test_check_all_sends_what_is_due(paths, project) -> None:
    record_failure(paths, P, CAUSE)
    alerts = Alerts()
    with patch.object(backup_alerts, "notify", alerts):
        backup_alerts.alert_backups(paths)
        backup_alerts.alert_backups(paths)
    assert alerts.titles == [("shop: scheduled backup failed", 0)]
    assert "alert_backups" in inspect.getsource(check_all.run_check_all)
