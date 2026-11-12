"""A failed scheduled backup reaches the operator, once per continuing failure.

backup-all returned 1 for a failed project and told nobody: the unit failed
in the journal, and the operator learned of it when they needed the
snapshot. These run the real backup core; only the dump, age and notify
are stood in for.
"""
from __future__ import annotations

import errno
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import backup, backup_alerts
from boxmunge.backup import BackupError
from boxmunge.backup_alerts import deliver
from boxmunge.backup_evidence import project_evidence, record_failure
from boxmunge.commands import backup_cmd
from boxmunge.commands.backup_cmd import list_snapshots, run_backup, run_backup_all
from boxmunge.commands.check_all import run_check_all
from boxmunge.health_checks.backup_freshness import check_backup_freshness
from boxmunge.pause import write_paused_state
from tests.backup_alert_helpers import (
    CONFIG, Alerts, backed_up_at, backed_up_project, snapshot_name,
)
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
    assert "No snapshot is on disk." in body
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
    backed_up_at(paths, P, T0)
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
    backed_up_at(paths, P, T0)
    record_failure(paths, P, CAUSE, now=T0 + timedelta(hours=24))
    record_failure(paths, P, CAUSE, now=T0 + timedelta(hours=48))
    alerts = Alerts()
    deliver(paths, alerts, now=T0 + timedelta(hours=51))
    assert alerts.titles == [("shop: scheduled backup failed", 0),
                             ("shop: no good backup for over 50 hours", 1)]
    assert CAUSE in alerts.sent[1][1] and "2026-11-02 02:00 UTC" in alerts.sent[1][1]


def test_a_paused_night_is_not_a_missed_one(paths, project) -> None:
    backed_up_at(paths, P, datetime.now(timezone.utc) - timedelta(hours=60))
    write_paused_state(P, paths)
    alerts = Alerts()
    assert _nightly(paths, alerts) == 0
    assert alerts.sent == []
    check = check_backup_freshness(paths)
    assert (check.status, check.detail) == ("ok", "no project is due a backup")


def test_a_project_with_no_backup_configured_never_alerts_or_warns(paths) -> None:
    backed_up_project(paths, "static", backup="none")
    alerts = Alerts()
    late = datetime.now(timezone.utc) + timedelta(hours=100)
    assert check_backup_freshness(paths, now=late).status == "ok"   # before any nightly
    assert _nightly(paths, alerts) == 0
    deliver(paths, alerts, now=late)
    assert alerts.sent == [] and check_backup_freshness(paths, now=late).status == "ok"


def test_a_record_behind_a_link_is_not_read_and_the_next_backup_replaces_it(
        paths, project, tmp_path) -> None:
    planted = tmp_path / "planted.json"
    planted.write_text(json.dumps({"failing_since": T0.isoformat(), "failure": "planted"}))
    paths.backup_state.mkdir()
    paths.project_backup_state(P).symlink_to(planted)
    alerts = Alerts()
    deliver(paths, alerts)
    assert alerts.sent == []
    assert "Cannot read state file" in check_backup_freshness(paths).detail

    assert _nightly(paths, alerts, _dump_works) == 0
    assert not paths.project_backup_state(P).is_symlink()
    assert project_evidence(paths, P).snapshot == list_snapshots(paths, P)[0].name
    assert json.loads(planted.read_text())["failure"] == "planted"


def test_the_health_tick_sends_what_is_due_and_one_bad_record_does_not_stop_it(
        paths, project) -> None:
    """check-all as root's timer runs it. The first project's record holds a
    time that overflows when compared: the tick used to end there."""
    paths.config_file.write_text(CONFIG)
    backed_up_project(paths, "blog")
    for name in ("blog", P):
        write_paused_state(name, paths)         # nothing for the tick to smoke-test
    record_failure(paths, P, CAUSE)
    paths.project_backup_state("blog").write_text(json.dumps(
        {"failing_since": "0001-01-01T00:00:00+12:00", "failure": "planted"}))
    alerts = Alerts()
    with patch.object(backup_alerts, "notify", alerts):
        run_check_all(paths, read_only=True)    # `boxmunge check-all --read-only`
        assert alerts.sent == []
        run_check_all(paths, read_only=False)
        run_check_all(paths, read_only=False)
    assert alerts.titles == [("shop: scheduled backup failed", 0)]


def _no_link_for(project: str):
    link = os.link

    def refusing(src, dst, **k):
        if f"/{project}/" in str(dst):
            raise PermissionError(errno.EPERM, "Operation not permitted")
        return link(src, dst, **k)
    return refusing


def test_a_snapshot_the_filesystem_will_not_name_fails_that_backup_alone(
        paths, project, capsys) -> None:
    backed_up_project(paths, "blog")
    alerts = Alerts()
    with patch.object(backup.os, "link", _no_link_for(P)):
        assert _nightly(paths, alerts, _dump_works) == 1
        assert list(paths.project_backups(P).iterdir()) == []
        capsys.readouterr()
        with patch.object(backup_cmd, "execute_dump", _dump_works):
            assert run_backup(P, paths) == 1    # by hand: an error, not a traceback
        by_hand = capsys.readouterr().err
    assert "ERROR" in by_hand and "Operation not permitted" in by_hand
    assert "Nothing was stored" in by_hand
    [(title, body, _priority)] = alerts.sent
    assert title == "shop: scheduled backup failed"
    assert "Cannot give the snapshot its name" in body and "Operation not permitted" in body
    assert len(list_snapshots(paths, "blog")) == 1
    assert project_evidence(paths, P).failing_since is not None

    # The next night the filesystem allows it: one snapshot, nothing left over.
    assert _nightly(paths, alerts, _dump_works) == 0
    [snapshot] = list_snapshots(paths, P)
    assert [f.name for f in paths.project_backups(P).iterdir()] == [snapshot.name]
    assert project_evidence(paths, P).failing_since is None
    assert len(alerts.sent) == 1 and check_backup_freshness(paths).status == "ok"
