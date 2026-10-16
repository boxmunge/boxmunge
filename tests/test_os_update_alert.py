# SPDX-License-Identifier: Apache-2.0
"""OS update failures alert the operator from the auto-update timer run."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from boxmunge.os_update_alert import read_os_update_state, record_os_updates
from boxmunge.os_updates import OsUpdateStatus, Problem
from boxmunge.paths import BoxPaths

T0 = datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc)
STALE = Problem("stamp:stale", "package lists last refreshed successfully 3d 0h ago",
                "as root, `apt-get update` shows the failing source")
STALE_LATER = Problem("stamp:stale", "package lists last refreshed successfully 3d 6h ago",
                      "as root, `apt-get update` shows the failing source")
UNIT = Problem("unit:apt-daily.service:exit-code", "last apt-daily.service run failed",
               "`journalctl -u apt-daily.service` shows why")
HEALTHY = OsUpdateStatus(problems=(), stamp_age=timedelta(hours=3))


def _broken(*problems: Problem) -> OsUpdateStatus:
    return OsUpdateStatus(problems=problems)


def _log(paths: BoxPaths) -> list[dict]:
    if not paths.log_file.exists():
        return []
    return [json.loads(line) for line in paths.log_file.read_text().splitlines() if line]


class _Notify:
    def __init__(self, delivered=True):
        self.delivered = delivered
        self.calls: list[dict] = []

    def __call__(self, paths, title, body, **kwargs):
        self.calls.append({"title": title, "body": body, **kwargs})
        return self.delivered


def _record(paths, status, now=T0, delivered=True) -> _Notify:
    notify = _Notify(delivered)
    with patch("boxmunge.os_update_alert.notify", notify):
        record_os_updates(paths, status, now=now)
    return notify


def test_problem_alerts_at_priority_one_and_is_recorded(paths):
    notify = _record(paths, _broken(STALE))
    assert len(notify.calls) == 1
    call = notify.calls[0]
    assert call["priority"] == 1 and call["component"] == "auto-update"
    assert "OS updates" in call["title"]
    assert "3d 0h ago" in call["body"] and "`apt-get update`" in call["body"]
    state = read_os_update_state(paths)
    assert state["problems"] == ["stamp:stale"]
    assert state["alerted"] == {"problems": ["stamp:stale"], "at": T0.isoformat()}


def test_problem_is_logged_as_a_warning_every_run(paths):
    _record(paths, _broken(STALE))
    _record(paths, _broken(STALE_LATER), now=T0 + timedelta(hours=6))
    warnings = [e for e in _log(paths) if e["level"] == "warn" and "OS updates" in e["msg"]]
    assert len(warnings) == 2


def test_same_problem_with_new_wording_does_not_realert_within_a_day(paths):
    _record(paths, _broken(STALE))
    notify = _record(paths, _broken(STALE_LATER), now=T0 + timedelta(hours=23, minutes=59))
    assert notify.calls == []
    assert read_os_update_state(paths)["alerted"]["at"] == T0.isoformat()


def test_reminds_after_a_day(paths):
    _record(paths, _broken(STALE))
    later = T0 + timedelta(hours=24)
    notify = _record(paths, _broken(STALE_LATER), now=later)
    assert len(notify.calls) == 1
    assert read_os_update_state(paths)["alerted"]["at"] == later.isoformat()


def test_a_changed_set_of_problems_alerts_at_once(paths):
    _record(paths, _broken(STALE))
    notify = _record(paths, _broken(STALE, UNIT), now=T0 + timedelta(hours=6))
    assert len(notify.calls) == 1
    assert read_os_update_state(paths)["alerted"]["problems"] == [
        "stamp:stale", "unit:apt-daily.service:exit-code"]


def test_undelivered_alert_is_not_recorded_and_retried_next_run(paths):
    notify = _record(paths, _broken(STALE), delivered=False)
    assert len(notify.calls) == 1
    assert read_os_update_state(paths)["alerted"] is None
    assert any("not delivered" in e["msg"] for e in _log(paths))
    assert len(_record(paths, _broken(STALE), now=T0 + timedelta(hours=6)).calls) == 1


def test_recovery_clears_state_and_is_logged(paths):
    _record(paths, _broken(STALE))
    notify = _record(paths, HEALTHY, now=T0 + timedelta(hours=6))
    assert notify.calls == []
    state = read_os_update_state(paths)
    assert state["problems"] == [] and state["alerted"] is None
    assert any("working again" in e["msg"] for e in _log(paths))
    # Broken again later: a fresh alert.
    assert len(_record(paths, _broken(STALE), now=T0 + timedelta(hours=12)).calls) == 1


def test_healthy_box_sends_nothing(paths):
    assert _record(paths, HEALTHY).calls == []
    assert read_os_update_state(paths)["problems"] == []


def test_corrupt_state_is_reported_and_replaced(paths):
    paths.os_update_state.parent.mkdir(parents=True, exist_ok=True)
    paths.os_update_state.write_text("{not json")
    notify = _record(paths, _broken(STALE))
    assert len(notify.calls) == 1
    assert read_os_update_state(paths)["alerted"]["problems"] == ["stamp:stale"]
    errors = [e for e in _log(paths) if e["level"] == "error"]
    assert errors and "os-updates.json" in errors[0]["msg"]


def test_auto_update_run_checks_os_updates_before_discovery(paths, monkeypatch):
    """`health` is not scheduled; the auto-update timer is the alerting path."""
    from boxmunge.commands.auto_update_cmd import run_auto_update
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    monkeypatch.setattr("boxmunge.os_updates.inspect_os_updates", lambda: _broken(STALE))
    notify = _Notify()
    with patch("boxmunge.os_update_alert.notify", notify), \
            patch("boxmunge.upgrade_discovery.discover_update") as discover:
        discover.return_value = {"action": "up_to_date", "current_version": "0.3.5",
                                 "blocked": None, "source": "endpoint"}
        assert run_auto_update(paths) == 0
    assert len(notify.calls) == 1
    assert read_os_update_state(paths)["problems"] == ["stamp:stale"]
