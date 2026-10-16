# SPDX-License-Identifier: Apache-2.0
"""Blocked platform updates: the operator alert and its persisted state."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from boxmunge.blocked_update import (
    BlockedStateError,
    alert_text,
    read_blocked_state,
    record_blocked,
)
from boxmunge.paths import BoxPaths

GH = "https://github.com/boxmunge/boxmunge/releases/tag/v"
T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _blocked(version="0.11.2", cls="security", reason=None):
    return {"version": version, "url": f"{GH}{version}", "class": cls,
            "reason": reason or {"breaking_release": "0.11.0"}}


def _result(blocked, current="0.10.3", source="endpoint"):
    return {"action": "up_to_date", "current_version": current, "blocked": blocked,
            "source": source}


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


def _record(paths, blocked, now=T0, delivered=True, current="0.10.3"):
    notify = _Notify(delivered)
    with patch("boxmunge.blocked_update.notify", notify):
        record_blocked(paths, _result(blocked, current), now=now)
    return notify


class TestAlertText:
    def test_breaking_release_between(self):
        title, body = alert_text(_blocked(), "0.10.3")
        assert body.startswith(
            "Security release 0.11.2 cannot be installed automatically: 0.11.0 between "
            "this box (0.10.3) and it is a breaking release. Read the release notes, "
            "then run `upgrade`.")
        assert f"{GH}0.11.2" in body
        assert "0.11.2" in title

    def test_breakfix_class_word(self):
        _, body = alert_text(_blocked(cls="breakfix"), "0.10.3")
        assert body.startswith("Break-fix release 0.11.2 cannot be installed automatically")

    def test_candidate_itself_breaking(self):
        blocked = _blocked("0.11.0", reason={"breaking_release": "0.11.0"})
        _, body = alert_text(blocked, "0.10.3")
        assert ("Security release 0.11.0 cannot be installed automatically: it is a "
                "breaking release, and this box runs 0.10.3.") in body

    def test_major_version(self):
        _, body = alert_text(_blocked("1.0.1", reason={"major": 1}), "0.12.2")
        assert ("Security release 1.0.1 cannot be installed automatically: it is in major "
                "version 1 and this box runs 0.12.2") in body
        assert "run `upgrade`" in body


class TestAlerting:
    def test_alerts_once_at_priority_one_and_records_it(self, paths):
        notify = _record(paths, _blocked())
        assert len(notify.calls) == 1
        assert notify.calls[0]["priority"] == 1
        assert notify.calls[0]["component"] == "auto-update"
        state = read_blocked_state(paths)
        assert state["blocked"] == _blocked()
        assert state["current_version"] == "0.10.3"
        assert state["alerted"] == {"version": "0.11.2", "at": T0.isoformat()}

    def test_no_repeat_within_a_day(self, paths):
        _record(paths, _blocked())
        notify = _record(paths, _blocked(), now=T0 + timedelta(hours=23, minutes=59))
        assert notify.calls == []
        assert read_blocked_state(paths)["alerted"]["at"] == T0.isoformat()
        assert any("already sent" in e["msg"] for e in _log(paths))

    def test_reminds_after_a_day(self, paths):
        _record(paths, _blocked())
        later = T0 + timedelta(hours=24)
        notify = _record(paths, _blocked(), now=later)
        assert len(notify.calls) == 1
        assert read_blocked_state(paths)["alerted"]["at"] == later.isoformat()

    def test_new_blocked_version_alerts_at_once(self, paths):
        _record(paths, _blocked())
        notify = _record(paths, _blocked("0.11.3"), now=T0 + timedelta(hours=6))
        assert len(notify.calls) == 1
        assert read_blocked_state(paths)["alerted"]["version"] == "0.11.3"

    def test_undelivered_alert_is_retried_next_run(self, paths):
        notify = _record(paths, _blocked(), delivered=False)
        assert len(notify.calls) == 1
        state = read_blocked_state(paths)
        assert state["blocked"] == _blocked()
        assert state["alerted"] is None
        assert any("not delivered" in e["msg"] for e in _log(paths))
        retry = _record(paths, _blocked(), now=T0 + timedelta(hours=6))
        assert len(retry.calls) == 1

    def test_unblocked_clears_state(self, paths):
        _record(paths, _blocked())
        notify = _record(paths, None, now=T0 + timedelta(hours=6))
        assert notify.calls == []
        state = read_blocked_state(paths)
        assert state["blocked"] is None and state["alerted"] is None
        # Blocked again later: a fresh alert.
        assert len(_record(paths, _blocked(), now=T0 + timedelta(hours=12)).calls) == 1

    def test_blocked_release_is_logged_with_its_source(self, paths):
        _record(paths, _blocked())
        entry = next(e for e in _log(paths) if "cannot be installed" in e["msg"])
        assert entry["level"] == "warn"
        assert entry["detail"]["blocked"] == _blocked()
        assert entry["detail"]["source"] == "endpoint"

    def test_corrupt_state_is_reported_and_replaced(self, paths):
        paths.platform_update_state.parent.mkdir(parents=True, exist_ok=True)
        paths.platform_update_state.write_text("{not json")
        notify = _record(paths, _blocked())
        assert len(notify.calls) == 1
        assert read_blocked_state(paths)["alerted"]["version"] == "0.11.2"
        errors = [e for e in _log(paths) if e["level"] == "error"]
        assert errors and "platform-updates.json" in errors[0]["msg"]


class TestReadState:
    def test_missing_is_none(self, paths):
        assert read_blocked_state(paths) is None

    @pytest.mark.parametrize("content", [
        "{not json", "[]", json.dumps({"blocked": None}),
        json.dumps({"checked_at": "x", "current_version": "0.1.0", "blocked": "0.2.0",
                    "alerted": None}),
        json.dumps({"checked_at": "x", "current_version": "0.1.0", "blocked": None,
                    "alerted": {"version": "0.2.0"}}),
        json.dumps({"checked_at": "x", "current_version": "0.1.0", "blocked": None,
                    "alerted": {"version": "0.2.0", "at": "yesterday"}}),
        json.dumps({"checked_at": "x", "current_version": "0.1.0", "blocked": None,
                    "alerted": {"version": "0.2.0", "at": "2026-10-01T12:00:00"}}),
    ])
    def test_invalid_raises(self, paths, content):
        paths.platform_update_state.parent.mkdir(parents=True, exist_ok=True)
        paths.platform_update_state.write_text(content)
        with pytest.raises(BlockedStateError, match="platform-updates.json"):
            read_blocked_state(paths)
