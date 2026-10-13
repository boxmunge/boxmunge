"""Health alerting records an alert as sent only if it was delivered (audit D-06)."""
from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.state import read_state, write_state

NAME = "myapp"
CONFIG = "hostname: t\nadmin_email: a@b\npushover:\n  user_key: u\n  app_token: a\n"


@pytest.fixture
def box(paths: BoxPaths) -> BoxPaths:
    paths.config_file.write_text(CONFIG)
    return paths


def _log_entries(paths: BoxPaths) -> list[dict]:
    if not paths.log_file.exists():
        return []
    return [json.loads(line) for line in paths.log_file.read_text().splitlines()]


def _errors(paths: BoxPaths) -> list[str]:
    return [e["msg"] for e in _log_entries(paths) if e["level"] == "error"]


def _tick(paths: BoxPaths, result: int, message: str, send) -> dict:
    from boxmunge.commands.health_state import update_health_state
    with patch("boxmunge.notify.send_notification", send), \
         patch("boxmunge.commands.health_state.compose_down"):
        update_health_state(NAME, result, message, paths)
    return read_state(paths.project_health_state(NAME))


class TestWarningAlerts:
    def test_failed_send_is_not_recorded_and_is_retried(self, box):
        fail, ok = MagicMock(return_value=False), MagicMock(return_value=True)
        _tick(box, 1, "slow", fail)
        _tick(box, 1, "slow", fail)
        state = _tick(box, 1, "slow", fail)  # threshold (3) reached; send fails
        assert fail.call_count == 1
        assert state["alerted"] is False
        assert state.get("last_alert", "") == ""
        assert any("Alert not sent" in m for m in _errors(box))

        state = _tick(box, 1, "slow", ok)  # retried on the next tick
        assert ok.call_count == 1
        assert state["alerted"] is True and state["last_alert"]

        _tick(box, 1, "slow", ok)  # delivered: no repeat for the same message
        assert ok.call_count == 1

    def test_failed_realert_on_new_message_is_retried(self, box):
        ok, fail = MagicMock(return_value=True), MagicMock(return_value=False)
        for _ in range(3):
            _tick(box, 1, "slow", ok)
        assert ok.call_count == 1
        _tick(box, 1, "timeouts", fail)  # message changed: re-alert fails
        assert fail.call_count == 1
        _tick(box, 1, "timeouts", ok)  # same message now, but never delivered
        assert ok.call_count == 2
        state = read_state(box.project_health_state(NAME))
        assert state["alerted_reason"] == "timeouts"


class TestCriticalAlert:
    def test_failed_critical_alert_still_stops_and_is_retried(self, box):
        down = MagicMock()
        fail, ok = MagicMock(return_value=False), MagicMock(return_value=True)
        from boxmunge.commands.health_state import update_health_state
        with patch("boxmunge.notify.send_notification", fail), \
             patch("boxmunge.commands.health_state.compose_down", down):
            update_health_state(NAME, 2, "db unreachable", box)
        state = read_state(box.project_health_state(NAME))
        assert down.call_count == 1
        assert state["status"] == "critical_stopped"
        assert state["alerted"] is False

        state = _tick(box, 1, "smoke could not run", ok)  # sticky tick retries
        assert ok.call_count == 1
        assert ok.call_args.kwargs.get("priority") == 1
        assert state["status"] == "critical_stopped" and state["alerted"] is True
        _tick(box, 1, "smoke could not run", ok)
        assert ok.call_count == 1

    def test_check_all_retries_undelivered_critical_alert(self, box):
        """check-all skips smoke for a stopped project but still retries the alert."""
        from boxmunge.commands.health_state import record_still_stopped
        write_state(box.project_health_state(NAME), {
            "status": "critical_stopped", "stopped_at": "2026-01-01T00:00:00+00:00",
            "failure_reason": "db unreachable", "alerted": False,
        })
        ok = MagicMock(return_value=True)
        with patch("boxmunge.notify.send_notification", ok):
            record_still_stopped(NAME, box)
        assert ok.call_count == 1
        assert read_state(box.project_health_state(NAME))["alerted"] is True


class TestRecoveryNotice:
    def test_failed_recovery_notice_is_retried(self, box):
        ok, fail = MagicMock(return_value=True), MagicMock(return_value=False)
        for _ in range(3):
            _tick(box, 1, "slow", ok)
        state = _tick(box, 0, "", fail)
        assert state["status"] == "ok"
        assert state["alerted"] is True, "recovery notice still owed"
        state = _tick(box, 0, "", ok)
        titles = [c.args[2] for c in ok.call_args_list]
        assert any("RECOVERED" in t for t in titles)
        assert state["alerted"] is False
        _tick(box, 0, "", ok)
        assert sum("RECOVERED" in c.args[2] for c in ok.call_args_list) == 1


class TestConfig:
    def test_missing_config_is_an_error_and_alert_not_recorded(self, box):
        box.config_file.unlink()
        down, send = MagicMock(), MagicMock(return_value=True)
        from boxmunge.commands.health_state import update_health_state
        with patch("boxmunge.notify.send_notification", send), \
             patch("boxmunge.commands.health_state.compose_down", down):
            update_health_state(NAME, 2, "db unreachable", box)
        state = read_state(box.project_health_state(NAME))
        assert down.call_count == 1, "the stop itself must not depend on config"
        assert state["alerted"] is False
        send.assert_not_called()
        assert any("Config file not found" in m for m in _errors(box))


class TestNotify:
    def test_unconfigured_pushover_is_a_warning_and_false(self, paths):
        from boxmunge.notify import notify
        paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
        assert notify(paths, "t", "b", component="health") is False
        entries = _log_entries(paths)
        assert entries and entries[-1]["level"] == "warn"
        assert "not configured" in entries[-1]["msg"]

    def test_send_failure_is_an_error_and_false(self, box):
        from boxmunge.notify import notify
        with patch("boxmunge.notify.send_notification", return_value=False):
            assert notify(box, "t", "b", component="health") is False
        assert any("Pushover request failed" in m for m in _errors(box))

    def test_pushover_logs_the_transport_reason(self, caplog):
        import urllib.error
        from boxmunge.pushover import send_notification
        with patch("boxmunge.pushover.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("name resolution failed")):
            with caplog.at_level(logging.WARNING, logger="boxmunge"):
                assert send_notification("u", "a", "t", "b") is False
        assert "name resolution failed" in caplog.text
