# SPDX-License-Identifier: Apache-2.0
"""notify(): an unconfigured Pushover is logged once a day, not every tick."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from boxmunge.notify import notify
from boxmunge.paths import BoxPaths

BASE = "hostname: box.example.com\nadmin_email: ops@example.com\n"
T0 = datetime(2026, 10, 16, 9, 0, tzinfo=timezone.utc)


def _unsent_lines(paths: BoxPaths) -> list[dict]:
    if not paths.log_file.exists():
        return []
    entries = [json.loads(line) for line in paths.log_file.read_text().splitlines() if line]
    return [e for e in entries if "Pushover is not configured" in e["msg"]]


def _notify_at(paths, now, title="t"):
    with patch("boxmunge.notify._now", return_value=now):
        return notify(paths, title, "b", component="health", project="myapp")


def _unconfigured(paths):
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(BASE)


def test_unconfigured_is_logged_once_then_quiet_for_a_day(paths):
    """check-all retries an undelivered alert every five minutes; without
    Pushover that wrote the same warning 288 times a day per failing project."""
    _unconfigured(paths)
    assert _notify_at(paths, T0) is False
    for minutes in range(5, 24 * 60, 5):
        assert _notify_at(paths, T0 + timedelta(minutes=minutes)) is False
    lines = _unsent_lines(paths)
    assert len(lines) == 1
    assert lines[0]["level"] == "warn"
    assert "Alert not sent (t)" in lines[0]["msg"]
    assert "`alerts` health check" in lines[0]["msg"]


def test_logged_again_after_a_day(paths):
    _unconfigured(paths)
    _notify_at(paths, T0)
    _notify_at(paths, T0 + timedelta(hours=24), title="later")
    lines = _unsent_lines(paths)
    assert len(lines) == 2 and "Alert not sent (later)" in lines[1]["msg"]


def test_unreadable_throttle_state_logs_and_is_replaced(paths):
    _unconfigured(paths)
    paths.alerts_unconfigured_state.parent.mkdir(parents=True, exist_ok=True)
    paths.alerts_unconfigured_state.write_text("{nope")
    _notify_at(paths, T0)
    _notify_at(paths, T0 + timedelta(minutes=5))
    assert len(_unsent_lines(paths)) == 1
    entries = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
    assert any(e["level"] == "error" and "alerts-unconfigured.json" in e["msg"]
               for e in entries)


def test_configured_pushover_failures_are_still_logged_every_time(paths):
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(BASE + "pushover:\n  user_key: u\n  app_token: a\n")
    with patch("boxmunge.notify.send_notification", return_value=False):
        for minutes in (0, 5):
            assert _notify_at(paths, T0 + timedelta(minutes=minutes)) is False
    entries = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
    assert sum("Pushover request failed" in e["msg"] for e in entries) == 2


def test_malformed_pushover_block_is_an_error(paths):
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(BASE + "pushover: yes\n")
    assert notify(paths, "t", "b", component="health") is False
    entries = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
    assert any(e["level"] == "error" and "must be a mapping" in e["msg"] for e in entries)
