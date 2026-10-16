# SPDX-License-Identifier: Apache-2.0
"""The alerts health check: can this box alert its operator at all?"""
from __future__ import annotations

import inspect

import pytest

from boxmunge.health_checks.alerts import check_alerts

BASE = "hostname: box.example.com\nadmin_email: ops@example.com\n"


@pytest.mark.parametrize("pushover", [
    "",
    "pushover:\n  user_key: u\n",
    "pushover:\n  app_token: t\n",
    "pushover:\n  user_key: ''\n  app_token: ''\n",
])
def test_unconfigured_pushover_warns_and_says_where_to_fix_it(paths, pushover):
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(BASE + pushover)
    result = check_alerts(paths)
    assert (result.name, result.status) == ("alerts", "warn")
    assert "nothing on this box can alert you" in result.detail
    assert "pushover:" in result.detail and str(paths.config_file) in result.detail
    assert "test-alert" in result.detail


def test_names_the_missing_key(paths):
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(BASE + "pushover:\n  user_key: u\n")
    assert "app_token" in check_alerts(paths).detail
    assert "user_key" not in check_alerts(paths).detail.split("(")[1].split(")")[0]


def test_configured_pushover_is_ok(paths):
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(BASE + "pushover:\n  user_key: u\n  app_token: t\n")
    result = check_alerts(paths)
    assert result.status == "ok"
    assert "test-alert" in result.detail


def test_malformed_pushover_block_warns(paths):
    paths.config_file.parent.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(BASE + "pushover: yes\n")
    result = check_alerts(paths)
    assert result.status == "warn" and "must be a mapping" in result.detail


def test_unreadable_config_warns(paths):
    result = check_alerts(paths)
    assert result.status == "warn"
    assert "no alert can be sent" in result.detail


def test_health_report_includes_the_check():
    from boxmunge.commands import health_cmd
    assert "check_alerts(paths)" in inspect.getsource(health_cmd.collect_health)
