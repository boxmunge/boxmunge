"""A wrong health setting in boxmunge.yml no longer aborts the fleet's tick.

`health: {alert_threshold: '3'}` loaded, and the first project with a
warning raised TypeError comparing its failure count with the string: the
tick stopped there, before the projects after it were checked.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands.health_state import update_health_state
from boxmunge.config import ConfigError, load_config
from boxmunge.paths import BoxPaths
from boxmunge.state import read_state

CONFIG = ("hostname: box.example.com\nadmin_email: ops@example.com\n"
          "pushover: {user_key: u, app_token: t}\n"
          "health:\n  alert_threshold: '3'\n")


@pytest.fixture
def box(paths: BoxPaths) -> BoxPaths:
    paths.config_file.write_text(CONFIG)
    return paths


def test_the_setting_is_refused_at_load(box: BoxPaths) -> None:
    with pytest.raises(ConfigError, match="'health.alert_threshold'"):
        load_config(box)


def test_the_tick_goes_on_to_the_next_project_and_still_alerts(box: BoxPaths) -> None:
    """Every project's warning is recorded; the documented default of three
    failures in a row applies, and the alert is delivered."""
    sent: list[str] = []
    with patch("boxmunge.notify.send_notification",
               lambda u, t, title, body, priority=0: sent.append(title) or True):
        for _ in range(3):
            for project in ("first", "second"):
                update_health_state(project, 1, "smoke failed", box)
    for project in ("first", "second"):
        state = read_state(box.project_health_state(project))
        assert state["consecutive_failures"] == 3
        assert state["alerted"] is True
    assert len(sent) == 2
    log = box.log_file.read_text()
    assert "'health.alert_threshold'" in log
    assert "default alert threshold" in log
