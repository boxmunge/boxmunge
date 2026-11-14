"""A damaged health record (right JSON, wrong field types) must not defeat the
critical stop (audit R07). Policy: a critical verdict is always enforced, from
fresh bookkeeping, with the damage logged and named in the recorded reason; a
warning or ok verdict with a damaged record raises StateError naming the field
(the fleet loop reports it each tick and carries on with the other projects)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import yaml

from boxmunge.commands.check_all import run_check_all
from boxmunge.commands.health_state import update_health_state
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError, read_state

BAD = [
    ({"consecutive_failures": "3"}, "consecutive_failures"),
    ({"consecutive_failures": True}, "consecutive_failures"),
    ({"consecutive_failures": -1}, "consecutive_failures"),
    ({"alerted": "yes"}, "alerted"),
    ({"alerted": 1}, "alerted"),
    ({"last_check": 12345}, "last_check"),
    ({"stopped_at": 7}, "stopped_at"),
    ({"status": ["ok"]}, "status"),
]
CONFIG = "hostname: t\nadmin_email: a@b\npushover:\n  user_key: u\n  app_token: a\n"


@pytest.fixture
def box(paths: BoxPaths) -> BoxPaths:
    paths.config_file.write_text(CONFIG)
    for name in ("aaa", "bbb"):
        paths.project_dir(name).mkdir(parents=True)
        paths.project_manifest(name).write_text(yaml.dump({
            "schema_version": 3, "id": "01TEST", "project": name, "source": "bundle",
            "hosts": [f"{name}.example.com"], "services": {"web": {"port": 8080}}}))
    return paths


def _damage(paths, name, fields) -> None:
    paths.project_health_state(name).parent.mkdir(parents=True, exist_ok=True)
    paths.project_health_state(name).write_text(json.dumps(fields))


def _errors(paths) -> list[str]:
    return [json.loads(l)["msg"] for l in paths.log_file.read_text().splitlines()
            if json.loads(l)["level"] == "error"]


@pytest.mark.parametrize("fields,field", BAD)
def test_critical_still_stops_and_alerts_from_a_damaged_record(box, fields, field) -> None:
    _damage(box, "aaa", fields)
    send, down = MagicMock(return_value=True), MagicMock()
    with patch("boxmunge.notify.send_notification", send), \
         patch("boxmunge.commands.health_state.compose_down", down):
        update_health_state("aaa", 2, "smoke dead", box)
    down.assert_called_once()
    send.assert_called_once()
    state = read_state(box.project_health_state("aaa"))
    assert state["status"] == "critical_stopped" and state["consecutive_failures"] == 1
    assert "damaged" in state["failure_reason"] and field in state["failure_reason"]
    assert any(field in m and "damaged" in m for m in _errors(box))


@pytest.mark.parametrize("result", [0, 1])
@pytest.mark.parametrize("fields,field", BAD)
def test_ok_and_warning_refuse_a_damaged_record_naming_the_field(
        box, result, fields, field) -> None:
    _damage(box, "aaa", fields)
    with patch("boxmunge.notify.send_notification", MagicMock()):
        with pytest.raises(StateError, match=field):
            update_health_state("aaa", result, "slow", box)
    assert json.loads(box.project_health_state("aaa").read_text()) == fields


@pytest.mark.parametrize("fields,field", BAD)
def test_a_damaged_project_does_not_stop_later_projects_in_the_tick(
        box, capsys, fields, field) -> None:
    _damage(box, "aaa", fields)
    send, down = MagicMock(return_value=True), MagicMock()
    verdicts = {"aaa": (2, "smoke dead"), "bbb": (0, "")}
    with patch("boxmunge.notify.send_notification", send), \
         patch("boxmunge.commands.health_state.compose_down", down), \
         patch("boxmunge.commands.check_all.check.check_with_reason",
               side_effect=lambda name, *a, **k: verdicts[name]), \
         patch("boxmunge.health_checks.userns.alert_docker_userns",
               return_value=MagicMock(status="ok")), \
         patch("boxmunge.backup_alerts.alert_backups"):
        assert run_check_all(box, read_only=False) == 2
    down.assert_called_once()
    assert read_state(box.project_health_state("aaa"))["status"] == "critical_stopped"
    assert read_state(box.project_health_state("bbb"))["status"] == "ok"


def test_a_damaged_record_does_not_hide_a_standing_stop_check(box) -> None:
    """is_monitor_stopped cannot tell: it answers False so the tick judges the
    project afresh (and update_health_state then applies the policy)."""
    from boxmunge.commands.health_state import is_monitor_stopped
    _damage(box, "aaa", {"status": "critical_stopped", "consecutive_failures": "x"})
    assert is_monitor_stopped("aaa", box) is False
