"""A wrong setting in boxmunge.yml stops only what reads it.

The timers' jobs run unless a setting they read is wrong; the commands a
person runs refuse on any. Whichever job meets the wrong settings first
tells the operator, once for them all.

Real config, state and log files. Stood in for: Pushover's HTTP call, the
update of one target, and the system container's docker calls.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
import yaml

from boxmunge import host_config_alert
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError
from boxmunge.commands import check_all, test_alert
from boxmunge.commands.backup_sync_cmd import run_backup_sync
from boxmunge.commands.container_update_cmd import run_container_update
from boxmunge.commands.doctor import run_doctor
from boxmunge.commands.health_state import update_health_state
from boxmunge.config import ConfigError, load_config
from boxmunge.cve.kev import KEV_DEFAULT_SOURCES
from boxmunge.cve.kev_refresh import kev_sources
from boxmunge.paths import BoxPaths
from boxmunge.state import read_state
from tests.api.fakes import make_invoker
from tests.test_commands.test_backup_sync import _ok

CONFIG = {
    "hostname": "box.example.com", "admin_email": "ops@example.com",
    "pushover": {"user_key": "u", "app_token": "t"},
    "backup_remote": "offsite:bucket",
}
# Settings no job reads: boxmunge.yml documents both as inert.
ODD = {**CONFIG, "logging": {"docker_max_file": "5"}, "reboot": {"auto_reboot": "yes"}}
TITLE = "[box.example.com] boxmunge.yml needs correcting"
UPDATE = "boxmunge.commands.container_update_cmd.update_target_locked"


def _write(paths: BoxPaths, config: dict) -> None:
    paths.config_file.write_text(yaml.safe_dump(config))


@pytest.fixture
def box(paths: BoxPaths):
    for d in (paths.caddy, paths.upgrade_state, paths.project_backups("shop")):
        d.mkdir(parents=True, exist_ok=True)
    (paths.caddy / "compose.yml").write_text(
        "services:\n  caddy:\n    image: caddy:2-alpine\n    container_name: boxmunge-caddy\n")
    _write(paths, ODD)
    sent: list[tuple[str, str]] = []
    delivery = {"ok": True}

    def send(user_key, app_token, title, body, priority=0):
        sent.append((title, body))
        return delivery["ok"]

    with patch("boxmunge.notify.send_notification", send):
        yield paths, sent, delivery


def _container_update(paths: BoxPaths) -> tuple[int, bool]:
    with patch(UPDATE, return_value={"name": "caddy", "status": "succeeded"}) as update:
        return run_container_update(paths), update.called


def _every_job(paths: BoxPaths, system_container) -> None:
    system_container.handler = _ok
    assert _container_update(paths) == (0, True)
    assert run_backup_sync(paths) == 0
    assert kev_sources(paths) == KEV_DEFAULT_SOURCES
    host_config_alert.report_at_start(paths, "upgrade")
    assert check_all._host_config_usable(paths) is True


def _config_alerts(sent) -> list[str]:
    return [body for title, body in sent if title == TITLE]


class TestAJobRunsOverASettingItDoesNotRead:
    def test_container_update(self, box) -> None:
        paths, *_ = box
        assert _container_update(paths) == (0, True)

    def test_backup_sync(self, box, system_container) -> None:
        paths, *_ = box
        system_container.handler = _ok
        assert run_backup_sync(paths) == 0
        assert system_container.calls[0][0] == "rclone"

    def test_the_kev_refresh(self, box) -> None:
        paths, *_ = box
        assert kev_sources(paths) == KEV_DEFAULT_SOURCES

    def test_check_all_does_not_fail_the_tick(self, box, capsys) -> None:
        paths, *_ = box
        assert check_all.run_check_all(paths, read_only=False) == 0
        assert "ERROR" not in capsys.readouterr().err

    @pytest.mark.parametrize("pushover", [None, {"user_key": 12345, "app_token": "t"}],
                             ids=["a bare pushover:", "a key that is a number"])
    def test_nor_over_the_alert_settings(self, box, system_container, pushover) -> None:
        paths, *_ = box
        _write(paths, {**CONFIG, "pushover": pushover})
        _every_job(paths, system_container)

    def test_a_valid_setting_is_used_as_written(self, box) -> None:
        """alert_threshold: 1 alerts on the first failure, whatever the
        reboot settings hold."""
        paths, sent, _ = box
        _write(paths, {**ODD, "health": {"alert_threshold": 1}})
        update_health_state("shop", 1, "smoke failed", paths)
        assert read_state(paths.project_health_state("shop"))["alerted"] is True
        assert "default alert threshold" not in paths.log_file.read_text()
        assert load_config(paths)["logging"]["docker_max_file"] == "5"


class TestAJobRefusesOverASettingItReads:
    def test_container_update(self, box, capsys) -> None:
        paths, *_ = box
        _write(paths, {**CONFIG, "container_updates": {"enabled": "false"}})
        assert _container_update(paths) == (1, False)
        assert "'container_updates.enabled'" in capsys.readouterr().err

    def test_container_update_over_the_whole_block(self, box, capsys) -> None:
        paths, *_ = box
        _write(paths, {**CONFIG, "container_updates": "off"})
        assert _container_update(paths) == (1, False)
        assert "'container_updates'" in capsys.readouterr().err

    def test_backup_sync(self, box, system_container, capsys) -> None:
        paths, *_ = box
        _write(paths, {**CONFIG, "backup_remote": 5})
        assert run_backup_sync(paths) == 1
        assert "'backup_remote'" in capsys.readouterr().err
        assert system_container.calls == []

    def test_the_health_monitor_says_which_threshold_it_uses(self, box) -> None:
        paths, *_ = box
        _write(paths, {**CONFIG, "health": {"alert_threshold": "1"}})
        update_health_state("shop", 1, "smoke failed", paths)
        assert read_state(paths.project_health_state("shop"))["alerted"] is False
        log = paths.log_file.read_text()
        assert "'health.alert_threshold'" in log and "default alert threshold (3)" in log


class TestACommandRunByHandRefuses:
    def test_test_alert(self, box, monkeypatch, capsys) -> None:
        paths, sent, _ = box
        monkeypatch.setattr(test_alert, "BoxPaths", lambda: paths)
        with pytest.raises(SystemExit) as exit_:
            test_alert.cmd_test_alert([])
        assert exit_.value.code == 1
        assert "'logging.docker_max_file'" in capsys.readouterr().err
        assert sent == []

    @pytest.mark.usefixtures("docker_down")
    def test_doctor(self, box, capsys) -> None:
        paths, *_ = box
        run_doctor(paths)
        [line] = [line for line in capsys.readouterr().out.splitlines()
                  if "Config file loads" in line]
        assert "'logging.docker_max_file'" in line and "'reboot.auto_reboot'" in line

    def test_platform_info_refuses_over_the_hostname_it_reads(self, box) -> None:
        paths, *_ = box
        _write(paths, {**CONFIG, "hostname": ["box.example.com"]})
        with pytest.raises(ActionError) as refused:
            make_invoker(paths).invoke("platform.info", {},
                                       Principal.plugin("webui", Tier.OBSERVE))
        assert "'hostname'" in refused.value.message

    def test_a_strict_load_names_every_wrong_setting(self, box) -> None:
        paths, *_ = box
        with pytest.raises(ConfigError, match="'reboot.auto_reboot'.*'logging.docker_max_file'"):
            load_config(paths, strict=True)


class TestTheOperatorIsToldOnce:
    def test_one_alert_for_every_job_and_run(self, box, system_container) -> None:
        paths, sent, _ = box
        for _ in range(2):
            _every_job(paths, system_container)
        [body] = _config_alerts(sent)
        assert "'logging.docker_max_file'" in body and "'reboot.auto_reboot'" in body
        assert paths.log_file.read_text().count("are not what they must be") == 1

    def test_a_job_that_refuses_tells_too(self, box) -> None:
        paths, sent, _ = box
        _write(paths, {**CONFIG, "container_updates": {"enabled": "false"}})
        assert _container_update(paths) == (1, False)
        assert kev_sources(paths) == KEV_DEFAULT_SOURCES
        [body] = _config_alerts(sent)
        assert "'container_updates.enabled'" in body

    def test_an_undelivered_alert_is_tried_again_after_an_hour(self, box, system_container) -> None:
        paths, sent, delivery = box
        delivery["ok"] = False
        assert _container_update(paths) == (0, True)
        assert kev_sources(paths) == KEV_DEFAULT_SOURCES
        assert len(_config_alerts(sent)) == 1  # tried again hourly, not by each job
        delivery["ok"] = True
        record = paths.state / "start-refused" / "boxmunge.yml.json"
        earlier = (datetime.now(timezone.utc) - timedelta(minutes=61)).isoformat()
        record.write_text(json.dumps({key: earlier for key in json.loads(record.read_text())}))
        _every_job(paths, system_container)
        _every_job(paths, system_container)
        assert len(_config_alerts(sent)) == 2
        assert paths.log_file.read_text().count("are not what they must be") == 1

    def test_it_repeats_after_a_day(self, box, system_container) -> None:
        paths, sent, _ = box
        _every_job(paths, system_container)
        record = paths.state / "start-refused" / "boxmunge.yml.json"
        earlier = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        record.write_text(json.dumps({key: earlier for key in json.loads(record.read_text())}))
        _every_job(paths, system_container)
        assert len(_config_alerts(sent)) == 2

    def test_a_different_set_of_problems_alerts_again(self, box, system_container) -> None:
        paths, sent, _ = box
        _every_job(paths, system_container)
        _write(paths, {**CONFIG, "ssh_port": "922"})
        _every_job(paths, system_container)
        bodies = _config_alerts(sent)
        assert len(bodies) == 2 and "reboot.auto_reboot" not in bodies[1]

    def test_a_sound_config_is_quiet(self, box, system_container) -> None:
        paths, sent, _ = box
        _write(paths, CONFIG)
        _every_job(paths, system_container)
        assert sent == [] and "WARNING" not in paths.log_file.read_text()


class TestItShowsWithoutPushover:
    def test_health_warns_naming_each_setting(self, box) -> None:
        from boxmunge.commands.health_cmd import _checks
        paths, *_ = box
        _write(paths, {**ODD, "pushover": {}})
        result = dict(_checks(paths))["host-config"]()
        assert result.status == "warn"  # an error would roll back an upgrade
        assert "'logging.docker_max_file'" in result.detail
        assert "'reboot.auto_reboot'" in result.detail

    def test_health_is_ok_for_a_sound_config(self, box) -> None:
        from boxmunge.commands.health_cmd import _checks
        paths, *_ = box
        _write(paths, CONFIG)
        assert dict(_checks(paths))["host-config"]().status == "ok"

    def test_a_config_that_cannot_be_loaded_still_fails_the_tick(self, box, capsys) -> None:
        paths, *_ = box
        paths.config_file.unlink()
        assert check_all.run_check_all(paths, read_only=False) == 1
        assert "alerts cannot be sent" in capsys.readouterr().err
