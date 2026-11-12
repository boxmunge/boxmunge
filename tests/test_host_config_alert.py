"""A box whose boxmunge.yml holds a value load_config now refuses still
starts its projects, upgrades and alerts; it is warned and alerted instead.

Real config, state and log files; only `docker compose up` and Pushover's
HTTP call are stood in for.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.compose_guard import ComposeRefused, compose_up_checked
from boxmunge.config import ConfigError, load_config
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.version_check_optout import version_checks_off

NAME = "shop"
CONFIG = {
    "hostname": "box.example.com", "admin_email": "ops@example.com",
    "pushover": {"user_key": "u", "app_token": "t"},
}
ODD = {**CONFIG, "ssh_port": "922", "reboot": {"auto_reboot": "yes"}}


@pytest.fixture
def box(tmp_path: Path):
    paths = BoxPaths(root=tmp_path / "bm")
    for d in (paths.config, paths.deploy_state, paths.logs):
        d.mkdir(parents=True)
    paths.config_file.write_text(yaml.safe_dump(ODD))
    project_dir = paths.project_dir(NAME)
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ", "project": NAME,
        "source": "bundle", "hosts": [f"{NAME}.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (project_dir / "compose.yml").write_text(yaml.safe_dump(
        {"services": {"web": {"image": "nginx:1.27"}}}))
    sent: list[tuple[str, str]] = []
    delivery = {"ok": True}

    def send(user_key, app_token, title, body, priority=0):
        sent.append((title, body))
        return delivery["ok"]

    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.notify.send_notification", send):
        yield paths, up, sent, delivery


def _start(paths: BoxPaths, component: str = "upgrade") -> None:
    compose_up_checked(paths, NAME, component=component, compose_files=["compose.yml"],
                       record=True)


def _warnings(paths: BoxPaths) -> int:
    log = paths.log_file.read_text() if paths.log_file.exists() else ""
    return log.count("holds values this release refuses")


def test_the_config_is_refused_where_it_is_read(box) -> None:
    paths, *_ = box
    with pytest.raises(ConfigError, match="'ssh_port'.*'reboot.auto_reboot'"):
        load_config(paths)


def test_a_start_goes_ahead_and_the_operator_is_told_once_a_day(box) -> None:
    paths, up, sent, _ = box
    for _ in range(3):
        _start(paths)
    assert up.call_count == 3
    assert len(sent) == 1
    title, body = sent[0]
    assert title == "[box.example.com] boxmunge.yml needs correcting"
    assert "'ssh_port'" in body and "'reboot.auto_reboot'" in body
    assert str(paths.config_file) in body
    assert _warnings(paths) == 1


def test_an_undelivered_alert_is_tried_again_at_the_next_start(box) -> None:
    paths, up, sent, delivery = box
    delivery["ok"] = False
    _start(paths)
    _start(paths)
    assert len(sent) == 2
    delivery["ok"] = True
    _start(paths)
    _start(paths)
    assert len(sent) == 3
    assert up.call_count == 4


def test_a_different_wrong_value_alerts_again(box) -> None:
    paths, _, sent, _ = box
    _start(paths)
    paths.config_file.write_text(yaml.safe_dump({**CONFIG, "ssh_port": "922"}))
    _start(paths)
    assert len(sent) == 2
    assert "reboot.auto_reboot" not in sent[1][1]


def test_a_corrected_config_is_quiet(box) -> None:
    paths, up, sent, _ = box
    paths.config_file.write_text(yaml.safe_dump(CONFIG))
    _start(paths)
    assert up.call_count == 1 and sent == [] and _warnings(paths) == 0


def test_a_start_does_not_need_a_loadable_config(box) -> None:
    """A start reads no host setting; the commands that do report this."""
    paths, up, sent, _ = box
    paths.config_file.unlink()
    _start(paths)
    assert up.call_count == 1 and sent == []


def test_a_refused_start_still_alerts(box) -> None:
    """The refusal's own alert is delivered over the odd config."""
    paths, up, sent, _ = box
    _start(paths)
    (paths.project_dir(NAME) / "manifest.yml").write_text(yaml.safe_dump({"project": "other"}))
    with pytest.raises(ComposeRefused):
        compose_up_checked(paths, NAME, component="upgrade", compose_files=["compose.yml"])
    assert [title for title, _ in sent] == [
        "[box.example.com] boxmunge.yml needs correcting",
        "[box.example.com] shop: start refused"]


def test_any_alert_is_delivered(box) -> None:
    paths, _, sent, _ = box
    assert notify(paths, "backup failed", "body", component="backup") is True
    assert sent == [("[box.example.com] backup failed", "body")]


def test_upgrade_discovery_reads_its_own_settings(box) -> None:
    paths, *_ = box
    assert version_checks_off(paths) is False
    paths.config_file.write_text(yaml.safe_dump({**ODD, "version_check": {"enabled": False}}))
    assert version_checks_off(paths) is True
    paths.config_file.write_text(yaml.safe_dump({**ODD, "version_check": {"enabled": "no"}}))
    with pytest.raises(ConfigError, match="version_check.enabled"):
        version_checks_off(paths)


def test_the_health_report_checks_the_firewall_for_the_configured_port(box) -> None:
    """The upgrade shim judges a release by `health`: a value refused in
    another setting does not move the firewall check to the default port."""
    from boxmunge.commands.health_cmd import _ssh_port
    paths, *_ = box
    paths.config_file.write_text(yaml.safe_dump(
        {**CONFIG, "ssh_port": 2222, "reboot": {"reboot_window": 240}}))
    assert _ssh_port(paths) == 2222
    assert not paths.log_file.exists()
