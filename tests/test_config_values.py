"""load_config checks the shape and value of every setting it knows.

A value of the wrong type used to load, and fail wherever it was first
used: `health: {alert_threshold: '3'}` raised TypeError in the health
state machine, in the middle of the fleet's tick.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from boxmunge.config import DEFAULTS, ConfigError, load_config
from boxmunge.paths import BoxPaths

BASE = {"hostname": "box.example.com", "admin_email": "ops@example.com"}


def _load(paths: BoxPaths, extra: dict, **kwargs) -> dict:
    paths.config_file.write_text(yaml.safe_dump({**BASE, **extra}))
    return load_config(paths, **kwargs)


REFUSED = [
    ("hostname", {"hostname": 123}),
    ("admin_email", {"admin_email": ["ops@example.com"]}),
    ("ssh_port", {"ssh_port": "922"}),
    ("ssh_port", {"ssh_port": True}),
    ("ssh_port", {"ssh_port": 0}),
    ("ssh_port", {"ssh_port": 65536}),
    ("backup_remote", {"backup_remote": 5}),
    ("pushover", {"pushover": "user:token"}),
    ("pushover", {"pushover": None}),
    ("pushover.user_key", {"pushover": {"user_key": 12345}}),
    ("pushover.app_token", {"pushover": {"app_token": ["t"]}}),
    ("health", {"health": 3}),
    ("health.alert_threshold", {"health": {"alert_threshold": "3"}}),
    ("health.alert_threshold", {"health": {"alert_threshold": True}}),
    ("health.alert_threshold", {"health": {"alert_threshold": 0}}),
    ("health.alert_threshold", {"health": {"alert_threshold": 2.5}}),
    ("health.check_interval_minutes", {"health": {"check_interval_minutes": "5"}}),
    ("health.check_interval_minutes", {"health": {"check_interval_minutes": 0}}),
    ("reboot", {"reboot": ["04:00"]}),
    ("reboot.auto_reboot", {"reboot": {"auto_reboot": "yes"}}),
    ("reboot.auto_reboot", {"reboot": {"auto_reboot": 1}}),
    ("reboot.reboot_window", {"reboot": {"reboot_window": 240}}),
    ("reboot.reboot_window", {"reboot": {"reboot_window": "25:00"}}),
    ("reboot.reboot_window", {"reboot": {"reboot_window": "4am"}}),
    ("logging", {"logging": "50m"}),
    ("logging.docker_max_size", {"logging": {"docker_max_size": 50}}),
    ("logging.docker_max_file", {"logging": {"docker_max_file": "5"}}),
    ("logging.docker_max_file", {"logging": {"docker_max_file": 0}}),
    ("container_updates", {"container_updates": None}),
    ("container_updates.enabled", {"container_updates": {"enabled": "false"}}),
    ("container_updates.strategy", {"container_updates": {"strategy": "rollback"}}),
    ("webhooks", {"webhooks": {"url": "https://hooks.example.com/x"}}),
    ("webhooks", {"webhooks": ["https://hooks.example.com/x"]}),
    ("webhooks", {"webhooks": [{"url": 5, "events": ["deploy"]}]}),
    ("webhooks", {"webhooks": [{"url": "https://hooks.example.com/x", "events": "deploy"}]}),
]


@pytest.mark.parametrize("setting,extra", REFUSED, ids=[f"{s}={e}" for s, e in REFUSED])
def test_a_wrong_value_is_refused_naming_its_setting(paths: BoxPaths, setting, extra) -> None:
    with pytest.raises(ConfigError) as refused:
        _load(paths, extra)
    assert f"'{setting}'" in str(refused.value)
    assert str(paths.config_file) in str(refused.value)


def test_every_wrong_value_is_named_at_once(paths: BoxPaths) -> None:
    with pytest.raises(ConfigError) as refused:
        _load(paths, {"ssh_port": "922", "health": {"alert_threshold": "3"}})
    assert "'ssh_port'" in str(refused.value)
    assert "'health.alert_threshold'" in str(refused.value)


ACCEPTED = [
    {},
    {"ssh_port": 22, "backup_remote": "b2:bucket/box"},
    {"pushover": {"user_key": "u", "app_token": "t"}},
    {"pushover": {"user_key": None, "app_token": None}, "backup_remote": None},
    {"health": {"alert_threshold": 1}, "reboot": {"auto_reboot": False, "reboot_window": "23:59"}},
    {"container_updates": {"enabled": False, "strategy": "rollback_to_previous"}},
    {"webhooks": [{"url": "https://hooks.example.com/x", "events": ["deploy", "rollback"]}]},
    {"webhooks": []},
]


@pytest.mark.parametrize("extra", ACCEPTED, ids=[str(e) for e in ACCEPTED])
def test_a_right_value_loads(paths: BoxPaths, extra) -> None:
    config = _load(paths, extra)
    for key, value in extra.items():
        if not isinstance(value, dict):
            assert config[key] == value


def test_the_defaults_pass_their_own_checks(paths: BoxPaths) -> None:
    assert _load(paths, DEFAULTS) == {**DEFAULTS, **BASE}


def test_the_reference_template_loads(paths: BoxPaths) -> None:
    template = Path(__file__).parent.parent / "config" / "boxmunge.yml.template"
    paths.config_file.write_text(template.read_text()
                                 .replace("__HOSTNAME__", "box.example.com")
                                 .replace("__ADMIN_EMAIL__", "ops@example.com"))
    assert load_config(paths)["ssh_port"] == 922


class TestLenientValues:
    """The paths that act on a box that is already running take the value
    as it is; the checks older than these stay errors there."""

    def test_the_value_is_kept(self, paths: BoxPaths) -> None:
        config = _load(paths, {"health": {"alert_threshold": "3"}}, lenient_values=True)
        assert config["health"]["alert_threshold"] == "3"

    def test_the_older_checks_still_refuse(self, paths: BoxPaths) -> None:
        with pytest.raises(ConfigError, match="auto_update.breakfix"):
            _load(paths, {"auto_update": {"breakfix": "yes"}}, lenient_values=True)
        with pytest.raises(ConfigError, match="version_check"):
            _load(paths, {"version_check": "off"}, lenient_values=True)
        paths.config_file.write_text("admin_email: ops@example.com\n")
        with pytest.raises(ConfigError, match="hostname"):
            load_config(paths, lenient_values=True)
