# SPDX-License-Identifier: Apache-2.0
"""Load and validate the host configuration file (boxmunge.yml)."""

from pathlib import Path
from typing import Any

import yaml

from boxmunge.paths import BoxPaths


class ConfigError(Exception):
    """Raised when host configuration is invalid or missing."""


DEFAULTS: dict[str, Any] = {
    "ssh_port": 922,
    "pushover": {"user_key": "", "app_token": ""},
    "backup_remote": "",
    "health": {"check_interval_minutes": 5, "alert_threshold": 3},
    "reboot": {"auto_reboot": True, "reboot_window": "04:00"},
    "logging": {"docker_max_size": "50m", "docker_max_file": 5},
}

REQUIRED_FIELDS = ["hostname", "admin_email"]


def _deep_merge(defaults: dict, overrides: dict) -> dict:
    """Merge overrides into defaults, recursing into nested dicts."""
    result = dict(defaults)
    for key, value in overrides.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(paths: BoxPaths) -> dict[str, Any]:
    """Load boxmunge.yml, apply defaults, and validate required fields.

    Raises ConfigError if the file is missing or required fields are absent.
    """
    config_file = paths.config_file
    if not config_file.exists():
        raise ConfigError(f"Config file not found: {config_file}")

    with open(config_file) as f:
        raw = yaml.safe_load(f) or {}

    config = _deep_merge(DEFAULTS, raw)

    for field in REQUIRED_FIELDS:
        if field not in config or not config[field]:
            raise ConfigError(
                f"Required field '{field}' missing from {config_file}"
            )

    return config
