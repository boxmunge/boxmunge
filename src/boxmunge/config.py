# SPDX-License-Identifier: Apache-2.0
"""Load and validate the host configuration file (boxmunge.yml)."""

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
    "container_updates": {
        "enabled": True,
        "strategy": "leave_broken",
    },
    # Platform auto-update. Security releases always apply; break-fix
    # releases (critical non-security fixes) apply unless disabled here.
    "auto_update": {"breakfix": True},
}

AUTO_UPDATE_KEYS = frozenset({"breakfix"})

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

    Raises ConfigError, naming the file, if it is missing, unreadable, not
    valid YAML, not a mapping, or required fields are absent.
    """
    config_file = paths.config_file
    if not config_file.exists():
        raise ConfigError(f"Config file not found: {config_file}")

    try:
        with open(config_file) as f:
            raw = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"Config is not valid YAML: {config_file}: {e}") from e
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"Cannot read config {config_file}: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError(f"Config is not a YAML mapping: {config_file}")

    config = _deep_merge(DEFAULTS, raw)

    for field in REQUIRED_FIELDS:
        if field not in config or not config[field]:
            raise ConfigError(
                f"Required field '{field}' missing from {config_file}"
            )

    _validate_auto_update(config, config_file)
    return config


def _validate_auto_update(config: dict[str, Any], config_file: object) -> None:
    """auto_update must be a mapping of known keys; breakfix must be a boolean."""
    block = config["auto_update"]
    if not isinstance(block, dict):
        raise ConfigError(
            f"'auto_update' in {config_file} must be a mapping, e.g. "
            f"'auto_update: {{breakfix: true}}'"
        )
    unknown = sorted(set(block) - AUTO_UPDATE_KEYS)
    if unknown:
        raise ConfigError(
            f"Unknown key(s) under 'auto_update' in {config_file}: "
            f"{', '.join(map(str, unknown))} (allowed: {', '.join(sorted(AUTO_UPDATE_KEYS))})"
        )
    if not isinstance(block["breakfix"], bool):
        raise ConfigError(
            f"'auto_update.breakfix' in {config_file} must be true or false, "
            f"got {block['breakfix']!r}"
        )


def auto_update_breakfix_enabled(config: dict[str, Any]) -> bool:
    """True if this box auto-applies break-fix releases (validated by load_config)."""
    return config["auto_update"]["breakfix"]
