# SPDX-License-Identifier: Apache-2.0
"""Load and validate the host configuration file (boxmunge.yml)."""

from typing import Any

import yaml

from boxmunge.config_values import Problem, among, found, value_problems
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
    # releases (important fixes that prevent issues) apply unless disabled here.
    "auto_update": {"breakfix": True},
    # The opt-out from everything the box sends the version-check service:
    # with enabled: false the box neither checks for releases (nor asks
    # GitHub instead) nor reports failed upgrades.
    "version_check": {"enabled": True},
}

# Blocks of boolean switches: block -> its keys.
BOOLEAN_BLOCKS = {
    "auto_update": ("breakfix", "auto_update: {breakfix: true}"),
    "version_check": ("enabled", "version_check: {enabled: true}"),
}

REQUIRED_FIELDS = ["hostname", "admin_email"]


def yaml_position(error: yaml.YAMLError) -> str:
    """Where a YAML error is, as ", line N, column M". Never the parser's
    own text: it quotes the file (an alias's name, the lines around the
    fault), and this file holds secrets."""
    mark = getattr(error, "problem_mark", None)
    return f", line {mark.line + 1}, column {mark.column + 1}" if mark else ""


def _deep_merge(defaults: dict, overrides: dict) -> dict:
    """Merge overrides into defaults, recursing into nested dicts."""
    result = dict(defaults)
    for key, value in overrides.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(paths: BoxPaths, *, strict: bool = False,
                reads: tuple[str, ...] = ()) -> dict[str, Any]:
    """Load boxmunge.yml and apply defaults.

    Raises ConfigError, naming the file, if it is missing, unreadable, not
    valid YAML, not a mapping, a required field is absent, or one of the
    BOOLEAN_BLOCKS is malformed. No message holds a setting's value.

    The other settings are checked by config_values, and what a wrong one
    costs is the caller's choice:
    - by default nothing: the value is returned exactly as written. A box
      that has run with it keeps running, and whatever is in memory from an
      older release (the upgrade shim's alerts) loads the config as before.
    - `reads` names the settings (or blocks) an unattended job reads: one
      of those wrong raises ConfigError naming it; any other is left to
      host_config_alert, which tells the operator.
    - `strict` is for a command a person runs: any wrong setting raises,
      naming each.
    """
    config, problems = read_config(paths)
    refused = problems if strict else among(problems, reads)
    if refused:
        raise ConfigError("; ".join(p.message for p in refused))
    return config


def read_config(paths: BoxPaths) -> tuple[dict[str, Any], list[Problem]]:
    """The config with defaults applied, every value as written, and the
    settings config_values finds wrong. Raises ConfigError for what
    load_config always refuses."""
    config_file = paths.config_file
    if not config_file.exists():
        raise ConfigError(f"Config file not found: {config_file}")

    try:
        with open(config_file) as f:
            raw = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"Config is not valid YAML: {config_file}{yaml_position(e)}") from e
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

    for name, (key, example) in BOOLEAN_BLOCKS.items():
        _validate_boolean_block(config, name, key, example, config_file)
    return config, value_problems(config, config_file)


def _validate_boolean_block(config: dict[str, Any], name: str, key: str, example: str,
                            config_file: object) -> None:
    """`name` must be a mapping holding only `key`, which must be a boolean."""
    block = config[name]
    if not isinstance(block, dict):
        raise ConfigError(f"'{name}' in {config_file} must be a mapping, e.g. '{example}'")
    unknown = sorted(set(block) - {key})
    if unknown:
        raise ConfigError(
            f"Unknown key(s) under '{name}' in {config_file}: "
            f"{', '.join(map(str, unknown))} (allowed: {key})"
        )
    if not isinstance(block[key], bool):
        raise ConfigError(
            f"'{name}.{key}' in {config_file} must be true or false, "
            f"found {found(block[key])}"
        )


def auto_update_breakfix_enabled(config: dict[str, Any]) -> bool:
    """True if this box auto-applies break-fix releases (validated by load_config)."""
    return config["auto_update"]["breakfix"]


def version_check_enabled(config: dict[str, Any]) -> bool:
    """False if boxmunge.yml opts out of the version-check service (validated by load_config)."""
    return config["version_check"]["enabled"]
