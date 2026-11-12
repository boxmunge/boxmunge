# SPDX-License-Identifier: Apache-2.0
"""The shape and value of each setting in the host configuration.

load_config runs these on the config with its defaults applied, so a
wrong value is refused where it is read from disk rather than failing
wherever it is first used. Two blocks are checked by their one reader
instead: `kev` (cve.kev_refresh, so a mistake there fails only the KEV
refresh) and `userns` (userns.offset, which writes it).
"""
from __future__ import annotations

import re
from typing import Any, Callable

from boxmunge.manifest_fields import VALID_STRATEGIES

# What a value must be, or None when it is.
Check = Callable[[Any], "str | None"]

_REBOOT_WINDOW = re.compile(r"([01][0-9]|2[0-3]):[0-5][0-9]")


def _whole_number(low: int, high: int | None = None) -> Check:
    """An integer in range. bool is an int to Python, and never one here:
    `alert_threshold: true` is a mistake, not 1."""
    what = (f"a whole number of at least {low}" if high is None
            else f"a whole number from {low} to {high}")

    def check(value: Any) -> str | None:
        in_range = (isinstance(value, int) and not isinstance(value, bool)
                    and value >= low and (high is None or value <= high))
        return None if in_range else what
    return check


def _boolean(value: Any) -> str | None:
    return None if isinstance(value, bool) else "true or false"


def _text(value: Any) -> str | None:
    return None if isinstance(value, str) and value else "a non-empty string"


def _optional_text(value: Any) -> str | None:
    return None if value is None or isinstance(value, str) else 'a string ("" when unset)'


def _reboot_window(value: Any) -> str | None:
    if isinstance(value, str) and _REBOOT_WINDOW.fullmatch(value):
        return None
    return 'a quoted 24-hour time such as "04:00"'


def _strategy(value: Any) -> str | None:
    return None if value in VALID_STRATEGIES else f"one of {', '.join(VALID_STRATEGIES)}"


TOP_LEVEL: dict[str, Check] = {
    "hostname": _text,
    "admin_email": _text,
    "ssh_port": _whole_number(1, 65535),
    "backup_remote": _optional_text,
}

BLOCKS: dict[str, dict[str, Check]] = {
    "pushover": {"user_key": _optional_text, "app_token": _optional_text},
    "health": {"check_interval_minutes": _whole_number(1),
               "alert_threshold": _whole_number(1)},
    "reboot": {"auto_reboot": _boolean, "reboot_window": _reboot_window},
    "logging": {"docker_max_size": _text, "docker_max_file": _whole_number(1)},
    "container_updates": {"enabled": _boolean, "strategy": _strategy},
}


def _webhook_problem(hooks: Any) -> str | None:
    """`webhooks` is optional: a list of {url, events}."""
    if not isinstance(hooks, list):
        return "a list of {url, events} mappings"
    for hook in hooks:
        events = hook.get("events", []) if isinstance(hook, dict) else None
        if (not isinstance(hook, dict) or _text(hook.get("url")) is not None
                or not isinstance(events, list)
                or not all(isinstance(event, str) for event in events)):
            return ("a list of mappings, each with a url string and a list of "
                    "event names")
    return None


def value_problems(config: dict[str, Any], where: object) -> list[str]:
    """Every setting in `config` (defaults applied) that is not what it must
    be. Each line names the setting, the file and the value found."""
    def problem(name: str, value: Any, check: Check) -> list[str]:
        must_be = check(value)
        return [] if must_be is None else [
            f"'{name}' in {where} must be {must_be}, got {value!r}"]

    problems: list[str] = []
    for name, check in TOP_LEVEL.items():
        problems += problem(name, config[name], check)
    for block_name, keys in BLOCKS.items():
        block = config[block_name]
        if not isinstance(block, dict):
            problems.append(f"'{block_name}' in {where} must be a mapping of "
                            f"{', '.join(keys)}, got {block!r}")
            continue
        for key, check in keys.items():
            problems += problem(f"{block_name}.{key}", block[key], check)
    if "webhooks" in config:
        problems += problem("webhooks", config["webhooks"], _webhook_problem)
    return problems
