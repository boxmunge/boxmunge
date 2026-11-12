# SPDX-License-Identifier: Apache-2.0
"""The shape and value of each setting in the host configuration.

read_config runs these on the config with its defaults applied. What a
caller does with the result is its own: an interactive command refuses on
any of them, an unattended job only on the settings it reads (load_config).
Two blocks are checked by their one reader instead: `kev` (cve.kev_refresh)
and `userns` (userns.offset, which writes it).

No message here holds a setting's value: boxmunge.yml carries secrets (a
webhook URL, the Pushover keys, whatever was pasted on the wrong line), and
these messages go to the log, to alerts and to the API. Each names the
setting, what it must be and the kind of thing found.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable, NamedTuple

from boxmunge.manifest_fields import VALID_STRATEGIES


class Problem(NamedTuple):
    """A setting that is not what it must be."""
    setting: str  # dotted, e.g. "health.alert_threshold"; a block's own name if it is no mapping
    message: str


# None when the value is right, else (what it must be, the kind of thing found).
Check = Callable[[Any], "tuple[str, str] | None"]


def found(value: Any) -> str:
    """The kind of thing a value is, never the value."""
    if value is None:
        return "nothing"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, int):
        return "a whole number"
    if isinstance(value, float):
        return "a decimal number"
    if isinstance(value, str):
        return "a string" if value else "an empty string"
    if isinstance(value, list):
        return "a list"
    if isinstance(value, dict):
        return "a mapping"
    return f"a {type(value).__name__}"


def _whole_number(low: int, high: int | None = None) -> Check:
    """An integer in range. bool is an int to Python, and never one here:
    `alert_threshold: true` is a mistake, not 1."""
    what = (f"a whole number of at least {low}" if high is None
            else f"a whole number from {low} to {high}")

    def check(value: Any) -> tuple[str, str] | None:
        if not isinstance(value, int) or isinstance(value, bool):
            return what, found(value)
        if value < low or (high is not None and value > high):
            return what, "one outside that range"
        return None
    return check


def _boolean(value: Any) -> tuple[str, str] | None:
    return None if isinstance(value, bool) else ("true or false", found(value))


def _text(value: Any) -> tuple[str, str] | None:
    return None if isinstance(value, str) and value else ("a non-empty string", found(value))


def _optional_text(value: Any) -> tuple[str, str] | None:
    if value is None or isinstance(value, str):
        return None
    return 'a string ("" when unset)', found(value)


def _strategy(value: Any) -> tuple[str, str] | None:
    if isinstance(value, str) and value in VALID_STRATEGIES:
        return None
    return (f"one of {', '.join(VALID_STRATEGIES)}",
            "another string" if isinstance(value, str) else found(value))


# The events a webhook can subscribe to (webhooks.webhook_safe's callers).
WEBHOOK_EVENTS = ("deploy", "stage", "promote", "unstage", "rollback")


def hook_events(hook: dict[str, Any]) -> list[str] | None:
    """The events a hook subscribes to, or None when `events` is not a
    list of names. One known event name on its own is that one event:
    `events: deploy` fired before these checks existed, and still does."""
    events = hook.get("events", [])
    if isinstance(events, str):
        return [events] if events in WEBHOOK_EVENTS else None
    if isinstance(events, list) and all(isinstance(event, str) for event in events):
        return events
    return None


def hook_problems(hooks: Any) -> list[tuple[str, str, str]]:
    """`webhooks` is optional: a list of {url, events}. Each hook is
    judged on its own, as (setting, what it must be, kind found), so one
    that is wrong does not stop the others (webhooks skips it)."""
    if not isinstance(hooks, list):
        return [("webhooks", "a list of mappings, each with a url and events", found(hooks))]
    wrong: list[tuple[str, str, str]] = []
    for i, hook in enumerate(hooks):
        if not isinstance(hook, dict):
            wrong.append((f"webhooks[{i}]", "a mapping with a url and events", found(hook)))
            continue
        if _text(hook.get("url")) is not None:
            wrong.append((f"webhooks[{i}].url", "a non-empty string", found(hook.get("url"))))
        if hook_events(hook) is None:
            events = hook.get("events")
            wrong.append((
                f"webhooks[{i}].events",
                f"a list of event names, or one of {', '.join(WEBHOOK_EVENTS)} on its own",
                "another string" if isinstance(events, str) else found(events)))
    return wrong


TOP_LEVEL: dict[str, Check] = {
    "hostname": _text,
    "admin_email": _text,
    "ssh_port": _whole_number(1, 65535),
    "backup_remote": _optional_text,
}

# reboot_window is handed to the OS's unattended upgrades as written
# (bootstrap/init-host.sh), which take more forms than HH:MM; boxmunge
# never reads it, so only its type is checked.
BLOCKS: dict[str, dict[str, Check]] = {
    "pushover": {"user_key": _optional_text, "app_token": _optional_text},
    "health": {"check_interval_minutes": _whole_number(1),
               "alert_threshold": _whole_number(1)},
    "reboot": {"auto_reboot": _boolean, "reboot_window": _text},
    "logging": {"docker_max_size": _text, "docker_max_file": _whole_number(1)},
    "container_updates": {"enabled": _boolean, "strategy": _strategy},
}


def value_problems(config: dict[str, Any], where: object) -> list[Problem]:
    """Every setting in `config` (defaults applied) that is not what it
    must be, in the file's documented order."""
    def problem(name: str, value: Any, check: Check) -> list[Problem]:
        wrong = check(value)
        return [] if wrong is None else [Problem(
            name, f"'{name}' in {where} must be {wrong[0]}, found {wrong[1]}")]

    problems: list[Problem] = []
    for name, check in TOP_LEVEL.items():
        problems += problem(name, config[name], check)
    for block_name, keys in BLOCKS.items():
        block = config[block_name]
        if not isinstance(block, dict):
            problems.append(Problem(
                block_name, f"'{block_name}' in {where} must be a mapping of "
                            f"{', '.join(keys)}, found {found(block)}"))
            continue
        for key, check in keys.items():
            problems += problem(f"{block_name}.{key}", block[key], check)
    if "webhooks" in config:
        problems += [Problem(name, f"'{name}' in {where} must be {must_be}, found {kind}")
                     for name, must_be, kind in hook_problems(config["webhooks"])]
    return problems


def among(problems: Iterable[Problem], reads: Iterable[str]) -> list[Problem]:
    """The problems in the settings a caller reads. `reads` names settings
    or whole blocks (a list's entries are in it); a block that is no
    mapping is a problem in each of its settings."""
    reads = tuple(reads)

    def read(setting: str) -> bool:
        return any(setting == name or setting.startswith((name + ".", name + "["))
                   or name.startswith(setting + ".") for name in reads)
    return [p for p in problems if read(p.setting)]
