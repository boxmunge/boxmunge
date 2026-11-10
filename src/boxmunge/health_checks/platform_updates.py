# SPDX-License-Identifier: Apache-2.0
"""Health check: is the box behind a release auto-update cannot install,
has its update discovery gone 48 hours without a usable answer, or has
boxmunge.yml turned version checks off, so that it discovers nothing?

Reads what auto-update last recorded (boxmunge.blocked_update and
boxmunge.discovery_freshness). Warns, never errors: a security or break-fix release blocked by a breaking release needs
the operator, not a rollback, and ``health`` exiting 2 during upgrade
probation would roll the platform back.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.blocked_update import (
    CLASS_WORD, BlockedStateError, describe_reason, read_blocked_state,
)
from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.config import ConfigError
from boxmunge.discovery_freshness import DiscoveryStateError, stale_discovery_warning
from boxmunge.release_selection import newer
from boxmunge.version import parse_version_string, read_installed_version
from boxmunge.version_check_optout import OFF, version_checks_off

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "platform-updates"


def check_platform_updates(paths: BoxPaths) -> HealthCheck:
    try:
        if version_checks_off(paths):
            # What auto-update recorded before the opt-out is out of date.
            return HealthCheck(NAME, "warn", OFF)
    except ConfigError as e:
        return HealthCheck(NAME, "warn", f"cannot read boxmunge.yml, so auto-update cannot "
                                         f"run: {e}")
    blocked = _check_blocked(paths)
    try:
        stale = stale_discovery_warning(paths)
    except DiscoveryStateError as e:
        stale = f"cannot read update-discovery state: {e}"
    if stale is None:
        return blocked
    if blocked.status == "ok":
        return HealthCheck(NAME, "warn", stale)
    return HealthCheck(NAME, "warn", f"{blocked.detail}; {stale}")


def _check_blocked(paths: BoxPaths) -> HealthCheck:
    try:
        state = read_blocked_state(paths)
    except BlockedStateError as e:
        return HealthCheck(NAME, "warn", f"cannot read auto-update state: {e}")
    if state is None:
        return HealthCheck(NAME, "ok", "auto-update has not recorded a check yet")
    blocked = state["blocked"]
    if blocked is None:
        return HealthCheck(NAME, "ok", f"nothing out of reach (checked {state['checked_at']})")
    installed, _ = parse_version_string(read_installed_version(paths))
    if not newer(blocked["version"], installed):
        return HealthCheck(NAME, "ok", f"{blocked['version']} is installed")
    word = CLASS_WORD[blocked["class"]]
    return HealthCheck(
        NAME, "warn",
        f"{word} release {blocked['version']} cannot be installed automatically: "
        f"{describe_reason(blocked, installed)}. Read the release notes, then run `upgrade`")
