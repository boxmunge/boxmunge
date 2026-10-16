# SPDX-License-Identifier: Apache-2.0
"""Health check: is the box behind a release auto-update cannot install?

Reads what auto-update last recorded (boxmunge.blocked_update). Warns, never
errors: a security or break-fix release blocked by a breaking release needs
the operator, not a rollback, and ``health`` exiting 2 during upgrade
probation would roll the platform back.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.blocked_update import (
    CLASS_WORD, BlockedStateError, describe_reason, read_blocked_state,
)
from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.release_selection import newer
from boxmunge.version import parse_version_string, read_installed_version

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "platform-updates"


def check_platform_updates(paths: BoxPaths) -> HealthCheck:
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
