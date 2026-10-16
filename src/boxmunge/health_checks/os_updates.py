# SPDX-License-Identifier: Apache-2.0
"""Health check: are OS security updates actually being fetched?

Reports the evidence gathered by boxmunge.os_updates. Warns, never errors:
a dead apt source needs the operator, not a platform rollback, and
``health`` exiting 2 during upgrade probation would roll the platform back.
"""
from __future__ import annotations

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.os_updates import inspect_os_updates

NAME = "auto-updates"


def check_os_updates() -> HealthCheck:
    status = inspect_os_updates()
    if status.problems:
        return HealthCheck(NAME, "warn",
                           f"OS updates may not be installing: {status.summary()}")
    return HealthCheck(NAME, "ok", status.summary())
