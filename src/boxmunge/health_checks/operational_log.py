# SPDX-License-Identifier: Apache-2.0
"""Health check: can boxmunge still write its operational log?

Rotation reads the active log's first entry to learn its day. If that line
is not a log entry, every write fails (reported on stderr only), so the
log-based checks such as recent-errors go quiet instead of failing. This
check reads the file directly. Warns, never errors: ``health`` exiting 2
during upgrade probation would roll back an upgrade that did not cause it.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.log_rotation import first_entry_day

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "operational-log"


def check_operational_log(paths: BoxPaths) -> HealthCheck:
    try:
        first_entry_day(paths.log_file)
    except FileNotFoundError:
        return HealthCheck(NAME, "ok", "No operational log yet")
    except (ValueError, OSError) as e:
        return HealthCheck(NAME, "warn", f"Operational log is not being written: {e}")
    return HealthCheck(NAME, "ok", "Operational log is well-formed")
