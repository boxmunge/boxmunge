# SPDX-License-Identifier: Apache-2.0
"""Health check: is every setting in boxmunge.yml what it must be?

The standing signal for a wrong setting, with or without Pushover: the
unattended jobs alert it once a day at most (host_config_alert) and
otherwise carry on unless they read it.

Warns, never errors. The upgrade shim rolls a release back, and blocklists
it, on a check that errors in the new release and did not in the old one;
this check is new, so an error here would do that to every box carrying a
value it has always run with.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.config import ConfigError, read_config

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "host-config"


def check_host_config(paths: BoxPaths) -> HealthCheck:
    try:
        _, problems = read_config(paths)
    except ConfigError as e:
        return HealthCheck(NAME, "warn", f"the host config cannot be loaded: {e}")
    if not problems:
        return HealthCheck(NAME, "ok", "every setting in boxmunge.yml is valid")
    return HealthCheck(
        NAME, "warn",
        f"{len(problems)} setting(s) need correcting: "
        f"{'; '.join(p.message for p in problems)}. A job that reads one of them refuses "
        f"to run, as do the commands you run by hand; everything else carries on")
