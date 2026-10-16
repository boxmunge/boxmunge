# SPDX-License-Identifier: Apache-2.0
"""Health check: can this box alert its operator at all?

Without Pushover keys every alert (health failures, quarantines, failed
container updates, blocked security releases, failing OS updates) is
dropped, and ``notify`` logs that only once a day. This check is the
persistent signal. Warns, never errors: a box without alerting still runs,
and ``health`` exiting 2 during upgrade probation would roll it back.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.config import ConfigError, load_config
from boxmunge.notify import pushover_credentials

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "alerts"
_DROPPED = ("health failures, CVE quarantines, failed container updates, blocked "
            "security releases and failing OS updates go unreported")


def check_alerts(paths: BoxPaths) -> HealthCheck:
    try:
        user_key, app_token = pushover_credentials(load_config(paths))
    except ConfigError as e:
        return HealthCheck(NAME, "warn", f"cannot load config, so no alert can be sent: {e}")
    missing = [f"pushover.{k}" for k, v in (("user_key", user_key), ("app_token", app_token))
               if not v]
    if missing:
        return HealthCheck(
            NAME, "warn",
            f"Pushover is not configured ({', '.join(missing)} missing), so nothing on "
            f"this box can alert you: {_DROPPED}. Set user_key and app_token under "
            f"`pushover:` in {paths.config_file}, then run `test-alert`")
    return HealthCheck(NAME, "ok", "Pushover configured (`test-alert` confirms delivery)")
