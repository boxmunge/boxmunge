# SPDX-License-Identifier: Apache-2.0
"""The host config's refused values, on the paths that only warn of them.

load_config refuses a setting config_values rejects, so `container-update`,
`backup-sync` and the other commands that read boxmunge.yml refuse to
run, naming it. Three paths do not refuse: the platform upgrade
(auto-update's discovery), every start of a project's containers (which
the upgrade's restart and a rollback go through) and the alerts
themselves. Refusing there would stop a box, or silence it, over a value
it ran with until this release; the same reasoning as validate_manifest's
`lenient_values`. Those paths log the settings as a warning and alert the
operator, at most once a day once the alert is delivered.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from boxmunge import start_alerts
from boxmunge.config import ConfigError, read_config
from boxmunge.log import log_warning
from boxmunge.notify import notify

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# The record start_alerts paces this alert by, beside the projects' own in
# state/start-refused/. Not a project's name: none can hold a dot.
_RECORD = "boxmunge.yml"


def load_lenient(paths: BoxPaths, component: str) -> dict[str, Any]:
    """load_config(lenient_values=True), reporting the values it let
    through. Raises ConfigError for what stays an error."""
    config, problems = read_config(paths)
    if problems:
        _warn_and_alert(paths, component, problems)
    return config


def report_at_start(paths: BoxPaths, component: str) -> None:
    """Before a start of a project's containers. A start reads no host
    setting, so a config that cannot be loaded at all is not refused here:
    notify logs that when the start has something to alert, and `health`
    reports it on every tick."""
    try:
        load_lenient(paths, component)
    except ConfigError:
        pass


def _warn_and_alert(paths: BoxPaths, component: str, problems: list[str]) -> None:
    reason = "; ".join(problems)
    now = datetime.now(timezone.utc)
    if start_alerts.alerted_recently(paths, _RECORD, reason, now):
        return
    message = (f"The host config holds values this release refuses: {reason}. "
               f"Upgrades, starts, rollbacks and alerts carry on. Until each is corrected "
               f"in {paths.config_file}, the other commands that read it refuse to run, "
               f"`container-update` and `backup-sync` among them.")
    log_warning(component, message, paths)
    if notify(paths, "boxmunge.yml needs correcting", message, component=component):
        start_alerts.record(paths, _RECORD, reason, now)
