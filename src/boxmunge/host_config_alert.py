# SPDX-License-Identifier: Apache-2.0
"""Telling the operator that boxmunge.yml holds a wrong setting.

The unattended jobs (check-all, container-update, backup-sync, the KEV
refresh, auto-update, and every start of a project's containers, which an
upgrade's restart and a rollback go through) do not stop over a setting
they do not read: a box keeps running with a value it has always carried.
Each one that meets such a config says so here instead, and then refuses
only if a setting it reads is among them (load_for_job).

One alert for one set of problems, whichever job meets it first and
however many do: start_alerts paces it by the problems' text, in one
record beside the projects' own. It counts as sent only when notify
delivered it, and repeats daily while the problems stay; an undelivered
one is tried again hourly. The log line is
paced the same way. The `host-config` health check is the standing
signal, and needs no Pushover.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from boxmunge import start_alerts
from boxmunge.config import ConfigError, read_config
from boxmunge.config_values import Problem, among
from boxmunge.log import log_warning
from boxmunge.notify import notify

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# The record start_alerts paces this by. Not a project's name: none can
# hold a dot.
_RECORD = "boxmunge.yml"
TITLE = "boxmunge.yml needs correcting"
# check-all meets the config every few minutes. While the alert cannot be
# delivered, each try can take the Pushover timeout and logs an error, so
# an undelivered one is tried again this often rather than every tick.
_RETRY_INTERVAL = timedelta(hours=1)


def load_for_job(paths: BoxPaths, component: str, *,
                 reads: tuple[str, ...] = ()) -> dict[str, Any]:
    """The config for an unattended job that reads the settings `reads`.

    Any wrong setting is reported to the operator. One the job reads then
    raises ConfigError naming it; the rest are returned as written. Raises
    ConfigError as load_config does for a config that cannot be loaded.
    """
    config, problems = read_config(paths)
    _tell(paths, component, problems)
    refused = among(problems, reads)
    if refused:
        raise ConfigError("; ".join(p.message for p in refused))
    return config


def report(paths: BoxPaths, component: str) -> None:
    """For a job that reads no setting itself: tell the operator of any
    wrong one. Raises ConfigError for a config that cannot be loaded."""
    load_for_job(paths, component)


def report_at_start(paths: BoxPaths, component: str) -> None:
    """Before a start of a project's containers. A start reads no host
    setting, so a config that cannot be loaded at all is not its business:
    notify logs that when the start has something to alert, and check-all
    reports it on every tick."""
    try:
        report(paths, component)
    except ConfigError:
        pass


def _tell(paths: BoxPaths, component: str, problems: list[Problem]) -> None:
    if not problems:
        return
    reason = "; ".join(p.message for p in problems)
    now = datetime.now(timezone.utc)
    message = (f"{len(problems)} setting(s) in the host config are not what they must be: "
               f"{reason}. A job that reads one of them refuses to run until it is "
               f"corrected, as do the commands you run by hand; everything else carries "
               f"on. `health` lists them under host-config.")
    logged = f"logged: {reason}"
    if not start_alerts.alerted_recently(paths, _RECORD, logged, now):
        log_warning(component, message, paths)
        start_alerts.record_or_warn(paths, _RECORD, logged, now, component)
    tried = f"tried: {reason}"
    if (start_alerts.alerted_recently(paths, _RECORD, reason, now)
            or start_alerts.alerted_recently(paths, _RECORD, tried, now, _RETRY_INTERVAL)):
        return
    delivered = notify(paths, TITLE, message, component=component)
    start_alerts.record_or_warn(paths, _RECORD, reason if delivered else tried, now, component)
