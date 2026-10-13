# SPDX-License-Identifier: Apache-2.0
"""Operator notifications with every non-delivery surfaced in the log.

Pushover is the operator's only out-of-band channel, so a notification
that was not delivered must never look as if it was. ``notify`` returns
True only when Pushover accepted the message, and logs why otherwise:

- config unreadable or missing: error (alerting is broken for the box);
- Pushover not configured: warning (a supported setup, but the operator
  should know the alert went nowhere);
- the API call failed: error (the reason is logged by ``boxmunge.pushover``).

Callers that track "alert sent" state record it only on True, so an
undelivered alert is retried on their next run.
"""
from __future__ import annotations

from boxmunge.config import ConfigError, load_config
from boxmunge.log import log_error, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.pushover import send_notification


def notify(
    paths: BoxPaths,
    title: str,
    body: str,
    *,
    component: str,
    project: str | None = None,
    priority: int = 0,
) -> bool:
    """Send a Pushover notification. True only if it was delivered."""
    try:
        config = load_config(paths)
    except ConfigError as e:
        log_error(component, f"Alert not sent ({title}): cannot load config: {e}",
                  paths, project=project)
        return False
    pushover = config.get("pushover") or {}
    user_key = pushover.get("user_key", "")
    app_token = pushover.get("app_token", "")
    if not user_key or not app_token:
        log_warning(
            component,
            f"Alert not sent ({title}): Pushover is not configured "
            f"(pushover.user_key and pushover.app_token in boxmunge.yml)",
            paths, project=project,
        )
        return False
    if not send_notification(user_key, app_token, title, body, priority=priority):
        log_error(component, f"Alert not sent ({title}): Pushover request failed",
                  paths, project=project)
        return False
    return True
