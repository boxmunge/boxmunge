# SPDX-License-Identifier: Apache-2.0
"""Operator notifications with every non-delivery surfaced.

Pushover is the operator's only out-of-band channel, so a notification
that was not delivered must never look as if it was. ``notify`` returns
True only when Pushover accepted the message, and logs why otherwise:

- config unreadable, missing, or its ``pushover`` block malformed: error
  (alerting is broken for the box);
- Pushover not configured: warning, at most once a day. Callers retry an
  undelivered alert on every run (check-all every five minutes), so logging
  each one buried the log in identical lines. The persistent signal is the
  ``alerts`` health check, which warns for as long as the keys are missing;
- the API call failed: error, every time (the reason is logged by
  ``boxmunge.pushover``).

Callers that track "alert sent" state record it only on True, so an
undelivered alert is retried on their next run.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from boxmunge.config import ConfigError, load_config
from boxmunge.fileutil import atomic_write_text
from boxmunge.log import log_error, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.pushover import send_notification

UNCONFIGURED_LOG_INTERVAL = timedelta(hours=24)


def pushover_credentials(config: dict[str, Any]) -> tuple[str, str]:
    """(user_key, app_token) from a loaded config; empty when not set.

    Raises ConfigError when ``pushover`` is not a mapping.
    """
    block = config.get("pushover") or {}
    if not isinstance(block, dict):
        raise ConfigError("'pushover' in boxmunge.yml must be a mapping with "
                          "user_key and app_token")
    return str(block.get("user_key") or ""), str(block.get("app_token") or "")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _unconfigured_logged_recently(paths: BoxPaths, now: datetime) -> bool:
    path = paths.alerts_unconfigured_state
    if not path.exists():
        return False
    try:
        logged_at = datetime.fromisoformat(json.loads(path.read_text())["logged_at"])
        if logged_at.tzinfo is None:
            raise ValueError("logged_at has no timezone")
    except (OSError, UnicodeDecodeError, ValueError, KeyError, TypeError) as e:
        log_error("alerts", f"{path} is unreadable ({e}); replacing it", paths)
        return False
    return now - logged_at < UNCONFIGURED_LOG_INTERVAL


def _log_unconfigured(paths: BoxPaths, component: str, title: str,
                      project: str | None) -> None:
    now = _now()
    if _unconfigured_logged_recently(paths, now):
        return
    log_warning(
        component,
        f"Alert not sent ({title}): Pushover is not configured "
        f"(pushover.user_key and pushover.app_token in boxmunge.yml). Unsent "
        f"alerts are logged once a day; the `alerts` health check reports this "
        f"until it is fixed",
        paths, project=project,
    )
    try:
        atomic_write_text(paths.alerts_unconfigured_state,
                          json.dumps({"logged_at": now.isoformat()}) + "\n")
    except OSError as e:
        log_error("alerts", f"Cannot record {paths.alerts_unconfigured_state} ({e}); "
                  f"the line above will repeat on every unsent alert", paths)


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
        user_key, app_token = pushover_credentials(load_config(paths))
    except ConfigError as e:
        log_error(component, f"Alert not sent ({title}): cannot load config: {e}",
                  paths, project=project)
        return False
    if not user_key or not app_token:
        _log_unconfigured(paths, component, title, project)
        return False
    if not send_notification(user_key, app_token, title, body, priority=priority):
        log_error(component, f"Alert not sent ({title}): Pushover request failed",
                  paths, project=project)
        return False
    return True
