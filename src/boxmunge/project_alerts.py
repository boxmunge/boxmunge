# SPDX-License-Identifier: Apache-2.0
"""Alerts sent once per project per condition, remembered across runs.

A condition (an old-schema repository manifest, a broken git layout) is
identified by a `kind` and a `key`, the facts that make it this condition
and not another. The alert goes out when no record exists or the key has
changed. The record under state/project-alerts/ is written only when
Pushover accepted the alert, so an undelivered one is retried next run.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.log import log_error, log_warning
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths

ALERT_KINDS = ("manifest-schema", "git-layout", "staged-slot", "production-down")


def alert_state(paths: BoxPaths, project: str, kind: str) -> Path:
    """The record of the `kind` alert last sent for `project`."""
    if kind not in ALERT_KINDS:
        raise ValueError(f"unknown alert kind {kind!r}; add it to ALERT_KINDS")
    return paths.project_alerts_dir(project) / f"{kind}.json"


def _already_alerted(paths: BoxPaths, project: str, kind: str, key: dict[str, Any]) -> bool:
    path = alert_state(paths, project, kind)
    if not path.exists():
        return False
    try:
        recorded = json.loads(path.read_text())
        if not isinstance(recorded, dict):
            raise ValueError("not a JSON object")
    except (OSError, UnicodeDecodeError, ValueError) as e:
        log_error("alerts", f"{path} is unreadable ({e}); alerting again and "
                  f"replacing it", paths, project=project)
        return False
    return recorded.get("key") == key


def alert_once(
    paths: BoxPaths, project: str, kind: str, key: dict[str, Any], *,
    title: str, message: str, component: str, priority: int = 0,
) -> None:
    """Log `message` as a warning and alert, unless this key was alerted."""
    if _already_alerted(paths, project, kind, key):
        return
    log_warning(component, message, paths, project=project)
    if not notify(paths, title, message, component=component, project=project,
                  priority=priority):
        return
    record = alert_state(paths, project, kind)
    try:
        atomic_write_text(record, json.dumps(
            {"key": key, "alerted_at": datetime.now(timezone.utc).isoformat()}) + "\n")
    except OSError as e:
        # The alert went out; the cost is that the next run sends it again.
        log_error(component, f"Cannot record {record} ({e}); the alert will "
                  f"repeat on the next run", paths, project=project)


def clear_alert(paths: BoxPaths, project: str, kind: str) -> None:
    """Forget a condition that no longer holds, so a recurrence alerts."""
    alert_state(paths, project, kind).unlink(missing_ok=True)
