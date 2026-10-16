# SPDX-License-Identifier: Apache-2.0
"""OS update failures: alert the operator, remember what was said.

``health`` runs only when someone runs it, so a box whose apt sources broke
could go months without anyone looking. The auto-update timer (every six
hours, as root) therefore inspects OS updates (boxmunge.os_updates) on every
run and calls ``record_os_updates``:

- each problem is logged (warn) on every run;
- a priority-1 alert goes out when the set of problems changes, and again
  at most once every 24 hours while it stays the same (problems are compared
  by key, so "3d ago" becoming "3d 6h ago" is not a change);
- an alert counts as sent only when Pushover accepted it, so an undelivered
  one is retried on the next run;
- recovery is logged and clears the state, so a later failure alerts afresh.

State lives in ``state/os-updates.json`` (deploy-owned, written atomically).
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.os_updates import OsUpdateStatus
from boxmunge.paths import BoxPaths

COMPONENT = "auto-update"
REMIND_AFTER = timedelta(hours=24)
_STATE_KEYS = {"checked_at", "problems", "alerted"}
TITLE = "OS updates are not being installed"


class OsUpdateStateError(ValueError):
    """state/os-updates.json is unreadable or not in the expected shape."""


def _is_key_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(k, str) for k in value)


def read_os_update_state(paths: BoxPaths) -> dict[str, Any] | None:
    """The last recorded check, or None if auto-update never recorded one."""
    path = paths.os_update_state
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise OsUpdateStateError(f"{path}: unreadable: {e}") from e
    if not isinstance(state, dict) or set(state) != _STATE_KEYS:
        raise OsUpdateStateError(f"{path}: expected keys {sorted(_STATE_KEYS)}")
    if not _is_key_list(state["problems"]):
        raise OsUpdateStateError(f"{path}: 'problems' must be a list of strings")
    alerted = state["alerted"]
    if alerted is not None:
        if not (isinstance(alerted, dict) and set(alerted) == {"problems", "at"}
                and _is_key_list(alerted["problems"])):
            raise OsUpdateStateError(f"{path}: 'alerted' must have problems and at")
        try:
            at = datetime.fromisoformat(alerted["at"])
        except (TypeError, ValueError) as e:
            raise OsUpdateStateError(f"{path}: 'alerted.at' is not a timestamp: {e}") from e
        if at.tzinfo is None:
            raise OsUpdateStateError(f"{path}: 'alerted.at' has no timezone")
    return state


def _previous_alert(paths: BoxPaths) -> dict[str, Any] | None:
    try:
        state = read_os_update_state(paths)
    except OsUpdateStateError as e:
        print(f"ERROR: {e}; replacing it", file=sys.stderr)
        log_error(COMPONENT, f"OS-update state {e}; replacing it", paths)
        return None
    return state["alerted"] if state else None


def _alert_due(alerted: dict[str, Any] | None, keys: list[str], now: datetime) -> bool:
    if alerted is None or alerted["problems"] != keys:
        return True
    return now - datetime.fromisoformat(alerted["at"]) >= REMIND_AFTER


def record_os_updates(paths: BoxPaths, status: OsUpdateStatus,
                      *, now: datetime | None = None) -> None:
    """Log, alert on and record one OS-update inspection."""
    now = now or datetime.now(timezone.utc)
    keys = sorted(p.key for p in status.problems)
    alerted = _previous_alert(paths)
    if not keys:
        if alerted is not None:
            log_operation(COMPONENT, f"OS updates are working again: {status.summary()}",
                          paths)
        alerted = None
    else:
        message = f"OS updates may not be installing: {status.summary()}"
        print(f"WARNING: {message}")
        log_warning(COMPONENT, message, paths, detail={"problems": keys})
        if _alert_due(alerted, keys, now):
            if notify(paths, TITLE, message, component=COMPONENT, priority=1):
                alerted = {"problems": keys, "at": now.isoformat()}
                log_operation(COMPONENT, f"Alert sent: {TITLE}", paths,
                              detail={"problems": keys})
            else:
                log_warning(COMPONENT, f"Alert not delivered ({TITLE}); "
                            f"retrying on the next run", paths)
        else:
            assert alerted is not None
            reminder = datetime.fromisoformat(alerted["at"]) + REMIND_AFTER
            log_operation(COMPONENT, f"OS-update alert already sent at {alerted['at']}; "
                          f"next reminder after {reminder.isoformat()}", paths)
    state = {"checked_at": now.isoformat(), "problems": keys, "alerted": alerted}
    atomic_write_text(paths.os_update_state, json.dumps(state, indent=2) + "\n")
