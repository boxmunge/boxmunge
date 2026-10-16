# SPDX-License-Identifier: Apache-2.0
"""Blocked platform updates: alert the operator, remember what was said.

Discovery reports ``blocked`` when a security or break-fix release exists
that auto-update may not install, because a breaking release lies between
the box and it or it is in a new major version (boxmunge.release_selection).
Without a word, the box would sit behind a fix indefinitely, so auto-update
calls ``record_blocked`` whenever it has nothing to install:

- the blocked release is logged (warn) on every run;
- a priority-1 alert goes out when the blocked version changes, and again
  at most once every 24 hours while it stays blocked;
- an alert counts as sent only when Pushover accepted it, so an undelivered
  one is retried on the next run.

State lives in ``state/platform-updates.json`` (deploy-owned, written
atomically). The ``platform-updates`` health check reads it.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths

COMPONENT = "auto-update"
REMIND_AFTER = timedelta(hours=24)
_STATE_KEYS = {"checked_at", "current_version", "blocked", "alerted"}
CLASS_WORD = {"security": "Security", "breakfix": "Break-fix"}


class BlockedStateError(ValueError):
    """state/platform-updates.json is unreadable or not in the expected shape."""


def read_blocked_state(paths: BoxPaths) -> dict[str, Any] | None:
    """The last recorded discovery, or None if auto-update never recorded one."""
    path = paths.platform_update_state
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise BlockedStateError(f"{path}: unreadable: {e}") from e
    if not isinstance(state, dict) or set(state) != _STATE_KEYS:
        raise BlockedStateError(f"{path}: expected keys {sorted(_STATE_KEYS)}")
    blocked, alerted = state["blocked"], state["alerted"]
    if blocked is not None and not (
            isinstance(blocked, dict) and {"version", "url", "class", "reason"} <= set(blocked)):
        raise BlockedStateError(f"{path}: 'blocked' is not a blocked release")
    if alerted is not None and not (
            isinstance(alerted, dict) and set(alerted) == {"version", "at"}):
        raise BlockedStateError(f"{path}: 'alerted' must have version and at")
    if alerted is not None:
        try:
            at = datetime.fromisoformat(alerted["at"])
        except (TypeError, ValueError) as e:
            raise BlockedStateError(f"{path}: 'alerted.at' is not a timestamp: {e}") from e
        if at.tzinfo is None:
            raise BlockedStateError(f"{path}: 'alerted.at' has no timezone")
    return state


def describe_reason(blocked: dict[str, Any], current: str) -> str:
    """Why ``blocked`` cannot be installed automatically, as a clause."""
    reason = blocked["reason"]
    if "major" in reason:
        return (f"it is in major version {reason['major']} and this box runs {current}; "
                f"automatic updates never cross a major version")
    breaking = reason["breaking_release"]
    if breaking == blocked["version"]:
        return f"it is a breaking release, and this box runs {current}"
    return f"{breaking} between this box ({current}) and it is a breaking release"


def alert_text(blocked: dict[str, Any], current: str) -> tuple[str, str]:
    """(title, body) of the blocked-update alert."""
    word = CLASS_WORD[blocked["class"]]
    version = blocked["version"]
    title = f"[boxmunge] {word} release {version} needs a manual upgrade"
    body = (f"{word} release {version} cannot be installed automatically: "
            f"{describe_reason(blocked, current)}. Read the release notes, then run "
            f"`upgrade`.\n{blocked['url']}")
    return title, body


def _alert_due(alerted: dict[str, Any] | None, version: str, now: datetime) -> bool:
    if alerted is None or alerted["version"] != version:
        return True
    return now - datetime.fromisoformat(alerted["at"]) >= REMIND_AFTER


def _previous_alert(paths: BoxPaths) -> dict[str, Any] | None:
    try:
        state = read_blocked_state(paths)
    except BlockedStateError as e:
        print(f"ERROR: {e}; replacing it", file=sys.stderr)
        log_error(COMPONENT, f"Blocked-update state {e}; replacing it", paths)
        return None
    return state["alerted"] if state else None


def record_blocked(paths: BoxPaths, result: dict[str, Any],
                   *, now: datetime | None = None) -> None:
    """Record a discovery that installs nothing, alerting on a blocked release.

    ``result`` is an up_to_date or blocklisted discover_update result.
    """
    now = now or datetime.now(timezone.utc)
    blocked, current = result["blocked"], result["current_version"]
    alerted = _previous_alert(paths)
    if blocked is None:
        alerted = None
    else:
        title, body = alert_text(blocked, current)
        message = body.splitlines()[0]
        print(f"WARNING: {message}")
        log_warning(COMPONENT, message, paths,
                    detail={"blocked": blocked, "current_version": current,
                            "source": result["source"]})
        if _alert_due(alerted, blocked["version"], now):
            if notify(paths, title, body, component=COMPONENT, priority=1):
                alerted = {"version": blocked["version"], "at": now.isoformat()}
                log_operation(COMPONENT, f"Alert sent: {title}", paths,
                              detail={"version": blocked["version"]})
            else:
                log_warning(COMPONENT, f"Alert not delivered ({title}); "
                            f"retrying on the next run", paths)
        else:
            log_operation(COMPONENT, f"Alert for {blocked['version']} already sent at "
                          f"{alerted['at']}; next reminder after "
                          f"{(datetime.fromisoformat(alerted['at']) + REMIND_AFTER).isoformat()}",
                          paths)
    state = {"checked_at": now.isoformat(), "current_version": current,
             "blocked": blocked, "alerted": alerted}
    atomic_write_text(paths.platform_update_state, json.dumps(state, indent=2) + "\n")
