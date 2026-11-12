# SPDX-License-Identifier: Apache-2.0
"""A release that needs a manual upgrade: say so once, at low priority.

Discovery reports ``manual`` when the newest release is one auto-update will
not install (a feature or breaking release) and that is not already a
blocked security or break-fix release, which has its own alert
(boxmunge.blocked_update). Auto-update calls ``record_manual`` after every
discovery:

- one priority -1 alert goes out per version, never a P1;
- an alert counts as sent only when Pushover accepted it, so an undelivered
  one is retried on the next run;
- the state is cleared when nothing needs a manual upgrade.

State lives in ``state/platform-manual-update.json`` (deploy-owned, written
atomically), apart from ``platform-updates.json`` so that a rollback to an
older release, which reads that file with a strict key set, still can. The
``platform-updates`` health check reads it.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.release_selection import VERSION_RE

COMPONENT = "auto-update"
_STATE_KEYS = {"version", "alerted_at"}


class ManualStateError(ValueError):
    """state/platform-manual-update.json is unreadable or not in the expected shape."""


def notice_text(version: str) -> str:
    return f"{version} is available and needs a manual upgrade: ask your agent to run `upgrade-howto`"


def read_manual(paths: BoxPaths) -> dict[str, Any] | None:
    """The release last announced, or None if none was."""
    path = paths.platform_manual_update
    try:
        raw = read_text_nofollow_or_none(path)
        if raw is None:
            return None
        state = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ManualStateError(f"{path}: unreadable: {e}") from e
    if not isinstance(state, dict) or set(state) != _STATE_KEYS:
        raise ManualStateError(f"{path}: expected keys {sorted(_STATE_KEYS)}")
    if not isinstance(state["version"], str) or not VERSION_RE.match(state["version"]):
        raise ManualStateError(f"{path}: 'version' is not X.Y.Z")
    try:
        at = datetime.fromisoformat(state["alerted_at"])
    except (TypeError, ValueError) as e:
        raise ManualStateError(f"{path}: 'alerted_at' is not a timestamp: {e}") from e
    if at.tzinfo is None:
        raise ManualStateError(f"{path}: 'alerted_at' has no timezone")
    return state


def _previous(paths: BoxPaths) -> dict[str, Any] | None:
    try:
        return read_manual(paths)
    except ManualStateError as e:
        print(f"ERROR: {e}; replacing it", file=sys.stderr)
        log_error(COMPONENT, f"Manual-update state {e}; replacing it", paths)
        return None


def record_manual(paths: BoxPaths, result: dict[str, Any],
                  *, now: datetime | None = None) -> None:
    """Announce ``result["manual"]`` once, or clear the state if it is None.

    ``result`` is any non-error discover_update result.
    """
    manual = result["manual"]
    if manual is None:
        paths.platform_manual_update.unlink(missing_ok=True)
        return
    version = manual["version"]
    previous = _previous(paths)
    if previous is not None and previous["version"] == version:
        return
    message = notice_text(version)
    print(f"NOTE: {message}")
    if notify(paths, f"{version} needs a manual upgrade", f"{message}\n{manual['url']}",
              component=COMPONENT, priority=-1):
        now = now or datetime.now(timezone.utc)
        atomic_write_text(paths.platform_manual_update, json.dumps(
            {"version": version, "alerted_at": now.isoformat()}, indent=2) + "\n")
        log_operation(COMPONENT, f"Alert sent: {message}", paths, detail={"version": version})
    else:
        log_warning(COMPONENT, f"Alert not delivered ({message}); retrying on the next run",
                    paths)
