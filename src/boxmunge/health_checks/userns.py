# SPDX-License-Identifier: Apache-2.0
"""Health check: is the Docker daemon remapped as this box records?

ok when remapped as recorded; warn on a box that has not migrated yet; error
when the record, the subid files, daemon.json and the running daemon
disagree (a daemon that restarted on another store or without remapping).
check-all, run by root's health timer, alerts on an error once a day.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.fileutil import atomic_write_text
from boxmunge.notify import notify
from boxmunge.userns.offset import RemapError, remap_offset

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "docker-userns"
_CHECK_COMMAND = "sudo /opt/boxmunge/bin/boxmunge-upgrade userns-migrate --check"
_ALERT_INTERVAL = timedelta(hours=24)
_ALERTING = frozenset({"error"})


def check_docker_userns(paths: BoxPaths) -> HealthCheck:
    try:
        s = remap_offset(paths)
    except RemapError as e:
        return HealthCheck(NAME, "error", str(e))
    if s == 0:
        return HealthCheck(
            NAME, "warn",
            "userns remapping is off: container root is host root for every file a "
            f"container can reach. Plan the migration: {_CHECK_COMMAND}")
    return HealthCheck(NAME, "ok", f"remapped: container uid N is host uid {s}+N (overlay2)")


def _alert_state(paths: BoxPaths) -> dict[str, str]:
    path = paths.state / "userns-alert.json"
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    return doc if isinstance(doc, dict) else {}


def alert_docker_userns(paths: BoxPaths, *, now: datetime | None = None) -> HealthCheck:
    """Run the check; send a priority-1 alert for an error, once a day per cause."""
    check = check_docker_userns(paths)
    if check.status not in _ALERTING:
        return check
    now = now or datetime.now(timezone.utc)
    key = hashlib.sha256(check.detail.encode()).hexdigest()[:16]
    state = _alert_state(paths)
    last = state.get(key)
    if last and now - datetime.fromisoformat(last) < _ALERT_INTERVAL:
        return check
    notify(paths, "Docker user-namespace remapping is broken", check.detail,
           component="health", priority=1)
    state[key] = now.isoformat()
    atomic_write_text(paths.state / "userns-alert.json", json.dumps(state) + "\n")
    return check
