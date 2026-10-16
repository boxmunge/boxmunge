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
import sys
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.fileutil import atomic_write_text
from boxmunge.log import log_error
from boxmunge.notify import notify
from boxmunge.userns import offset
from boxmunge.userns.offset import RemapError, remap_offset

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "docker-userns"
_CHECK_COMMAND = "sudo /opt/boxmunge/bin/boxmunge-upgrade userns-migrate --check"
_ALERT_INTERVAL = timedelta(hours=24)
_ALERTING = frozenset({"error"})


def _remap_claimed(paths: BoxPaths) -> bool:
    """Does any source that can be read say this box is remapped?

    Only grades a RemapError. Health exiting 2 during an upgrade's probation
    rolls the upgrade back, so a file that cannot be read, or a daemon that
    does not answer (the docker check reports that), on a box nothing says
    is remapped is a warning, not an error.
    """
    probes = (lambda: offset.recorded_offset(paths) is not None,
              lambda: offset.daemon_json_userns(offset.ETC) is not None,
              lambda: "name=userns" in (offset.docker_info().get("SecurityOptions") or []))
    for probe in probes:
        try:
            if probe():
                return True
        except RemapError:
            continue  # this source is already named in the error being graded
    return False


def check_docker_userns(paths: BoxPaths) -> HealthCheck:
    try:
        s = remap_offset(paths)
    except RemapError as e:
        if _remap_claimed(paths):
            return HealthCheck(NAME, "error", str(e))
        return HealthCheck(NAME, "warn", f"cannot tell whether Docker remaps user "
                           f"namespaces (nothing says it does yet): {e}")
    if s == 0:
        return HealthCheck(
            NAME, "warn",
            "userns remapping is off: container root is host root for every file a "
            f"container can reach. Plan the migration: {_CHECK_COMMAND}")
    return HealthCheck(NAME, "ok", f"remapped: container uid N is host uid {s}+N (overlay2)")


def _alert_state(paths: BoxPaths) -> dict[str, str]:
    """{cause: when it was last alerted}. An unusable file is reported and
    replaced, so it can cost one repeated alert but never stop check-all."""
    path = paths.state / "userns-alert.json"
    try:
        doc = json.loads(path.read_text())
        if not isinstance(doc, dict):
            raise ValueError("not a JSON object")
        for when in doc.values():
            if not isinstance(when, str) or datetime.fromisoformat(when).tzinfo is None:
                raise ValueError(f"{when!r} is not a timestamp with a time zone")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError, ValueError) as e:  # JSONDecodeError is a ValueError
        print(f"ERROR: {path} is unusable ({e}); replacing it", file=sys.stderr)
        log_error("health", f"{path} is unusable ({e}); replacing it", paths)
        return {}
    return doc


def alert_docker_userns(paths: BoxPaths, *, now: datetime | None = None) -> HealthCheck:
    """Run the check; send a priority-1 alert for an error, once a day per cause.
    An alert that was not delivered is tried again on the next run."""
    check = check_docker_userns(paths)
    if check.status not in _ALERTING:
        return check
    now = now or datetime.now(timezone.utc)
    key = hashlib.sha256(check.detail.encode()).hexdigest()[:16]
    state = _alert_state(paths)
    last = state.get(key)
    if last and now - datetime.fromisoformat(last) < _ALERT_INTERVAL:
        return check
    if notify(paths, "Docker user-namespace remapping is broken", check.detail,
              component="health", priority=1):
        state[key] = now.isoformat()
        atomic_write_text(paths.state / "userns-alert.json", json.dumps(state) + "\n")
    return check
