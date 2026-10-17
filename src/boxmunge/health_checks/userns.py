# SPDX-License-Identifier: Apache-2.0
"""Health check: is the Docker daemon remapped as this box records?

ok when remapped as recorded; warn on a box that has not migrated yet; error
when the record, the subid files, daemon.json and the running daemon
disagree (a daemon that restarted on another store or without remapping),
or when a remapped Caddy cannot read caddy/Caddyfile.
check-all, run by root's health timer, alerts on an error once a day.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import open_regular_nofollow
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


def _unclaimed_detail(error: RemapError) -> str:
    """The warning for a RemapError on a box boxmunge does not remap. Health
    exiting 2 during an upgrade's probation rolls the upgrade back, so this
    is never an error; deploys go on under the unremapped rules."""
    try:
        foreign = offset.daemon_json_userns(offset.ETC)
    except RemapError:
        foreign = None
    if foreign is not None:
        return (f"Docker already remaps user namespaces with userns-remap {foreign!r}, "
                f"not boxmunge's {offset.DAEMON_REMAP_VALUE!r}; the migration refuses "
                f"another identity. See OPERATIONS.md, 'User-namespace remapping'")
    return (f"cannot tell whether Docker remaps user namespaces (no boxmunge source "
            f"says it does): {error}")


def check_docker_userns(paths: BoxPaths) -> HealthCheck:
    try:
        s = remap_offset(paths)
    except RemapError as e:
        if offset.boxmunge_claims_remap(paths):
            return HealthCheck(NAME, "error", str(e))
        return HealthCheck(NAME, "warn", _unclaimed_detail(e))
    if s == 0:
        return HealthCheck(
            NAME, "warn",
            "userns remapping is off: container root is host root for every file a "
            f"container can reach. Plan the migration: {_CHECK_COMMAND}")
    problem = _caddyfile_problem(paths)
    if problem:
        return HealthCheck(NAME, "error", problem)
    return HealthCheck(NAME, "ok", f"remapped: container uid N is host uid {s}+N (overlay2)")


def _caddyfile_problem(paths: BoxPaths) -> str | None:
    """Remapped, Caddy's root is an "other" user to the root:deploy
    Caddyfile, so without the other-read bit Caddy cannot load its config."""
    caddyfile = paths.caddy / "Caddyfile"
    fix = f"sudo chmod 0644 {caddyfile}"
    try:
        st = os.lstat(caddyfile)
    except FileNotFoundError:
        return f"{caddyfile} does not exist, so Caddy has no config to load"
    if not stat.S_ISREG(st.st_mode):
        return (f"{caddyfile} is not a regular file (a link or a directory); replace it with "
                f"the file itself, then: {fix}")
    if not st.st_mode & stat.S_IROTH:
        return (f"{caddyfile} is mode {stat.S_IMODE(st.st_mode):04o}, which Caddy's remapped "
                f"root cannot read, so Caddy cannot load its config. Fix: {fix}")
    return None


def _alert_state(paths: BoxPaths, now: datetime) -> dict[str, str]:
    """{cause: when it was last alerted}. The deploy user can write state/,
    so the file is opened without following a symlink, a time in the future
    is refused, and no value from it reaches the log. An unusable file is
    reported and replaced: it can cost one repeated alert, never check-all."""
    path = paths.state / "userns-alert.json"
    try:
        fd = open_regular_nofollow(path, os.O_RDONLY)
        with os.fdopen(fd, "rb") as f:
            doc = json.loads(f.read().decode())
        if not isinstance(doc, dict) or not all(_past_time(w, now) for w in doc.values()):
            raise ValueError("expected an object of past timestamps with a time zone")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError, ValueError) as e:  # JSONDecodeError is a ValueError
        print(f"ERROR: {path} is unusable ({e}); replacing it", file=sys.stderr)
        log_error("health", f"{path} is unusable ({e}); replacing it", paths)
        return {}
    return doc


def _past_time(value: object, now: datetime) -> bool:
    if not isinstance(value, str):
        return False
    when = datetime.fromisoformat(value)  # ValueError: reported by the caller
    return when.tzinfo is not None and when <= now


def alert_docker_userns(paths: BoxPaths, *, now: datetime | None = None) -> HealthCheck:
    """Run the check; send a priority-1 alert for an error, once a day per cause.
    An alert that was not delivered is tried again on the next run."""
    check = check_docker_userns(paths)
    if check.status not in _ALERTING:
        return check
    now = now or datetime.now(timezone.utc)
    key = hashlib.sha256(check.detail.encode()).hexdigest()[:16]
    state = _alert_state(paths, now)
    last = state.get(key)
    if last and now - datetime.fromisoformat(last) < _ALERT_INTERVAL:
        return check
    if notify(paths, "Docker user-namespace remapping is broken", check.detail,
              component="health", priority=1):
        state[key] = now.isoformat()
        atomic_write_text(paths.state / "userns-alert.json", json.dumps(state) + "\n")
    return check
