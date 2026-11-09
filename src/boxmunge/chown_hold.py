# SPDX-License-Identifier: Apache-2.0
"""Keep a service `data chown` stopped from coming back on its own.

`data chown` leaves a service stopped for the deploy that runs it as its new
user. `docker stop` is not enough to keep it down: when the Docker daemon
starts (a reboot, a docker-ce upgrade) it restarts every stopped
`restart: always` container. So the service's containers are held at
restart policy "no", as pause and quarantine hold a whole project
(restart_hold), and the originals are kept in the deploy state file. The
next production start of the service by boxmunge (the deploy, or any start
before it, which now runs the new user: the overlay is regenerated with the
record) gives them back (compose_guard).

A paused or quarantined project's containers are held by that record
already, whose own exit gives the originals back; they are not held twice.
"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from boxmunge import restart_hold
from boxmunge.docker import set_restart_policy
from boxmunge.docker_containers import project_containers
from boxmunge.docker_run import DockerError
from boxmunge.log import log_error
from boxmunge.state import StateError, read_state, write_state

if TYPE_CHECKING:
    from collections.abc import Collection

    from boxmunge.paths import BoxPaths

KEY = "chown_restart_hold"


def _held(paths: BoxPaths, project: str) -> dict[str, dict[str, str]]:
    entry = read_state(paths.project_deploy_state(project)).get(KEY) or {}
    if not (isinstance(entry, dict) and all(
            isinstance(v, dict) and isinstance(v.get("service"), str)
            and isinstance(v.get("policy"), str) for v in entry.values())):
        raise StateError(f"{paths.project_deploy_state(project)}: {KEY} is not a restart "
                         f"hold: {entry!r}")
    return entry


def _write(paths: BoxPaths, project: str, held: dict[str, dict[str, str]]) -> None:
    path = paths.project_deploy_state(project)
    state = read_state(path)
    if held:
        state[KEY] = held
    else:
        state.pop(KEY, None)
    write_state(path, state)


def hold(paths: BoxPaths, project: str, service: str) -> list[str]:
    """Set the restart policy of every container of `service` to "no",
    keeping the originals (a policy saved by an earlier hold is kept: it is
    the real one). Returns the containers held. Raises DockerError or
    StateError."""
    current = {c.name: c.restart_policy for c in project_containers(project)
               if c.service == service and not c.oneoff}
    names = sorted(current)
    if not names:
        return []
    held = _held(paths, project)
    for name in names:
        held.setdefault(name, {"service": service, "policy": current[name]})
    # Saved before any policy changes: a hold that fails part-way, then a
    # re-run that sees "no", never saves "no" as an original.
    _write(paths, project, held)
    set_restart_policy([n for n in names if current[n] != "no"], "no")
    return names


def release(paths: BoxPaths, project: str, services: Collection[str] | None) -> None:
    """Give back the policies held for `services` (None: every service),
    which a start has just started. Raises DockerError or StateError."""
    held = _held(paths, project)
    mine = {n: v for n, v in held.items() if services is None or v["service"] in services}
    if not mine:
        return
    restart_hold.release(project, {n: v["policy"] for n, v in mine.items()})
    _write(paths, project, {n: v for n, v in held.items() if n not in mine})


def release_after_start(paths: BoxPaths, project: str, services: Collection[str] | None,
                        component: str) -> None:
    """release, for a start that has just run: production is up by now, so
    a failure is said loudly and left for the next start to retry, not
    turned into a failed start."""
    try:
        release(paths, project, services)
    except (DockerError, StateError) as e:
        message = (f"{project}: started, but the restart policies data chown held at "
                   f"\"no\" could not be given back: {e}. The next start tries again; "
                   f"until then a reboot does not restart those containers.")
        print(f"ERROR: {message}", file=sys.stderr)
        log_error(component, message, paths, project=project)
