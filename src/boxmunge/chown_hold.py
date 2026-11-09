# SPDX-License-Identifier: Apache-2.0
"""Keep a service `data chown` stopped from coming back on its own.

`data chown` leaves a service stopped for the deploy that runs it as its new
user. `docker stop` is not enough to keep it down: when the Docker daemon
starts (a reboot, a docker-ce upgrade) it restarts every stopped
`restart: always` container. So the service's containers are held at
restart policy "no", as pause and quarantine hold a whole project
(restart_hold), and the held containers are kept in the deploy state file.
The next production start of the service by boxmunge (the deploy, or any
start before it, which now runs the new user: the overlay is regenerated
with the record) gives each its release's own policy (release_policies):
a deploy may have recreated it under the same name from a release with
another policy, so no policy saved before is given back.

A paused or quarantined project's containers are held by that record
already, until its own exit; they are not held twice.
"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from boxmunge import pending_snapshot, restart_hold
from boxmunge.compose_resolve import ComposeResolveError
from boxmunge.docker import set_restart_policy
from boxmunge.docker_containers import project_containers
from boxmunge.docker_run import DockerError
from boxmunge.log import log_error
from boxmunge.release_policies import ReleasePolicyError, service_policy
from boxmunge.release_target import production_target, resolved_services
from boxmunge.state import StateError, read_state, write_state

if TYPE_CHECKING:
    from collections.abc import Collection

    from boxmunge.paths import BoxPaths

KEY = "chown_restart_hold"


def _held(paths: BoxPaths, project: str) -> dict[str, str]:
    """{container: its service} of the containers held."""
    entry = read_state(paths.project_deploy_state(project)).get(KEY) or {}
    if not (isinstance(entry, dict) and all(isinstance(v, str) for v in entry.values())):
        raise StateError(f"{paths.project_deploy_state(project)}: {KEY} is not a restart "
                         f"hold: {entry!r}")
    return entry


def _write(paths: BoxPaths, project: str, held: dict[str, str]) -> None:
    path = paths.project_deploy_state(project)
    state = read_state(path)
    if held:
        state[KEY] = held
    else:
        state.pop(KEY, None)
    write_state(path, state)


def hold(paths: BoxPaths, project: str, service: str) -> list[str]:
    """Set the restart policy of every container of `service` to "no",
    recording them first. Returns the containers held. Raises DockerError
    or StateError."""
    current = {c.name: c.restart_policy for c in project_containers(project)
               if c.service == service and not c.oneoff}
    if not current:
        return []
    _write(paths, project, {**_held(paths, project), **{n: service for n in current}})
    set_restart_policy(sorted(n for n, p in current.items() if p != "no"), "no")
    return sorted(current)


def release(paths: BoxPaths, project: str, services: Collection[str] | None) -> None:
    """Give the containers held for `services` (None: every service), which
    a start has just started, their release's own policy. One of a service
    the release no longer has is an orphan, and keeps "no". Raises
    DockerError, StateError, ComposeResolveError, ReleasePolicyError or
    OSError."""
    held = _held(paths, project)
    mine = {n: svc for n, svc in held.items() if services is None or svc in services}
    if not mine:
        return
    _model, model = resolved_services(production_target(paths, project))
    restart_hold.release(project, {n: service_policy(model[svc])
                                   for n, svc in mine.items() if svc in model})
    _write(paths, project, {n: svc for n, svc in held.items() if n not in mine})


def after_start(paths: BoxPaths, project: str, services: Collection[str] | None,
                component: str) -> None:
    """What data chown left for a service, once boxmunge has started it
    (`services`; None: every service): its restart policies go back, and a
    snapshot pending for the next deploy no longer holds the data that
    deploy would dump (pending_snapshot). Production is up by now, so a
    failure is said loudly and left for the next start to retry, not turned
    into a failed start."""
    try:
        pending_snapshot.drop_if_started(paths, project,
                                         None if services is None else set(services))
        release(paths, project, services)
    except (DockerError, StateError, ComposeResolveError, ReleasePolicyError, OSError) as e:
        message = (f"{project}: started, but what data chown left for it could not be "
                   f"undone: {e}. The next start tries again; until then a reboot may not "
                   f"restart the containers it held at restart policy \"no\".")
        print(f"ERROR: {message}", file=sys.stderr)
        log_error(component, message, paths, project=project)
