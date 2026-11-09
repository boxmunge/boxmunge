# SPDX-License-Identifier: Apache-2.0
"""A deploy that ends a pause handed to it.

`resume <project> --no-start` leaves a paused project down but hands the
pause to the next deploy (pause.awaiting_deploy): the way out when only a
deploy can repair what resume refuses to start. Until that deploy starts
it, the project is paused for everything else: the maintenance page stays
up, its containers stay stopped with their restart policies held, and the
timers skip it.

The deploy leaves the maintenance site in place while it prepares
(release_config.generate_release_config), gives the containers their
restart policies back just before the start, as resume does, and ends the
pause once `compose up` has run: production runs the release from then
on, whatever fails afterwards. A start that stops before the up holds the
policies again, and the project stays paused, awaiting a deploy.
"""
from __future__ import annotations

import sys

from boxmunge.caddy import prepare_caddy_config
from boxmunge.docker_run import DockerError
from boxmunge.log import log_error, log_operation
from boxmunge.pause import (
    awaiting_deploy, clear_paused_state, hold_restart_policies, release_restart_policies,
)
from boxmunge.paths import BoxPaths


def begin(paths: BoxPaths, project: str) -> bool:
    """True when this deploy ends a pause; its containers then have their
    restart policies back. Raises DockerError (nothing started)."""
    if not awaiting_deploy(project, paths):
        return False
    release_restart_policies(project, paths)
    return True


def keep(paths: BoxPaths, project: str, component: str) -> None:
    """The start stopped before the up: hold the restart policies again, so
    a Docker restart cannot start what stays paused. A failure is said
    loudly; the pause record keeps the originals either way."""
    try:
        hold_restart_policies(project, paths)
    except DockerError as e:
        message = (f"{project} stays paused, but its restart policies could not be held "
                   f"again: {e}. A Docker restart may start its `restart: always` "
                   f"services; deploy it again once Docker answers.")
        print(f"ERROR: {message}", file=sys.stderr)
        log_error(component, message, paths, project=project)
        return
    print(f"  {project} stays paused, awaiting a deploy: its maintenance page stays up.",
          file=sys.stderr)


def end(paths: BoxPaths, project: str, manifest: dict, component: str) -> None:
    """`compose up` has run: the pause is over, and the release's own site
    replaces the maintenance page (the deploy reloads Caddy next)."""
    clear_paused_state(project, paths)
    log_operation(component, "Pause ended by the deploy it was handed to", paths,
                  project=project)
    print(f"  The pause of {project} ended: its containers were started.")
    try:
        prepare_caddy_config(paths, manifest)
    except (OSError, ValueError) as e:
        message = (f"{project} is no longer paused, but its site config could not be "
                   f"written ({e}), so the maintenance page stays up; deploy it again "
                   f"once the cause is fixed.")
        print(f"ERROR: {message}", file=sys.stderr)
        log_error(component, message, paths, project=project)
