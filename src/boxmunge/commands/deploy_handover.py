# SPDX-License-Identifier: Apache-2.0
"""A deploy that ends a pause handed to it.

`resume <project> --no-start` leaves a paused project down but hands the
pause to the next deploy or rollback (pause.awaiting_deploy; a rollback's
start runs through here too): the way out when only a
deploy can repair what resume refuses to start. Until that deploy starts
it, the project is paused for everything else: the maintenance page stays
up, its containers stay stopped with their restart policies held, and the
timers skip it. The pause's snapshot (commands/pause_snapshot) is that
deploy's pre-deploy snapshot.

The deploy leaves the maintenance site in place while it prepares
(release_config.generate_release_config), and the restart policies held
until `compose up` has started the containers. Then the policies go back,
the release's site replaces the maintenance page and the pause ends: from
then on production runs the release, whatever fails afterwards. A start
that stops before the up changes nothing: the project stays paused,
awaiting a deploy. An up that fails part-way stops the project again and
keeps the pause, so no half-started release runs behind a maintenance
page or under stale routing.
"""
from __future__ import annotations

import sys

from boxmunge.caddy import prepare_caddy_config
from boxmunge.docker_run import DockerError
from boxmunge.log import log_error, log_operation
from boxmunge.pause import (
    awaiting_deploy, clear_paused_state, mark_pause_incomplete, read_paused_state,
    release_restart_policies, stop_again,
)
from boxmunge.paths import BoxPaths


def pending(paths: BoxPaths, project: str) -> bool:
    """True when this deploy ends a pause."""
    return awaiting_deploy(project, paths)


def not_started(project: str) -> None:
    print(f"  {project} stays paused, awaiting a deploy: nothing was started and its "
          f"maintenance page stays up.", file=sys.stderr)


def failed_start(paths: BoxPaths, project: str, component: str) -> None:
    """`compose up` failed part-way: stop what it started and hold the
    restart policies again, so the project is paused as before. A step that
    fails marks the pause incomplete, which `pause` finishes."""
    try:
        stop_again(project, paths)
    except DockerError as e:
        mark_pause_incomplete(project, paths)
        message = (f"{project} stays paused, but stopping what the failed start started, "
                   f"or holding its restart policies, failed: {e}. It may be running behind "
                   f"its maintenance page; run `boxmunge pause {project}` to finish the "
                   f"pause, then deploy again.")
        print(f"ERROR: {message}", file=sys.stderr)
        log_error(component, message, paths, project=project)
        return
    print(f"  {project} stays paused, awaiting a deploy: what the failed start started was "
          f"stopped again, and its maintenance page stays up. Deploy again once the cause "
          f"is fixed, or `boxmunge rollback {project}` to the release it replaced (with the "
          f"data snapshot paired with it); either ends the pause once it starts.",
          file=sys.stderr)


def end(paths: BoxPaths, project: str, manifest: dict, component: str) -> None:
    """`compose up` has started the containers: they get their restart
    policies back, the pause ends, and the release's own site replaces the
    maintenance page (the deploy reloads Caddy next)."""
    saved = (read_paused_state(project, paths) or {}).get("restart_policies") or {}
    try:
        release_restart_policies(project, paths)
    except DockerError as e:
        message = (f"{project} runs, but its containers' restart policies could not be "
                   f"given back ({e}): a Docker restart will not restart them. The "
                   f"originals were {saved}; deploy it again, or set them with "
                   f"`docker update --restart`.")
        print(f"ERROR: {message}", file=sys.stderr)
        log_error(component, message, paths, project=project, detail={"policies": saved})
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
