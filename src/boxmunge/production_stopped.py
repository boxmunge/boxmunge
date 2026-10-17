# SPDX-License-Identifier: Apache-2.0
"""The slot's production_stopped marker.

A ``copy_data`` stage stops production's running containers to copy their
data. The marker (the container names) is written durably before the stop
and cleared once production runs again, so production never stays stopped
because of staging: whoever finds the marker with the lock free (a copy
that crashed) starts production again: the health tick, stage, unstage and
recover. Any other production up clears it (compose_guard). A paused or
quarantined project stays down: its lift is such an up.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from boxmunge import docker_containers
from boxmunge.compose_guard import compose_up_checked, start_containers_checked
from boxmunge.docker_run import DockerError
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_error, log_operation
from boxmunge.notify import notify
from boxmunge.staged_release import StagedRelease, load_slot, update_meta

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

PROD_FILES = ["compose.yml", "compose.boxmunge.yml"]


class ProductionDownError(DockerError):
    """Production was stopped for the copy and could not be started again."""


def mark_stopped(paths: BoxPaths, project: str, meta: StagedRelease,
                 containers: list[str]) -> StagedRelease:
    return update_meta(paths, project, meta, production_stopped={
        "at": datetime.now(timezone.utc).isoformat(), "containers": list(containers)})


def _start(paths: BoxPaths, project: str, names: list[str], component: str) -> None:
    # `docker start` brings back exactly what was stopped; a container gone
    # since (removed by hand, a crashed recreate) needs production's up.
    present = {c.name for c in docker_containers.project_containers(project)}
    if names and set(names) <= present:
        start_containers_checked(paths, project, names, component=component)
    else:
        compose_up_checked(paths, project, component=component, compose_files=PROD_FILES)


def start_again(paths: BoxPaths, project: str, *, component: str, alert: bool) -> bool:
    """Start production again if the slot says the copy stopped it and no
    pause or quarantine holds it down. True when production runs again;
    raises ProductionDownError (the marker kept) when it could not be
    started."""
    meta = load_slot(paths, project)
    if meta is None or not meta.production_stopped:
        return False
    block = is_blocked(project, paths)
    if block is not None:
        why = f"{project} is {block.reason.value}; its lift starts production"
        print(f"  Production stays stopped: {why}.")
        log_operation(component, f"production_stopped kept: {why}", paths, project=project)
        return False
    names = list(meta.production_stopped.get("containers") or [])
    try:
        _start(paths, project, names, component)
    except DockerError as e:
        message = (f"PRODUCTION IS DOWN: {project}'s containers were stopped for "
                   f"staging's data copy and starting them again failed: {e}. Start them "
                   f"with: docker start {' '.join(names)}")
        print(f"ERROR: {message}", file=sys.stderr)
        log_error(component, message, paths, project=project)
        notify(paths, f"{project}: production is down", message, component=component,
               project=project, priority=1)
        raise ProductionDownError(message) from e
    update_meta(paths, project, meta, production_stopped=None)
    print("  Production started again.")
    if alert:
        notify(paths, f"{project}: production started again",
               f"{project}'s production containers had been stopped for staging's data "
               f"copy, which did not finish; {component} started them again.",
               component=component, project=project, priority=1)
    return True
