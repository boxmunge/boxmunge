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
from boxmunge.compose_guard import (
    ComposeRefused, compose_up_checked, start_containers_checked,
)
from boxmunge.docker_run import DockerError
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_error, log_operation
from boxmunge.notify import notify
from boxmunge.staged_release import (
    SlotError, StagedRelease, clear_production_stopped, load_slot, update_meta,
)
from boxmunge.state import read_state, write_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

PROD_FILES = ["compose.yml", "compose.boxmunge.yml"]
DOWN_TITLE = "{project}: production is down"


class ProductionDownError(DockerError):
    """Production was stopped for the copy and could not be started again."""


def mark_stopped(paths: BoxPaths, project: str, meta: StagedRelease,
                 containers: list[str]) -> StagedRelease:
    if not containers:
        raise ValueError(f"{project}: a production_stopped marker records the containers "
                         f"stopped; no container was named")
    return update_meta(paths, project, meta, production_stopped={
        "at": datetime.now(timezone.utc).isoformat(), "containers": list(containers)})


def _all_present(project: str, names: list[str]) -> bool:
    # `docker start` brings back exactly what was stopped; a container gone
    # since (removed by hand, a crashed recreate) needs production's up.
    present = {c.name for c in docker_containers.project_containers(project)}
    return set(names) <= present


def _remedy(project: str, names: list[str], error: DockerError, docker_start: bool) -> str:
    recover = f"`boxmunge recover {project}`"
    if isinstance(error, ComposeRefused):
        # Never advise bypassing the check: the refusal's alert says what failed.
        return f"Its start was refused: fix what the refusal names, then run {recover}."
    if docker_start:
        return f"Start them with `docker start {' '.join(names)}` or run {recover}."
    return f"Fix the cause, then run {recover}."


def start_stopped(paths: BoxPaths, project: str, names: list[str], *,
                  component: str, page: bool = True) -> None:
    """Start production's containers the copy stopped (`docker start`, or
    production's up when one is gone). Raises ProductionDownError, said
    loudly (``page`` False: stderr and log only), when they could not be
    started."""
    docker_start = False
    try:
        docker_start = _all_present(project, names)
        if docker_start:
            start_containers_checked(paths, project, names, component=component)
        else:
            compose_up_checked(paths, project, component=component, compose_files=PROD_FILES)
    except DockerError as e:
        raise production_down(paths, project, component, (
            f"{project}'s containers were stopped for staging's data copy and starting "
            f"them again failed: {e}. {_remedy(project, names, e, docker_start)}"),
            page=page) from e


def production_down(paths: BoxPaths, project: str, component: str,
                    why: str, *, page: bool = True) -> ProductionDownError:
    """Say loudly (stderr, log and, if ``page``, a priority-1 alert) that
    production is down; returns the error to raise. A caller that repeats
    (the health tick) pages itself, once per error."""
    message = f"PRODUCTION IS DOWN: {why}"
    print(f"ERROR: {message}", file=sys.stderr)
    log_error(component, message, paths, project=project)
    if page:
        notify(paths, DOWN_TITLE.format(project=project), message, component=component,
               project=project, priority=1)
    return ProductionDownError(message)


def _record_started(paths: BoxPaths, project: str) -> None:
    # The health tick's grace window starts here, as after a deploy, resume
    # or recover: an app still booting does not fail its next smoke.
    path = paths.project_deploy_state(project)
    state = read_state(path)
    state["last_started_at"] = datetime.now(timezone.utc).isoformat()
    write_state(path, state)


def start_again(paths: BoxPaths, project: str, *, component: str, alert: bool) -> bool:
    """Start production again if the slot says the copy stopped it and no
    pause or quarantine holds it down. True when production runs again;
    raises ProductionDownError (the marker kept) when it could not be
    started, or when the slot cannot be read to name what was stopped."""
    try:
        meta = load_slot(paths, project)
    except SlotError as e:
        raise production_down(paths, project, component, (
            f"{project}'s staged slot cannot be read ({e}), so the production containers "
            f"staging's data copy stopped cannot be named or started again. Run "
            f"`boxmunge recover {project}` to start production, then `unstage "
            f"{project}`.")) from e
    return start_again_from(paths, project, meta, component=component, alert=alert)


def start_again_from(paths: BoxPaths, project: str, meta: StagedRelease | None, *,
                     component: str, alert: bool, page: bool = True) -> bool:
    """start_again with the slot already read (``meta``). ``page`` False
    leaves a failure's alert to the caller (start_stopped)."""
    if meta is None or meta.production_stopped is None:
        return False
    block = is_blocked(project, paths)
    if block is not None:
        why = f"{project} is {block.reason.value}; its lift starts production"
        print(f"  Production stays stopped: {why}.")
        log_operation(component, f"production_stopped kept: {why}", paths, project=project)
        return False
    start_stopped(paths, project, list(meta.production_stopped["containers"]),
                  component=component, page=page)
    # The up path has cleared it already; this reloads, so it writes at most once.
    clear_production_stopped(paths, project)
    _record_started(paths, project)
    print("  Production started again.")
    if alert:
        notify(paths, f"{project}: production started again",
               f"{project}'s production containers had been stopped for staging's data "
               f"copy, which did not finish; {component} started them again.",
               component=component, project=project, priority=1)
    return True
