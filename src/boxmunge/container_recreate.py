# SPDX-License-Identifier: Apache-2.0
"""Recreate a user project's containers and wait for them to be healthy.

Container update (container_update) and autofix (cve.autofix_run) both
swap the images a project runs: they recreate its containers from the
local images through the start checks, then poll until every service is
healthy, a service fails, or the timeout passes.

A recreate starts the project, so it refuses one the platform keeps down:
paused, quarantined, stopped by the health monitor, or held by the userns
migration (lifecycle.is_blocked); an open install is refused by the start
checks. The one exception is autofix's dark patch: a project quarantined
for the very patch being swapped in is started behind its maintenance
page for its health check (`patch_cves`: the quarantine's CVE must be
one the patch fixes), unless it is paused too.
"""
from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Collection, Iterable
from typing import TYPE_CHECKING

from boxmunge import docker_containers
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.compose_guard import ComposeRefused, compose_up_checked
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.pause import is_paused
from boxmunge.docker_containers import ProjectContainer

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

HEALTHCHECK_TIMEOUT_SEC = 90
HEALTHCHECK_POLL_INTERVAL_SEC = 3
NO_HEALTHCHECK_GRACE_SEC = 30


def managed(containers: Iterable[ProjectContainer]) -> list[ProjectContainer]:
    """Containers `up` manages; `compose run` one-offs are not recreated."""
    return [c for c in containers if not c.oneoff]


def start_refusal(paths: BoxPaths, project: str, *,
                  patch_cves: Collection[str] = ()) -> str | None:
    """Why the project may not be started now, or None."""
    block = is_blocked(project, paths)
    if block is not None:
        if block.reason is not BlockReason.QUARANTINED or not patch_cves:
            return block.refuse_message
        cve = block.detail.get("cve_id")
        if cve not in patch_cves:
            return (f"Project '{project}' is CVE-quarantined for {cve}, which this patch "
                    f"({', '.join(sorted(patch_cves))}) does not fix; it is patched once "
                    f"that quarantine is resolved.")
        if is_paused(project, paths):   # is_blocked names the quarantine first
            return (f"Project '{project}' is paused as well as quarantined for the patch; "
                    f"`boxmunge resume {project}` brings it back.")
    if is_monitor_stopped(project, paths):
        return (f"Project '{project}' was stopped by the health monitor; "
                f"`boxmunge recover {project}` brings it back.")
    return None


def recreate_project(paths: BoxPaths, project: str, compose_files: list[str], *,
                     component: str, patch_cves: Collection[str] = ()) -> None:
    """Recreate the user project's containers from its local images, through
    the start checks. `patch_cves`: the caller quarantined the project for
    the patch of these CVEs it swaps in (autofix's dark patch), the one
    blocked start allowed, when the quarantine is for one of them. Raises ComposeRefused (nothing started) or
    DockerError."""
    refusal = start_refusal(paths, project, patch_cves=patch_cves)
    if refusal is not None:
        raise ComposeRefused(f"Refused to recreate {project}: {refusal} Nothing was started.")
    compose_up_checked(paths, project, component=component, compose_files=compose_files)


def _health_round(
    project: str, services: list[str], one_shots: frozenset[str], *, in_grace: bool,
) -> tuple[list[str], list[str]]:
    """One look at the services' containers: (still settling, unhealthy).

    A service without a container, or with one that is not running or
    reports unhealthy, is unhealthy, except a container of a one-shot
    service that ran to completion again. One without a healthcheck
    settles once the no-healthcheck grace period is over.
    """
    by_service: dict[str, list[ProjectContainer]] = defaultdict(list)
    for container in managed(docker_containers.project_containers(project)):
        by_service[container.service].append(container)
    settling: list[str] = []
    unhealthy: list[str] = []
    for name in services:
        containers = [c for c in by_service.get(name, [])
                      if not (name in one_shots and c.finished_cleanly)]
        if not by_service.get(name):
            unhealthy.append(name)
        elif any(not c.running or c.health == "unhealthy" for c in containers):
            unhealthy.append(name)
        elif any(c.health == "starting" or (c.health is None and in_grace)
                 for c in containers):
            settling.append(name)
    return settling, unhealthy


def wait_healthy(
    project: str, services: list[str], one_shots: frozenset[str] = frozenset(),
    timeout_sec: int = HEALTHCHECK_TIMEOUT_SEC,
) -> tuple[bool, list[str]]:
    """Poll until every service's containers are healthy, or timeout.

    Returns (all_healthy, list_of_unhealthy_service_names). An unhealthy
    verdict is final; services still settling at the deadline count as
    unhealthy.
    """
    start = time.monotonic()
    deadline = start + timeout_sec
    settling = list(services)
    while time.monotonic() < deadline:
        in_grace = time.monotonic() - start < NO_HEALTHCHECK_GRACE_SEC
        settling, unhealthy = _health_round(project, services, one_shots, in_grace=in_grace)
        if unhealthy:
            return False, unhealthy
        if not settling:
            return True, []
        time.sleep(HEALTHCHECK_POLL_INTERVAL_SEC)
    return False, settling
