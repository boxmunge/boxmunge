# SPDX-License-Identifier: Apache-2.0
"""Recreate a user project's containers and wait for them to be healthy.

Container update (container_update) and autofix (cve.autofix_run) both
swap the images a project runs: they recreate its containers from the
local images through the start checks, then poll until every service is
healthy, a service fails, or the timeout passes.
"""
from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Iterable
from typing import TYPE_CHECKING

from boxmunge import docker_containers
from boxmunge.compose_guard import compose_up_checked
from boxmunge.docker_containers import ProjectContainer

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

HEALTHCHECK_TIMEOUT_SEC = 90
HEALTHCHECK_POLL_INTERVAL_SEC = 3
NO_HEALTHCHECK_GRACE_SEC = 30


def managed(containers: Iterable[ProjectContainer]) -> list[ProjectContainer]:
    """Containers `up` manages; `compose run` one-offs are not recreated."""
    return [c for c in containers if not c.oneoff]


def recreate_project(paths: BoxPaths, project: str, compose_files: list[str], *,
                     component: str) -> None:
    """Recreate the user project's containers from its local images, through
    the start checks. Raises ComposeRefused or DockerError."""
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
