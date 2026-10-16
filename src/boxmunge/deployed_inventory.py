# SPDX-License-Identifier: Apache-2.0
"""What a project has deployed: its resolved services and the containers
actually running them.

The CVE scan and the container updater both ask, per service, which image
it should run and which image its containers really run. Reading
compose.yml literally answers both wrongly: services from `include:` are
missing, `extends:` hides an inherited `image:`, `${VAR:-default}` is not
an image name, and `<project>-<service>-1` is not the name of a container
with a custom `container_name` or of a second replica. So both read this
inventory instead: the model `docker compose config` resolves from every
compose file the project is deployed with, from the project directory as
`up` does, joined with the project's containers found by Compose labels.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxmunge import docker_containers
from boxmunge.compose_resolve import ComposeResolveError, resolve_deployed_config
from boxmunge.docker_containers import ProjectContainer
from boxmunge.docker_run import DockerError


class InventoryError(RuntimeError):
    """The deployed model or the project's containers could not be read."""


@dataclass(frozen=True)
class DeployedService:
    """One service: what the resolved model says, and its containers."""

    name: str
    # The resolved `image:` reference, or None (build-only, or a container
    # whose service is no longer in the model).
    image: str | None
    buildable: bool
    # `up` starts it: in the model and not behind an inactive profile.
    expected: bool
    containers: tuple[ProjectContainer, ...]


@dataclass(frozen=True)
class DeployedInventory:
    project: str
    # Model services first, in model order; then services that only
    # containers name (left over after a service was removed).
    services: dict[str, DeployedService]


def _services(model: dict[str, Any], what: str) -> dict[str, dict[str, Any]]:
    services = model.get("services") or {}
    if not isinstance(services, dict) or not all(
        isinstance(s, dict) for s in services.values()
    ):
        raise InventoryError(f"{what}: `services` is not a mapping of service mappings")
    for name, svc in services.items():
        image = svc.get("image")
        if image is not None and not (isinstance(image, str) and image):
            raise InventoryError(f"{what}: service {name!r} has image {image!r}")
    return services


def load_deployed_inventory(
    project_dir: Path, compose_files: list[str], project_name: str,
) -> DeployedInventory:
    """Resolve the deployed model and join it with the project's containers.

    Raises InventoryError when Compose cannot resolve the model or Docker
    cannot list the containers.
    """
    what = f"compose project {project_name!r}"
    try:
        active = _services(resolve_deployed_config(
            project_dir, compose_files, project_name), what)
        every = _services(resolve_deployed_config(
            project_dir, compose_files, project_name, all_profiles=True), what)
        containers = docker_containers.project_containers(project_name)
    except (ComposeResolveError, DockerError) as e:
        raise InventoryError(f"{what}: {e}") from e
    by_service: dict[str, list[ProjectContainer]] = defaultdict(list)
    for container in containers:
        by_service[container.service].append(container)
    services = {
        name: DeployedService(
            name=name, image=svc.get("image"), buildable="build" in svc,
            expected=name in active, containers=tuple(by_service.pop(name, ())),
        )
        for name, svc in every.items()
    }
    for name, leftover in by_service.items():
        services[name] = DeployedService(
            name=name, image=None, buildable=False, expected=False,
            containers=tuple(leftover),
        )
    return DeployedInventory(project=project_name, services=services)
