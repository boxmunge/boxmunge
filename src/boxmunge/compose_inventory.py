# SPDX-License-Identifier: Apache-2.0
"""Which containers of which Compose projects are running, from one `docker ps`.

`docker ps` without `-a` lists the containers Docker reports running (paused
and restarting ones included, as `State.Running` does), and its `.Label`
template field reads Compose's project, service and one-off labels directly.
So the running containers of every project on the box are one CLI call, with
no inspect and no compose file to parse. The periodic checks (check-all,
health, the console) ask once and look each project up in the answer.

This says nothing about the images the containers run: a start, which must
know whether an image has gone from the store, asks docker_containers.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from boxmunge.docker import (
    COMPOSE_ONEOFF_LABEL, COMPOSE_PROJECT_LABEL, COMPOSE_SERVICE_LABEL, compose_project_filter,
)
from boxmunge.docker_run import DEFAULT_TIMEOUT, DockerError, run as _run

_LABELS = (COMPOSE_PROJECT_LABEL, COMPOSE_SERVICE_LABEL, COMPOSE_ONEOFF_LABEL)
# Without --no-trunc, .Names is the container's own name, never its legacy link aliases.
FORMAT = "\t".join(["{{.Names}}", *(f'{{{{.Label "{label}"}}}}' for label in _LABELS)])


@dataclass(frozen=True)
class RunningInventory:
    """{compose project: {service: names of its running containers}},
    `docker compose run` one-offs excluded, names sorted."""

    by_project: Mapping[str, Mapping[str, tuple[str, ...]]]
    # {compose project: why its containers cannot be told apart}: one
    # project's mislabelled container must not blind the checks of the rest.
    unreadable: Mapping[str, str]

    def services(self, project: str) -> dict[str, list[str]]:
        """{service: names of its running containers} for one project.
        Raises DockerError when one of its containers has no service label."""
        if project in self.unreadable:
            raise DockerError(self.unreadable[project])
        return {svc: list(names) for svc, names in self.by_project.get(project, {}).items()}

    def is_running(self, project: str, service: str | None = None) -> bool:
        """Whether the project (or that service of it) has a running container."""
        running = self.services(project)
        return bool(running) if service is None else service in running


def running_inventory(project: str | None = None, *,
                      timeout: int = DEFAULT_TIMEOUT) -> RunningInventory:
    """The running containers Compose labels: the whole box's, or one
    project's. Raises DockerError when Docker cannot be asked (or does not
    answer within *timeout* seconds), so an empty answer always means "none
    running"."""
    scope = (compose_project_filter(project) if project is not None
             else ["--filter", f"label={COMPOSE_PROJECT_LABEL}"])
    listed = _run(["docker", "ps", *scope, "--format", FORMAT], capture=True, timeout=timeout)
    return parse(listed.stdout)


def parse(stdout: str) -> RunningInventory:
    """The inventory from `docker ps --format FORMAT` output."""
    found: dict[str, dict[str, list[str]]] = {}
    unreadable: dict[str, str] = {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 1 + len(_LABELS):
            raise DockerError(f"docker ps returned a line that is not {1 + len(_LABELS)} "
                              f"tab-separated fields: {line!r}")
        name, project, service, oneoff = fields
        if not service:
            unreadable[project] = (
                f"container {name} carries the compose project label but no "
                f"{COMPOSE_SERVICE_LABEL} label, so its service is unknown. Remove it "
                f"(`docker rm -f {name}`) or relabel it.")
            continue
        if oneoff.lower() == "true":
            continue
        found.setdefault(project, {}).setdefault(service, []).append(name)
    return RunningInventory({
        project: {svc: tuple(sorted(names)) for svc, names in sorted(services.items())}
        for project, services in found.items()}, unreadable)
