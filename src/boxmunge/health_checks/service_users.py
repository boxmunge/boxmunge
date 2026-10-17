# SPDX-License-Identifier: Apache-2.0
"""Who each deployed project's services run as, box-wide.

`service-users` (health) warns for every deployed project whose users were
never decided: deployed before boxmunge decided them, its overlay names no
user and its next deploy decides them. `pending_declarations` (doctor)
reads those projects' images to list each registry service the next
deploy will refuse until its manifest says who it runs as, so the operator
can add every line in one pass before deploying.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.project_registry import deployed_among, read_registry
from boxmunge.run_as import SOURCE_CHOWN, RunAsError, effective_user, read_users

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

GUIDE = 'PROJECT_CONVENTIONS.md, "Who a service runs as"'


def _undecided(paths: BoxPaths) -> tuple[list[str], list[str]]:
    """(projects with no users record, problems reading one)."""
    undecided, problems = [], []
    for project in deployed_among(read_registry(paths).names, paths):
        try:
            users = read_users(paths, project)
        except RunAsError as e:
            problems.append(str(e))
            continue
        # data chown records only its service: no deploy decided the rest.
        if all(u.source == SOURCE_CHOWN for u in users.values()):
            undecided.append(project)
    return undecided, problems


def check_service_users(paths: BoxPaths) -> HealthCheck:
    undecided, problems = _undecided(paths)
    if problems:
        return HealthCheck("service-users", "warn", "; ".join(problems))
    if undecided:
        return HealthCheck(
            "service-users", "warn",
            f"users not decided for {', '.join(undecided)}: deployed before boxmunge "
            f"decided who each service runs as, so they run as their images say. Each "
            f"one's next deploy decides them; `boxmunge doctor` lists the services that "
            f"deploy will refuse until declared ({GUIDE})")
    return HealthCheck("service-users", "ok", "every deployed project's users are decided")


def _project_pending(paths: BoxPaths, project: str) -> list[str]:
    from boxmunge.docker_containers import image_facts
    from boxmunge.manifest import load_manifest
    from boxmunge.release_target import (
        as_written, compose_users, production_target, resolved_services,
    )
    manifest = load_manifest(paths.project_manifest(project))
    target = production_target(paths, project)
    _model, services = resolved_services(target)
    services = as_written(services, compose_users(target))
    pending = []
    for name, svc in sorted(services.items()):
        if svc.get("build") is not None:
            continue
        image = str(svc.get("image"))
        try:
            effective_user(name, svc, manifest, image_facts(image).user)
        except RunAsError:
            pending.append(f"{project}/{name} ({image})")
    return pending


def pending_declarations(paths: BoxPaths) -> tuple[list[str], list[str]]:
    """(services the next deploy refuses until declared, projects that could
    not be checked, with why). Reads only local images: a deployed
    project's images are present."""
    from boxmunge.compose_resolve import ComposeResolveError
    from boxmunge.docker_run import DockerError
    from boxmunge.manifest import ManifestError
    undecided, problems = _undecided(paths)
    pending: list[str] = []
    for project in undecided:
        try:
            pending += _project_pending(paths, project)
        except (ComposeResolveError, DockerError, ManifestError, OSError, ValueError) as e:
            problems.append(f"{project}: {e}")
    return pending, problems
