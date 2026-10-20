# SPDX-License-Identifier: Apache-2.0
"""Stopping the box for the switch, and bringing it back project by project.

Quiesce: projects, then the system container, Caddy last (the preflight
refused a staged release, so no staging runs). Bring-up: the system
container (host namespace), then Caddy with every project behind the
maintenance page (pause's rendering, not pause's state), then each project
through compose_guard and its smoke tests before its routes come back. A
project that fails stays on the maintenance page and is journalled
`failed`; the others carry on. Nothing rolls back by itself. Every step is
repeated harmlessly by a resumed run: a journalled `up` is never redone.
A paused or quarantined project, and one the health monitor stopped, stays
down: starting it would undo a deliberate stop.
"""
from __future__ import annotations

from typing import Callable

from boxmunge import docker_containers
from boxmunge.caddy import prepare_caddy_config
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.commands.deploy_steps import smoke_ok
from boxmunge.compose import ComposeError, prepare_compose_override
from boxmunge.compose_guard import compose_up_checked, compose_up_platform
from boxmunge.data_helper import HELPER_IMAGE
from boxmunge.docker import caddy_reload
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.fileutil import atomic_write_text
from boxmunge.lifecycle import lifecycle_block
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.pause import render_maintenance_caddy_config
from boxmunge.system_container import CONTAINER_NAME, SystemContainerError, connect
from boxmunge.userns.inventory import Inventory
from boxmunge.userns.journal import Journal

PROJECT_FILES = ["compose.yml", "compose.boxmunge.yml"]
_STOP_TIMEOUT = 30


class BringUpError(Exception):
    """One project did not come back healthy."""


def quiesce(inv: Inventory) -> list[str]:
    """Stop every container still running, in order; returns their names.
    Asked of Docker, not the inventory: a resumed quiesce finds some stopped,
    or removed, already (and a restarted daemon may have started more)."""
    groups = [
        [c for c in inv.containers if c.compose_project in inv.projects],
        [c for c in inv.containers if c.name == CONTAINER_NAME],
        [c for c in inv.containers if c.compose_project not in inv.projects
         and c.name != CONTAINER_NAME],
    ]
    running = set(_run(["docker", "ps", "--format", "{{.Names}}"], capture=True).stdout.split())
    stopped = []
    for group in groups:
        names = [c.name for c in group if c.name in running]
        if names:
            _run(["docker", "stop", "-t", str(_STOP_TIMEOUT), *names], capture=True, timeout=900)
            stopped += names
    return stopped


def _maintenance(paths: BoxPaths, project: str) -> None:
    manifest = load_manifest(paths.project_manifest(project))
    atomic_write_text(paths.project_caddy_site(project),
                      render_maintenance_caddy_config(manifest.get("hosts", [])), mode=0o644,
                      refuse_link=True)


def _running_services(inv: Inventory, compose_project: str) -> list[str]:
    return sorted({c.service for c in inv.containers
                   if c.compose_project == compose_project and c.running and c.service})


def _services_to_start(inv: Inventory, project: str, only_stopped: bool) -> list[str]:
    """The services the inventory saw running; with ``only_stopped``, those
    not running now (asked of Docker: the inventory is older, and an abort
    runs on a box that carried on without it)."""
    services = _running_services(inv, project)
    if not only_stopped:
        return services
    now = {c.service for c in docker_containers.project_containers(project)
           if c.running and not c.oneoff}
    return [s for s in services if s not in now]


def _held(paths: BoxPaths, project: str) -> str | None:
    """Why the bring-up leaves a project down, if it does."""
    block = lifecycle_block(project, paths)
    if block:
        return block.reason.value
    # Starting it would leave the monitor's stop standing over a running
    # project (nothing bumps last_started_at); `recover` brings it back.
    return "stopped by the health monitor" if is_monitor_stopped(project, paths) else None


def _failed_before(journal: Journal, project: str) -> bool:
    """An earlier bring-up of this journal left the project failed: it may run
    yet still sit behind the maintenance page (its smoke tests failed), so
    only a full bring-up of it puts the site right."""
    return any(str(journal.items.get(f"{prefix}:{project}", "")).startswith("failed")
               for prefix in ("project", "restart", "abort"))


def _project(paths: BoxPaths, project: str, services: list[str], component: str) -> None:
    manifest = load_manifest(paths.project_manifest(project))
    prepare_compose_override(paths, manifest, component=component)
    if services:
        compose_up_checked(paths, project, component=component, compose_files=PROJECT_FILES,
                           record=True, build=False, services=services)
        if not smoke_ok(project, paths, paths.project_dir(project), manifest, PROJECT_FILES):
            raise BringUpError("its smoke tests failed (see above and the log)")
    prepare_caddy_config(paths, manifest)
    caddy_reload(paths.caddy, paths.state)


def _platform(paths: BoxPaths, behind_page: list[str], journal: Journal, prefix: str) -> None:
    """The system container and Caddy, with each project about to be started
    behind the maintenance page."""
    try:
        _run(["docker", "image", "inspect", "--format", "{{.Id}}", HELPER_IMAGE], capture=True)
        rebuild = False  # loaded from its tar
    except DockerError:
        rebuild = True
    compose_up_platform(paths.system, ["compose.yml"], "system", build=rebuild)
    connect(paths)
    for p in behind_page:
        if journal.items.get(f"{prefix}:{p}") != "up":
            _maintenance(paths, p)
    compose_up_platform(paths.caddy, ["compose.yml"], "caddy", build=False)
    caddy_reload(paths.caddy, paths.state)


def bring_up(paths: BoxPaths, inv: Inventory, journal: Journal, save: Callable[[], None], *,
             component: str, prefix: str = "project",
             only_stopped: bool = False) -> dict[str, str]:
    """Start the platform, then every project; returns project -> status.

    ``only_stopped``: for a box that ran on since the inventory was taken (an
    abort before the switch). A project whose services all run now is not
    touched (no maintenance page, no restart, no smoke test) unless an earlier
    bring-up of it failed (then it is brought up in full: compose up is a
    no-op for what runs, and its smoke tests decide).
    """
    projects = [p for p in inv.projects if paths.project_manifest(p).exists()]
    held = {p: why for p in projects if (why := _held(paths, p))}
    todo = {p: _services_to_start(inv, p, only_stopped and not _failed_before(journal, p))
            for p in projects if p not in held}
    untouched = {p for p, services in todo.items()
                 if only_stopped and not services and _running_services(inv, p)}
    _platform(paths, [p for p in todo if p not in untouched], journal, prefix)
    for p in projects:
        key = f"{prefix}:{p}"
        if journal.items.get(key) == "up":
            continue
        try:
            if p in held:
                prepare_compose_override(paths, load_manifest(paths.project_manifest(p)),
                                         component=component)
                journal.items[key] = f"left {held[p]}"
            elif p in untouched:
                journal.items[key] = "already running"
            else:
                _project(paths, p, todo[p], component)
                journal.items[key] = "up"
        except (BringUpError, ComposeError, DockerError, ManifestError,
                SystemContainerError, OSError) as e:
            journal.items[key] = f"failed: {e}"
        save()
    return {p: journal.items[f"{prefix}:{p}"] for p in projects}
