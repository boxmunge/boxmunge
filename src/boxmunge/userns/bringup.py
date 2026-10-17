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
"""
from __future__ import annotations

from typing import Callable

from boxmunge.caddy import prepare_caddy_config
from boxmunge.commands.deploy_steps import smoke_ok
from boxmunge.compose import ComposeError, prepare_compose_override
from boxmunge.compose_guard import compose_up_checked, compose_up_platform
from boxmunge.data_helper import HELPER_IMAGE
from boxmunge.docker import caddy_reload
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.fileutil import atomic_write_text
from boxmunge.lifecycle import is_blocked
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


def _project(paths: BoxPaths, inv: Inventory, project: str, component: str) -> None:
    manifest = load_manifest(paths.project_manifest(project))
    prepare_compose_override(paths, manifest, component=component)
    services = _running_services(inv, project)
    if services:
        compose_up_checked(paths, project, component=component, compose_files=PROJECT_FILES,
                           record=True, build=False, services=services)
        if not smoke_ok(project, paths, paths.project_dir(project), manifest, PROJECT_FILES):
            raise BringUpError("its smoke tests failed (see above and the log)")
    prepare_caddy_config(paths, manifest)
    caddy_reload(paths.caddy, paths.state)


def _platform(paths: BoxPaths, projects: list[str], journal: Journal, prefix: str) -> None:
    try:
        _run(["docker", "image", "inspect", "--format", "{{.Id}}", HELPER_IMAGE], capture=True)
        rebuild = False  # loaded from its tar
    except DockerError:
        rebuild = True
    compose_up_platform(paths.system, ["compose.yml"], "system", build=rebuild)
    connect(paths)
    for p in projects:
        if not is_blocked(p, paths) and journal.items.get(f"{prefix}:{p}") != "up":
            _maintenance(paths, p)
    compose_up_platform(paths.caddy, ["compose.yml"], "caddy", build=False)
    caddy_reload(paths.caddy, paths.state)


def bring_up(paths: BoxPaths, inv: Inventory, journal: Journal, save: Callable[[], None], *,
             component: str, prefix: str = "project") -> dict[str, str]:
    """Start the platform, then every project; returns project -> status."""
    projects = [p for p in inv.projects if paths.project_manifest(p).exists()]
    _platform(paths, projects, journal, prefix)
    for p in projects:
        key = f"{prefix}:{p}"
        if journal.items.get(key) == "up":
            continue
        block = is_blocked(p, paths)
        try:
            if block:
                prepare_compose_override(paths, load_manifest(paths.project_manifest(p)),
                                         component=component)
                journal.items[key] = f"left {block.reason.value}"
            else:
                _project(paths, inv, p, component)
                journal.items[key] = "up"
        except (BringUpError, ComposeError, DockerError, ManifestError,
                SystemContainerError, OSError) as e:
            journal.items[key] = f"failed: {e}"
        save()
    return {p: journal.items[f"{prefix}:{p}"] for p in projects}
