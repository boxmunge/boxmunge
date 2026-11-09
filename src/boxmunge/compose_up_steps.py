# SPDX-License-Identifier: Apache-2.0
"""The steps compose_guard.compose_up_checked runs around `docker compose up`.

Before the up: the images a build service's containers run get back their
platform name (restore_build_names), and the images the up would start
are listed so a missing one is refused by name (start_images,
missing_text). The up's failure names an image that went from the store
during it (up_failed). After it: running containers whose image the store
lost are recreated (recreate_without_image), and a full production up
clears a staging copy's stop and sweeps 0.10.1's live-scripts copy.

Nothing here checks the project: compose_guard does, before any of it.
"""
from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from boxmunge import built_images, compose_resolve, docker_containers
from boxmunge.compose_images import built_image_name
from boxmunge.docker_run import DockerError
from boxmunge.fileutil import discard_dir
from boxmunge.fs_nofollow import read_text_nofollow
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.staged_release import SlotError, clear_production_stopped

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


class ComposeUpFailed(DockerError):
    """`docker compose up` ran and failed: it may have created, recreated or
    started some of the project's containers. Any other error from
    compose_up_checked was raised before the up, which changed none."""



def restore_build_names(paths: BoxPaths, project_name: str, compose_project: str,
                         overlay: Path | None, component: str) -> None:
    """Name the images the build services' containers run by their platform
    name where it names nothing (built_images.name_running_builds), so the
    start runs them instead of building new ones. The overlay says which
    services are built: it gives each one its platform name (an overlay
    from before boxmunge named built images gives none; a start without
    one has none to name)."""
    if overlay is None:
        return
    try:
        doc = yaml.safe_load(read_text_nofollow(overlay)) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise DockerError(f"cannot read {overlay}: {e}") from e
    services = doc.get("services") if isinstance(doc, dict) else None
    built = sorted(svc for svc, spec in (services or {}).items()
                   if isinstance(spec, dict)
                   and spec.get("image") == built_image_name(compose_project, svc))
    named = built_images.name_running_builds(compose_project, built) if built else []
    if named:
        log_operation(component, f"named the images {compose_project}'s containers run: "
                      f"{', '.join(named)} (their old names had been taken off them)",
                      paths, project=project_name)


def up_failed(error: DockerError, images: dict[str, str], redo: str) -> ComposeUpFailed:
    """The up's failure, naming an image that went from the store during it."""
    try:
        gone = docker_containers.absent_images(images)
    except DockerError as e:
        return ComposeUpFailed(f"{error} (whether an image went from the local image store "
                               f"during the start cannot be told: {e})")
    if not gone:
        return ComposeUpFailed(str(error))
    return ComposeUpFailed(
        f"{error}. {missing_text(gone)}: it went from the local image store during the "
        f"start, which may already have created or recreated the services ahead of it. "
        f"Run {redo}.")


def missing_text(missing: list[tuple[str, str]]) -> str:
    return "; ".join(f"the image for {svc} ({image}) is missing" for svc, image in missing)


def start_images(run_dir: Path, files: list[str], compose_project: str,
                  services: list[str] | None, where: dict) -> dict[str, str]:
    """{service: image} for every service the up would create or start:
    `services`, or every service without a profile (boxmunge runs Compose
    with no profile enabled), and those they depend on. Compose names a
    build service without an `image:` (an overlay from before boxmunge
    named built images) `<project>-<service>`."""
    model = compose_resolve.resolve_deployed_config(
        run_dir, files, compose_project, all_profiles=True, **where)
    specs = model.get("services") or {}
    wanted: set[str] = set()
    todo = list(services if services is not None else
                (svc for svc, spec in specs.items()
                 if isinstance(spec, dict) and not spec.get("profiles")))
    while todo:
        svc = todo.pop()
        spec = specs.get(svc)
        if svc in wanted or not isinstance(spec, dict):
            continue
        wanted.add(svc)
        todo.extend(spec.get("depends_on") or ())
    images = {}
    for svc in sorted(wanted):
        spec = specs[svc]
        image = spec.get("image") or (f"{compose_project}-{svc}" if "build" in spec else None)
        if isinstance(image, str):
            images[svc] = image
    return images


def recreate_without_image(paths: BoxPaths, project_name: str, compose_project: str,
                            component: str, services: list[str] | None,
                            up: Callable[..., None]) -> None:
    """Recreate the running containers whose image the local image store no
    longer has, from the image their name points at now.

    A build that moved a name to a new image index left them there:
    Compose compares the platform manifest, which a cached build keeps, so
    it does not recreate them, and on the containerd store the index they
    were created from goes with its last name (boxmunge.docker_containers).
    Compose left them because their platform manifest is still the one
    the name points at, so the recreated containers run the same image."""
    gone = docker_containers.running_without_image(compose_project)
    recreate = sorted(svc for svc in gone if services is None or svc in services)
    if not recreate:
        return
    names = ", ".join(n for svc in recreate for n in gone[svc])
    message = (f"{compose_project}: recreating {', '.join(recreate)}: the local image store "
               f"no longer has the image {names} was created from (a build replaced it "
               f"under its name)")
    print(f"  WARNING: {message}", file=sys.stderr)
    log_warning(component, message, paths, project=project_name)
    up(force_recreate=True, services=recreate)


def clear_copy_stop(paths: BoxPaths, project_name: str, component: str) -> None:
    """Production runs again, so a staging copy's stop no longer stands
    (boxmunge.production_stopped). Production is up by now: an unreadable
    slot must not turn that into a failed start, so it is said loudly and
    left for the slot's own cores, which refuse it."""
    try:
        clear_production_stopped(paths, project_name)
    except (SlotError, OSError) as e:
        message = (f"{project_name}: production is running, but its staged slot cannot be "
                   f"read or written to clear the production_stopped marker: {e}. Inspect "
                   f"the slot and unstage {project_name}.")
        print(f"ERROR: {message}", file=sys.stderr)
        log_error(component, message, paths, project=project_name)
        notify(paths, f"{project_name}: staged slot unreadable", message,
               component=component, project=project_name, priority=1)


# The bind source boxmunge 0.10.1's production overlay used for the copy.
LIVE_SCRIPTS_SOURCE = "./.releases/live-scripts"


def sweep_live_scripts(paths: BoxPaths, project_name: str, component: str) -> None:
    """boxmunge 0.10.1 mounted production's smoke scripts from
    .releases/live-scripts. Once production's overlay no longer names it and
    no container of the project mounts it, it is removed. Production is up
    by now, so a failure to tell or to remove is said, not raised."""
    live = paths.project_releases(project_name) / "live-scripts"
    if not os.path.lexists(live):
        return
    try:
        overlay = paths.project_compose_override(project_name)
        if overlay.exists() and LIVE_SCRIPTS_SOURCE in overlay.read_text():
            return
        roots = {str(live), os.path.realpath(live)}
        if any(src == root or src.startswith(root + os.sep)
               for src, _rw in docker_containers.container_bind_sources(project_name)
               for root in roots):
            return
        discard_dir(live)
    except (OSError, DockerError) as e:
        message = (f"{project_name}: production is running, but {live} (the smoke-script "
                   f"copy boxmunge 0.10.1 mounted) was not removed: {e}. The next "
                   f"production start tries again; if it is not a directory, inspect it.")
        print(f"WARNING: {message}", file=sys.stderr)
        log_warning(component, message, paths, project=project_name)
