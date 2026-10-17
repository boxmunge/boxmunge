# SPDX-License-Identifier: Apache-2.0
"""A pulled image whose USER moved under a service that runs as its image's user.

Such a service (security.user: image, an image USER, profile: off) would
start writing its data as someone else with the new image. Every path
that pulls without deciding users (container-update and its dry run,
resume) checks what it pulled against the users record; for each service
whose image's USER changed it points the tag back at the image it named
before the pull, records the service (`state/deploy/<p>.user-drift.json`)
and alerts. The deploy the alert asks for pulls those services' images
again (prepare_release_users' `refetch`), decides their users from the new
image, and clears the record once its own record is written.
"""
from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from boxmunge import docker_containers
from boxmunge.docker import tag_image
from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow
from boxmunge.notify import notify
from boxmunge.run_as import SOURCE_COMPOSE, RunAsError, identity, read_users

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def image_ids(refs: dict[str, str]) -> dict[str, str | None]:
    """{service: the local image its ref names now, or None} (before a pull)."""
    out = {}
    for svc, ref in refs.items():
        image = docker_containers.local_image(ref)
        out[svc] = image.image_id if image is not None else None
    return out


def drift(paths: BoxPaths, project: str, changed: dict[str, str]) -> dict[str, str]:
    """{service: "image user <old> -> <new>"} for the `changed` services
    (service -> newly pulled ref) that run as their image's own user and
    whose new image declares another USER. Other sources pin the user."""
    record = read_users(paths, project)
    out = {}
    for svc, ref in sorted(changed.items()):
        rec = record.get(svc)
        if rec is None or rec.emitted() is not None or rec.source == SOURCE_COMPOSE:
            continue
        new = docker_containers.image_facts(ref).user
        if identity(new) != identity(rec.image_user):
            out[svc] = f"image user {rec.image_user or 'root'} -> {new or 'root'}"
    return out


def held_back(paths: BoxPaths, project: str) -> frozenset[str]:
    """The services a deploy must pull again."""
    path = paths.project_user_drift(project)
    try:
        doc = json.loads(read_text_nofollow(path))
    except FileNotFoundError:
        return frozenset()
    except (OSError, ValueError) as e:
        raise RunAsError(f"cannot read {path}: {e}; remove it and deploy {project}") from e
    # An object, as every file in state/deploy is (identity reads them all).
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, list) or not all(isinstance(s, str) for s in services):
        raise RunAsError(f"{path} is not {{\"services\": [...]}}; remove it and deploy "
                         f"{project}")
    return frozenset(services)


def clear(paths: BoxPaths, project: str) -> None:
    path = paths.project_user_drift(project)
    if os.path.lexists(path):
        path.unlink()


def guard_pull(paths: BoxPaths, project: str, refs: dict[str, str],
               before: dict[str, str | None], *, component: str) -> dict[str, str]:
    """After a pull of `refs` (service -> ref; `before`: image_ids from
    before it): hold back every service whose image's USER changed, and
    alert. Returns {service: what changed}. Raises DockerError or
    RunAsError."""
    changed = {}
    for svc, ref in refs.items():
        image = docker_containers.local_image(ref)
        if image is not None and image.image_id != before.get(svc):
            changed[svc] = ref
    moved = drift(paths, project, changed)
    if not moved:
        return {}
    for svc in moved:
        if before.get(svc) is None:
            continue  # nothing ran it before: the deploy decides from this image
        tag_image(str(before[svc]), refs[svc])
    atomic_write_text(paths.project_user_drift(project), json.dumps(
        {"services": sorted(held_back(paths, project) | set(moved))}) + "\n")
    text = "; ".join(f"{svc}: {why}" for svc, why in moved.items())
    notify(paths, f"{project}: image user changed",
           f"{component} held back {project}'s new images ({text}): these services run as "
           f"their image's own user, so the new image would change who owns and writes "
           f"their data. Their tags point at the images they ran before. Review the "
           f"change, declare security.user if needed, and deploy {project}: the deploy "
           f"pulls these images again and decides from them.",
           component=component, project=project, priority=1)
    return moved
