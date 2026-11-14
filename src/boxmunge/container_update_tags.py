# SPDX-License-Identifier: Apache-2.0
"""Image tags after an update that pulled but recreated nothing.

A pull moves a registry tag (`postgres:17`) to the new image at once, while
the containers keep running the old one. When the update then stops before
its recreate, the tag has to go back: anything that later recreates
containers from local tags (a restart, a resume, a restore) would otherwise
start the image the update refused.

A tag is one pointer for the whole host. Projects that name the same
`image:tag` share it, so pointing it back moves it for all of them, and a
project that had already updated runs the older image at its next recreate
until an update pulls again. Binding each project to its own image identity
is the supply-chain work planned for 0.12.
"""
from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from boxmunge import docker_containers
from boxmunge.deployed_inventory import DeployedService
from boxmunge.docker import DockerError, tag_image
from boxmunge.docker_containers import ProjectContainer
from boxmunge.log import log_error

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def restore_tags(
    paths: "BoxPaths", project: str,
    services: dict[str, DeployedService], running: dict[str, ProjectContainer],
) -> dict[str, str]:
    """Point every image reference a pull moved back at the image its
    service's containers run.

    Returns {reference: why it is not back, and the fix} for each one that
    could not be restored, each logged as an error: restore_and_report makes
    them part of the run's result.
    """
    ran: dict[str, set[str]] = defaultdict(set)
    for name, svc in services.items():
        assert svc.image is not None  # image_services keeps image services only
        ran[svc.image].add(running[name].image_id)
    stuck: dict[str, str] = {}
    for ref, ids in sorted(ran.items()):
        if "@" in ref:
            continue  # a digest reference names one image for ever: no pull moves it
        why = _restore(ref, ids)
        if why:
            stuck[ref] = (f"{ref} was not pointed back at the image {project} runs, so "
                          f"a restart may start the pulled image: {why}")
            log_error("container-update", f"Tag restore failed for {project}: {stuck[ref]}",
                      paths, project=project)
    return stuck


def restore_and_report(
    paths: "BoxPaths", project: str, result: dict[str, Any], reason: str,
    services: dict[str, DeployedService], running: dict[str, ProjectContainer],
) -> str:
    """restore_tags, for the result of a run that pulled and recreated
    nothing. The references that stay are listed in
    result["tags_not_restored"] and appended to `reason` ("" for a run that
    had not failed) as `tag_restore_failed`. Returns the reason: the run has
    failed whenever that list is not empty."""
    stuck = restore_tags(paths, project, services, running)
    result["tags_not_restored"] = sorted(stuck)
    if not stuck:
        return reason
    failed = "tag_restore_failed: " + "; ".join(stuck[ref] for ref in sorted(stuck))
    return f"{reason}; {failed}" if reason else failed


def restore_after_interrupt(
    paths: "BoxPaths", project: str, interrupt: BaseException,
    services: dict[str, DeployedService], running: dict[str, ProjectContainer],
) -> None:
    """restore_tags, for an interruption (KeyboardInterrupt, SystemExit, a
    SIGTERM handler's exception) that is about to propagate. The interrupt
    stays the failure; a tag that could not go back is attached to it as a
    note, and logged by restore_tags."""
    stuck = restore_tags(paths, project, services, running)
    if stuck:
        interrupt.add_note("tag_restore_failed: " + "; ".join(stuck[ref] for ref in sorted(stuck)))


def _restore(ref: str, ids: set[str]) -> str | None:
    """None once `ref` names an image its services run; else why it may not,
    ending with the fix."""
    if len(ids) > 1:
        fix = "Redeploy the project so its services agree."
    else:
        fix = f"Run: docker tag {min(ids)} {ref}"
    try:
        now = docker_containers.local_image(ref)
        if now is None or now.image_id in ids:
            return None  # the pull did not move it
        if len(ids) > 1:
            return (f"its services run different images ({', '.join(sorted(ids))}), so "
                    f"there is no one image to point it back at. {fix}")
        tag_image(min(ids), ref)
    except DockerError as e:
        return f"{e}. {fix}"
    return None
