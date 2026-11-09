# SPDX-License-Identifier: Apache-2.0
"""Images the platform builds for a project: removing them, naming the ones
its containers run, and taking the old `<project>-<service>` style names
off them.

Built images are named `boxmunge.invalid/<compose-project>/<service>`
(compose_images.BUILT_IMAGE_HOST), a name no registry serves and no other
project can take.
"""
from __future__ import annotations

from collections.abc import Collection
from typing import NamedTuple

from boxmunge import docker_containers
from boxmunge.compose_images import BUILT_IMAGE_HOST, built_image_name
from boxmunge.docker import (
    COMPOSE_ONEOFF_LABEL, COMPOSE_PROJECT_LABEL, COMPOSE_SERVICE_LABEL,
    check_compose_project_name, compose_project_filter,
)
from boxmunge.docker_run import DockerError, run as _run


def remove_built_images(compose_project: str) -> list[str]:
    """Remove every image the platform built for a compose project (named
    boxmunge.invalid/<compose-project>/<service>). Returns the names removed.
    Raises DockerError if one cannot be removed."""
    check_compose_project_name(compose_project)
    result = _run(
        ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}",
         "--filter", f"reference={BUILT_IMAGE_HOST}/{compose_project}/*"],
        capture=True,
    )
    names = [line for line in result.stdout.splitlines() if line.strip()]
    if names:
        _run(["docker", "image", "rm", *names], capture=True)
    return names


class _ContainerImages(NamedTuple):
    own_ids: set[str]       # images this project's build services' containers run
    user_ids: set[str]      # images every other container runs ...
    user_names: set[str]    # ... and the names they were created from
    # build service -> {image its `up` containers run: their names}
    by_service: dict[str, dict[str, list[str]]]


def _container_images(
    compose_project: str, build_services: set[str], image_services: set[str],
) -> _ContainerImages:
    """The images every container, running or stopped, was created from:
    those of this project's build services, and those of the containers
    that protect an image (another project's, a project-less one, or one of
    this project's image-only services). A leftover container of a service
    this project no longer has is neither."""
    found = _ContainerImages(set(), set(), set(), {})
    ids = _run(["docker", "ps", "-a", "-q", "--no-trunc"], capture=True).stdout.split()
    if not ids:
        return found
    labels = "\t".join(f'{{{{index .Config.Labels "{label}"}}}}' for label in (
        COMPOSE_PROJECT_LABEL, COMPOSE_SERVICE_LABEL, COMPOSE_ONEOFF_LABEL))
    cmd = ["docker", "container", "inspect", "--format",
           "{{.Image}}\t{{.Config.Image}}\t" + labels + "\t{{.Name}}", *ids]
    result = _run(cmd, capture=True, check=False)
    # A container removed since `ps` uses no image; any other error is one.
    errors = [e for e in result.stderr.splitlines()
              if e.strip() and "No such container" not in e]
    if result.returncode != 0 and errors:
        raise DockerError(f"{' '.join(cmd[:3])} failed: {'; '.join(errors)}")
    for line in filter(None, result.stdout.splitlines()):
        image_id, image_name, project, service, oneoff, name = (line.split("\t") + [""] * 5)[:6]
        if project == compose_project and service in build_services:
            found.own_ids.add(image_id)
            # A `compose run` one-off is not what `up` runs, nor what it starts.
            if oneoff.lower() != "true":
                found.by_service.setdefault(service, {}).setdefault(image_id, []).append(
                    name.lstrip("/"))
        elif project != compose_project or service in image_services:
            found.user_ids.add(image_id)
            found.user_names.add(image_name)
    return found


def name_running_builds(compose_project: str, build_services: Collection[str]) -> list[str]:
    """Give each build service's platform name, where it names no image, to
    the image that service's containers run: the image their deploy built,
    by the containers' own image ID. Returns the names given.

    Taking a project's old names off an image a container still ran left it
    with no name: once that container stopped, the graph driver deleted it,
    and the containerd store kept it nameless. A start that runs only local
    images by their platform name (a quarantine's lift) then had nothing
    to start, and any other start built a new image no deploy had vetted.
    Raises DockerError, also when a service's containers run different
    images."""
    check_compose_project_name(compose_project)
    by_service = _container_images(compose_project, set(build_services), set()).by_service
    named = []
    for service, image_ids in sorted(by_service.items()):
        name = built_image_name(compose_project, service)
        if docker_containers.local_image(name) is not None:
            continue
        # One whose image the store no longer has is recreated at its start.
        present = sorted(i for i in image_ids if docker_containers.local_image(i) is not None)
        if len(present) > 1:
            which = "; ".join(f"{', '.join(image_ids[i])} on {i}" for i in present)
            raise DockerError(
                f"the containers of {compose_project}'s service {service} run different "
                f"images ({which}), so which one its deploy built is unknown. Remove the "
                f"ones its last deploy did not create (docker rm <container>, as the "
                f"operator), or deploy the project again.")
        if present:
            _run(["docker", "tag", present[0], name], capture=True)
            named.append(name)
    return named


def _image_names(extra: list[str]) -> dict[str, list[str]]:
    """{image ID: names} of local images (`docker image ls` plus `extra`
    arguments), leaving out <none> and the platform's own names."""
    listed = _run(
        ["docker", "image", "ls", "--no-trunc",
         "--format", "{{.ID}} {{.Repository}}:{{.Tag}}", *extra],
        capture=True,
    ).stdout.splitlines()
    by_id: dict[str, list[str]] = {}
    for line in filter(None, (entry.strip() for entry in listed)):
        image_id, name = line.split(" ", 1)
        if not name.startswith(("<none>", f"{BUILT_IMAGE_HOST}/")):
            by_id.setdefault(image_id, []).append(name)
    return by_id


def _bare(name: str) -> str:
    return name.removesuffix(":latest")


def untag_old_built_names(
    compose_project: str, build_services: dict[str, str | None], image_services: set[str],
) -> list[str]:
    """Remove the old names of images this compose project built. Returns
    the names removed. A container still running one keeps its image.

    `build_services` maps each build service to the `image:` the user gave
    it, if any; `image_services` are the project's other services. An image whose Compose project label names
    this project is its build (current services and ones since removed or
    renamed), and loses every name but the platform's. An unlabelled image
    (Compose 2.38 builds without labels) that a build service's container
    runs loses only the names this project gave it: `<project>-<service>`
    and that service's own `image:`. A Dockerfile that is just
    `FROM busybox:1.36` builds busybox's very image, whose other names are
    not ours.

    Ownership comes from labels, not names: `foo`'s service `bar-web` and
    `foo-bar`'s service `web` share the old default name. An image any
    other container uses (another project's, a project-less one, or one of
    this project's image-only services), by ID or by one of its names, is
    left alone, whatever its labels say. A leftover container of a removed
    service protects nothing: the next up removes it.

    Call name_running_builds first: an image a build service's container
    runs then keeps a name, the platform's, and the next start runs it."""
    check_compose_project_name(compose_project)
    labelled = _image_names(compose_project_filter(compose_project))
    containers = _container_images(compose_project, set(build_services), image_services)
    if not labelled and not containers.own_ids:
        return []
    produced = {_bare(image) for image in build_services.values() if image}
    prefixes = tuple(f"{compose_project}-{svc}:" for svc in build_services)
    candidates = dict(labelled)
    if containers.own_ids:
        for image_id, image_names in _image_names([]).items():
            if image_id in containers.own_ids and image_id not in labelled:
                candidates[image_id] = [n for n in image_names
                                        if n.startswith(prefixes) or _bare(n) in produced]
    names = [
        name for image_id, image_names in candidates.items()
        if image_id not in containers.user_ids
        and not containers.user_names & {n for full in image_names for n in (full, _bare(full))}
        for name in image_names
    ]
    if names:
        _run(["docker", "image", "rm", "-f", *names], capture=True)
    return names
