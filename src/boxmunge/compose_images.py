# SPDX-License-Identifier: Apache-2.0
"""Image-name isolation rules for user compose files.

Image names are global to the Docker daemon. A build tags its image with
the service's `image:` (Compose's `<compose-project>-<service>` when there
is none) and with every `build.tags` entry, overwriting whatever that name
held. Unchecked, a build could replace another project's image, a public
image other projects run (`postgres:16-alpine`), or the platform's own
(`caddy:2-alpine`, `system-system`, which mounts the backup key); their next
container recreate would run it.

So every name a build produces must lie in the project's image namespace:
`<project>-<name>`, `<project>_<name>` or `<project>/<name>`, with no
registry host. Project names may contain hyphens, so `foo-bar-web` lies in
both `foo`'s and `foo-bar`'s namespace; it belongs to the longest project
name it starts with (the reserved platform names count), and only that
project may build it.

The reverse holds too: an image-only service may not name an image in
another project's namespace. Compose's default pull policy runs a local
image without pulling, so it would run the other project's build, with its
code and anything baked into it.
"""
from __future__ import annotations

from typing import Any, Iterable

_HUB_PREFIXES = ("docker.io/", "index.docker.io/", "registry-1.docker.io/")
_NAMESPACE_SEPARATORS = ("-", "_", "/")


def _repository(ref: str) -> str:
    """Strip the tag and digest: `foo/bar:1@sha256:..` -> `foo/bar`."""
    ref = ref.split("@", 1)[0]
    head, _, last = ref.rpartition("/")
    last = last.split(":", 1)[0]
    return f"{head}/{last}" if head else last


def _has_registry_host(repo: str) -> bool:
    first, sep, _ = repo.partition("/")
    return bool(sep) and ("." in first or ":" in first or first == "localhost")


def _local_repository(ref: str) -> str | None:
    """The repository a reference names on this daemon without a registry
    host (Docker Hub spellings normalised), or None if it names another
    registry."""
    repo = _repository(ref)
    for prefix in _HUB_PREFIXES:
        if repo.startswith(prefix):
            repo = repo[len(prefix):]
            break
    else:
        if _has_registry_host(repo):
            return None
    return repo.removeprefix("library/")


def owner(repo: str, projects: Iterable[str]) -> str | None:
    """The project whose image namespace holds `repo`: the longest project
    name followed by `-`, `_` or `/`."""
    owners = [
        p for p in projects
        if any(repo.startswith(p + sep) for sep in _NAMESPACE_SEPARATORS)
    ]
    return max(owners, key=len, default=None)


def _built_names(svc_name: str, svc: dict[str, Any], project: str) -> list[str]:
    build = svc.get("build")
    names = [svc.get("image") or f"{project}-{svc_name}"]
    tags = build.get("tags") if isinstance(build, dict) else None
    names += [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []
    return [n for n in names if isinstance(n, str)]


def _built_problem(svc_name: str, name: str, project: str,
                   projects: frozenset[str]) -> str | None:
    accepted = (
        f"Name it {project}-<name> (for example {project}-{svc_name}), "
        f"{project}_<name> or {project}/<name>, with no registry host, or "
        f"remove image: to use Compose's default {project}-{svc_name}."
    )
    repo = _repository(name)
    if _has_registry_host(repo) or owner(repo, {project}) is None:
        return (
            f"service {svc_name}: the build tags its image {name!r}, outside "
            f"this project's image namespace. Image names are shared by every "
            f"project on the server, so the build could replace another "
            f"project's or a public image. {accepted}"
        )
    holder = owner(repo, projects | {project})
    if holder != project:
        return (
            f"service {svc_name}: the build tags its image {name!r}, which lies "
            f"in project {holder!r}'s image namespace ({holder} is the longest "
            f"project name it starts with). Rename the service or image so the "
            f"name does not start with {holder}-, {holder}_ or {holder}/."
        )
    return None


def image_problems(
    services: dict[str, Any], project: str, other_projects: Iterable[str],
) -> list[str]:
    """Return every image name that reaches into another project's images."""
    projects = frozenset(other_projects) - {project}
    problems: list[str] = []
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if svc.get("build") is not None:
            problems += [
                p for name in _built_names(svc_name, svc, project)
                if (p := _built_problem(svc_name, name, project, projects))
            ]
            continue
        image = svc.get("image")
        repo = _local_repository(image) if isinstance(image, str) else None
        holder = owner(repo, projects | {project}) if repo else None
        if holder is not None and holder != project:
            problems.append(
                f"service {svc_name}: image {image!r} lies in project "
                f"{holder!r}'s image namespace, so Compose could run that "
                f"project's locally built image. Use a published image from a "
                f"registry, or build your own as {project}-<name>."
            )
    return problems
