# SPDX-License-Identifier: Apache-2.0
"""Image-name isolation rules for user compose files.

Image names are global to the Docker daemon. Left to Compose, a build is
tagged with the service's `image:` (or `<compose-project>-<service>`) and
every `build.tags` entry, so it could replace another project's image, a
public image other projects run, or the platform's own, and their next
recreate would run it. So the platform names every built image itself:
the overlay sets a build service's `image:` to
`boxmunge.invalid/<compose-project>/<service>` (staging's compose project
is `<project>-staging`, a suffix no project may use). `.invalid` can never
be a registry or a Docker Hub name, and project names contain no `/`, so
each project owns exactly the names under its own prefix. A user `image:`
on a build service is overridden (with a warning) and `build.tags` is
refused.

The reverse direction is checked too: Compose runs a local image without
pulling it, so nothing may name an image under another project's prefix,
or by image ID, which the daemon resolves to any local image. That covers
image-only services, `type: image` mounts, `docker-image://` additional
contexts, and the Dockerfile. The Dockerfile check is a best-effort text
scan (SECURITY.md says what it does not catch); everything else is exact.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

BUILT_IMAGE_HOST = "boxmunge.invalid"
_STAGING = "-staging"

# A Docker repository path component.
_COMPONENT_RE = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
# `sha256:<hex>` or a bare hex string: the daemon resolves either to a local
# image by ID (or ID prefix), whoever built it.
_IMAGE_ID_RE = re.compile(r"(?:sha256:)?[0-9a-f]+", re.IGNORECASE)
_PLATFORM_REF_RE = re.compile(
    re.escape(BUILT_IMAGE_HOST) + r"(?::\d+)?/([^/\s\"']*)", re.IGNORECASE,
)
_FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)
_FROM_FLAG_RE = re.compile(r"--from=([^\s,]+)", re.IGNORECASE)
# Any spelling of the platform host, or a fragment of it that only makes
# sense joined to the rest (`ARG B=.invalid`, `ARG A=boxmunge.inval`). Group 1
# is the owner component following a full host, when there is one.
_HOST_RE = re.compile(
    r"boxmunge\.invalid(?::\d+)?(/[^/\s\"'${}]*/)?"
    r"|(?<![A-Za-z0-9-])\.invalid\b"
    r"|boxmunge\.(?:i(?:n(?:v(?:a(?:l(?:i(?:d)?)?)?)?)?)?)?(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def is_platform_image(ref: str) -> bool:
    """True for a name under the platform's host: an image built on this
    server, which no registry serves, so it is never pulled."""
    host = ref.strip().split("/", 1)[0].split(":", 1)[0]
    return host.lower() == BUILT_IMAGE_HOST


def built_image_name(compose_project: str, service: str) -> str:
    """The name the overlay gives a build service's image."""
    return f"{BUILT_IMAGE_HOST}/{compose_project}/{service}"


def _own_owners(project: str) -> frozenset[str]:
    return frozenset({project, project + _STAGING})


def _ref_problem(what: str, ref: str, project: str) -> str | None:
    """Advice if `ref` names another project's built image or an image ID."""
    ref = ref.strip()
    if _IMAGE_ID_RE.fullmatch(ref):
        return (
            f"{what} {ref!r} is an image ID, which can name any image on the "
            f"server, including another project's. Name the image by its "
            f"repository and tag instead."
        )
    match = _PLATFORM_REF_RE.match(ref)
    if match and match.group(1).lower() not in _own_owners(project):
        return (
            f"{what} {ref!r} is another project's locally built image. Use a "
            f"published image from a registry, or this project's own "
            f"{BUILT_IMAGE_HOST}/{project}/<service>."
        )
    return None


def _split_name_problems(what: str, value: str, project: str) -> list[str]:
    """Text naming the platform host, or a fragment of it, other than as
    this project's own full prefix: the rest of an image name could be
    joined on at build time (`FROM ${X:-boxmunge.invalid}/<other>/web`,
    `ARG A=boxmunge` + `ARG B=.invalid`)."""
    own = {f"/{o}/" for o in _own_owners(project)}
    if all((m.group(1) or "").lower() in own for m in _HOST_RE.finditer(value)):
        return []
    return [
        f"{what} uses {BUILT_IMAGE_HOST} other than as this project's own "
        f"{BUILT_IMAGE_HOST}/{project}/ prefix, so the Dockerfile could join "
        f"it into another project's image name. Write this project's images "
        f"in full ({BUILT_IMAGE_HOST}/{project}/<service>), or use a "
        f"published image."
    ]


def _text_problems(what: str, text: str, project: str) -> list[str]:
    """Best-effort scan of Dockerfile-like text: every platform image name
    it mentions, and image IDs in FROM and --from=."""
    problems = [
        f"{what} names {BUILT_IMAGE_HOST}/{m.group(1)}/..., another project's "
        f"locally built image. Use a published image, or this project's own "
        f"{BUILT_IMAGE_HOST}/{project}/<service>."
        for m in _PLATFORM_REF_RE.finditer(text)
        if m.group(1).lower() not in _own_owners(project)
    ]
    for number, line in enumerate(text.splitlines(), 1):
        problems += _split_name_problems(f"{what} line {number}", line, project)
    stages: set[str] = set()
    for line in text.splitlines():
        refs = [m.group(1) for m in _FROM_FLAG_RE.finditer(line)]
        found = _FROM_RE.match(line)
        if found:
            refs.append(found.group(1))
        for ref in refs:
            # --from=0 names an earlier stage by index; named stages likewise.
            if ref.lower() in stages or ref.isdigit():
                continue
            if _IMAGE_ID_RE.fullmatch(ref):
                problems.append(str(_ref_problem(what, ref, project)))
        if found and found.group(2):
            stages.add(found.group(2).lower())
    return problems


def _build_refs(svc_name: str, build: dict[str, Any], project: str,
                dockerfile: Path | None) -> list[str]:
    where = f"service {svc_name}:"
    problems: list[str] = []
    if build.get("tags"):
        problems.append(
            f"{where} build.tags {build['tags']!r} would tag the build with "
            f"names other projects may use. Remove it: boxmunge tags the build "
            f"{built_image_name(project, svc_name)}."
        )
    contexts = build.get("additional_contexts")
    for name, ref in (contexts.items() if isinstance(contexts, dict) else []):
        if isinstance(ref, str) and ref.startswith("docker-image://"):
            problem = _ref_problem(
                f"{where} build.additional_contexts.{name}",
                ref.removeprefix("docker-image://"), project,
            )
            problems += [problem] if problem else []
    texts = [("build.dockerfile_inline", build.get("dockerfile_inline"))]
    args = build.get("args")
    for key, value in (args.items() if isinstance(args, dict) else []):
        if isinstance(value, str):
            problems += _split_name_problems(f"{where} build.args.{key}", value, project)
            texts.append((f"build.args.{key}", value))
    if dockerfile is not None and dockerfile.is_file():
        texts.append((f"Dockerfile {dockerfile.name}", dockerfile.read_text(errors="replace")))
    for what, text in texts:
        if isinstance(text, str):
            problems += _text_problems(f"{where} {what}", text, project)
    return problems


def _mount_refs(svc_name: str, svc: dict[str, Any], project: str) -> list[str]:
    problems: list[str] = []
    for entry in svc.get("volumes") or []:
        if isinstance(entry, dict) and entry.get("type") == "image":
            problem = _ref_problem(
                f"service {svc_name}: image mount", str(entry.get("source")), project,
            )
            problems += [problem] if problem else []
    return problems


def image_problems(
    services: dict[str, Any], project: str, dockerfiles: dict[str, Path | None],
) -> list[str]:
    """Return every image reference that reaches another project's images.

    `dockerfiles` maps each build service to its local Dockerfile (None for
    a remote or inline one)."""
    problems: list[str] = []
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        build = svc.get("build")
        build = {"context": build} if isinstance(build, str) else build
        if isinstance(build, dict):
            if not _COMPONENT_RE.fullmatch(str(svc_name)):
                problems.append(
                    f"service {svc_name}: a built service's name becomes part of "
                    f"its image name ({built_image_name(project, svc_name)}), so "
                    f"it must be lowercase letters and digits separated by '.', "
                    f"'_' or '-'. Rename the service."
                )
            problems += _build_refs(svc_name, build, project, dockerfiles.get(svc_name))
        elif isinstance(svc.get("image"), str):
            problem = _ref_problem(f"service {svc_name}: image", svc["image"], project)
            problems += [problem] if problem else []
        problems += _mount_refs(svc_name, svc, project)
    return problems


def image_warnings(services: dict[str, Any], project: str) -> list[str]:
    """A user `image:` on a build service, which the overlay overrides."""
    own = {project, project + _STAGING}
    return [
        f"service {name}: image: {svc['image']!r} is ignored for a built "
        f"service; boxmunge names built images itself, and tags this build "
        f"{built_image_name(project, name)} (staging: "
        f"{built_image_name(project + _STAGING, name)})."
        for name, svc in services.items()
        if isinstance(svc, dict) and svc.get("build") is not None
        and isinstance(svc.get("image"), str)
        and svc["image"] not in {built_image_name(p, name) for p in own}
    ]
