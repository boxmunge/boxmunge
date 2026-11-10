# SPDX-License-Identifier: Apache-2.0
"""`compose build` of a release's build services, with or without --pull.

A pulling build asks each base image's registry for its tag's current
digest, so a base image's fixes reach the release; an unchanged digest
downloads nothing and keeps the build cache. The pull never creates or
moves a tag in the box's local image store: BuildKit keeps what it pulled
in its own cache. A build without --pull resolves each base from the local
image store, and asks the registry only for a base that is not there.

A service whose compose files set `build: {pull: false}` builds from the
local image store even in a pulling deploy: its FROM may name an image
only this box has (docker load, a hand build), which no registry serves.
Compose's CLI --pull would override that setting, so those services are
built in a separate invocation without it. Building a service also builds
the services it names as `service:` build contexts, so a pulling build on
a local one is built locally too, and a local build on a pulling one is
refused (it would rebuild that service on the stale local bases).
"""
from __future__ import annotations

import yaml

from boxmunge.compose_build_specs import build_specs, service_contexts
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.release_target import DeployRefused, ReleaseTarget

_BUILD_TIMEOUT = 1800
# BuildKit's wording when it cannot read a base image's manifest from its
# registry: unreachable, rate-limited, credentials refused, or no such
# image. The same on the overlay2 and containerd image stores. The classic
# builder (DOCKER_BUILDKIT=0, which boxmunge's docker environment never
# sets) words it differently, so its failures would pass through as they are.
_BASE_UNREADABLE = "failed to resolve source metadata"


def _build_specs(target: ReleaseTarget) -> dict[str, dict]:
    """{service: its merged `build:` mapping} (compose_build_specs).
    Raises DeployRefused."""
    release = target.compose.project_directory or target.compose.cwd
    try:
        return build_specs(release / "compose.yml", (release,))
    except (OSError, ValueError, yaml.YAMLError) as e:
        raise DeployRefused([f"cannot read the release's compose files to see which "
                             f"builds set build.pull: false: {e}"]) from e


def local_base_builds(target: ReleaseTarget) -> frozenset[str]:
    """The services built from the local image store in a pulling deploy:
    each whose merged definition sets `build.pull: false`, and each that
    builds on one of those through a `service:` additional context (a
    pulling build would build that service again, with --pull). Raises
    DeployRefused for the reverse: a local build on a pulling service."""
    specs = _build_specs(target)
    # Each local service, and the local context it builds on (None: it
    # sets pull: false itself).
    local: dict[str, str | None] = {
        n: None for n, spec in specs.items() if spec.get("pull") is False}
    grew = True
    while grew:
        more = {n: sorted(service_contexts(spec) & set(local))[0]
                for n, spec in specs.items() if n not in local
                and service_contexts(spec) & set(local)}
        local |= more
        grew = bool(more)
    _refuse_pulling_contexts(specs, local)
    return frozenset(local)


def _refuse_pulling_contexts(specs: dict[str, dict], local: dict[str, str | None]) -> None:
    """Building a local service builds its `service:` contexts too, without
    --pull, so a pulling context would be built again, over its pulled
    build, on the base images this box already has."""
    def why(name: str) -> str:
        via = local[name]
        return "(compose build.pull: false)" if via is None else f"because it builds on '{via}'"
    problems = [
        f"'{name}' builds from the local image store {why(name)} but "
        f"names '{context}' as a `service:` build context, and '{context}' pulls its "
        f"base images: building '{name}' would build '{context}' again without "
        f"--pull, on the base images this box already has. Set `build: {{pull: false}}` "
        f"on '{context}' too, or run the command again with --no-pull."
        for name in sorted(local) for context in sorted(service_contexts(specs[name]))
        if context in specs and context not in local]
    if problems:
        raise DeployRefused(problems)


def build_services(target: ReleaseTarget, builds: list[str], *, pull: bool) -> None:
    """Build `builds`; with `pull`, every one but those local_base_builds
    names asks its base images' registries. A base that cannot be read fails
    the build: nothing falls back to the base the box has."""
    local = sorted(set(builds) & local_base_builds(target)) if pull else builds
    pulled = [b for b in builds if b not in local]
    if pulled:
        print(f"  Building {', '.join(pulled)} on each base image's current registry "
              f"digest...")
        _compose_build(target, pulled, pull=True)
    if local:
        why = "compose build.pull: false" if pull else "--no-pull"
        print(f"  Building {', '.join(local)} from the base images in this box's image "
              f"store ({why})...")
        _compose_build(target, local, pull=False)


def _compose_build(target: ReleaseTarget, builds: list[str], *, pull: bool) -> None:
    try:
        _run([*target.command(), "build", *(["--pull"] if pull else []), *builds],
             cwd=target.compose.cwd, timeout=_BUILD_TIMEOUT)
    except DockerError as e:
        if pull and _BASE_UNREADABLE in str(e):
            raise DockerError(
                f"A base image could not be read from its registry (unreachable, "
                f"rate-limited, credentials refused, or no such image), so the build "
                f"stopped before anything was started:\n{e}\n"
                f"If the registry is only unreachable for now, run the command again "
                f"with --no-pull: it builds from the base images in this box's local "
                f"image store (`docker image ls`), which miss any fix published since "
                f"they were pulled. A base that is not in that store (one an earlier "
                f"pulling build fetched lands only in the builder's cache) still needs "
                f"its registry. For a base image only this box has, set compose "
                f"`build: {{pull: false}}` on that service.") from e
        raise
