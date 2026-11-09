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
built in a separate invocation without it.
"""
from __future__ import annotations

import yaml

from boxmunge import compose_references
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.release_target import DeployRefused, ReleaseTarget

_BUILD_TIMEOUT = 1800
# BuildKit's wording when it cannot read a base image's manifest from its
# registry: unreachable, rate-limited, credentials refused, or no such
# image. The same on the overlay2 and containerd image stores. The classic
# builder (DOCKER_BUILDKIT=0, which boxmunge's docker environment never
# sets) words it differently, so its failures would pass through as they are.
_BASE_UNREADABLE = "failed to resolve source metadata"


def local_base_builds(target: ReleaseTarget) -> frozenset[str]:
    """The services whose definition, as written, sets `build.pull: false`:
    in compose.yml or in a file it includes or extends from, read as the
    reference walk follows them (compose_references). Compose's resolved
    model drops a false `pull`, so the files themselves are read. A
    service that extends another under a different name sets it itself."""
    release = target.compose.project_directory or target.compose.cwd
    found: set[str] = set()
    try:
        for path in compose_references.compose_files(release / "compose.yml", (release,)):
            doc = yaml.safe_load(path.read_text()) or {}
            services = doc.get("services") if isinstance(doc, dict) else None
            found |= {n for n, s in (services or {}).items() if isinstance(s, dict)
                      and isinstance(s.get("build"), dict) and s["build"].get("pull") is False}
    except (OSError, ValueError, yaml.YAMLError) as e:
        raise DeployRefused([f"cannot read the release's compose files to see which "
                             f"builds set build.pull: false: {e}"]) from e
    return frozenset(found)


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
