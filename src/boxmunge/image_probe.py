# SPDX-License-Identifier: Apache-2.0
"""Who owns a directory in an image, read without running the image.

Docker copies an image's directory, owner included, into an empty named
volume at every container create, so a numeric non-root service's volume
targets must be owned by its own uid in the image (deploy_checks). The
probe creates a throwaway container from the image (never started, no
network, nothing of ours mounted) and streams `docker container cp
<it>:<path> -` only as far as the first tar header. On a remapped daemon
that header carries host ids (S+N), which are translated back to the
container's view; an id outside the remap range is refused.
"""
from __future__ import annotations

import subprocess
import tarfile
import threading
import uuid
from dataclasses import dataclass
from typing import IO

from boxmunge.docker_run import DockerError, docker_env, run as _run

RANGE = 65536
_PROBE_TIMEOUT = 60
_NOT_FOUND = b"Could not find the file"


class ProbeError(DockerError):
    """The image stores the path with an id the remapped daemon cannot map."""


@dataclass(frozen=True)
class DirOwner:
    uid: int
    gid: int
    mode: int
    is_dir: bool


def _container_view(value: int, offset: int, what: str) -> int:
    if not offset:
        return value
    if not offset <= value < offset + RANGE:
        raise ProbeError(f"the image stores {what} with host id {value}, outside the "
                         f"remap range [{offset}, {offset + RANGE - 1}]")
    return value - offset


def first_header_owner(stream: IO[bytes], offset: int) -> DirOwner | None:
    """Owner of the first entry of a `docker container cp ... -` tar, in the
    container's view; None for an empty stream (the path was not found)."""
    try:
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            first = next(iter(tar), None)
    except tarfile.ReadError as e:
        if "empty file" in str(e):
            return None
        raise DockerError(f"docker container cp returned no readable tar: {e}") from e
    if first is None:
        return None
    return DirOwner(_container_view(first.uid, offset, first.name),
                    _container_view(first.gid, offset, first.name), first.mode, first.isdir())


def probe_dir(image_id: str, path: str, offset: int) -> DirOwner | None:
    """The owner of `path` in the image, or None when the image has no such
    path. Docker still makes anonymous volumes for the image's VOLUMEs, so
    the container is removed with -v, also on failure."""
    name = f"boxmunge-probe-{uuid.uuid4().hex[:8]}"
    _run(["docker", "create", "--name", name, "--network", "none", "--entrypoint", "",
          image_id, "/boxmunge-probe-never-runs"], capture=True)
    try:
        proc = subprocess.Popen(["docker", "container", "cp", f"{name}:{path}", "-"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=docker_env())
        # A daemon that never answers must not hang the deploy.
        watchdog = threading.Timer(_PROBE_TIMEOUT, proc.kill)
        watchdog.start()
        try:
            assert proc.stdout is not None
            owner = first_header_owner(proc.stdout, offset)
        finally:
            watchdog.cancel()
            proc.kill()
            _out, err = proc.communicate(timeout=_PROBE_TIMEOUT)
        if owner is None and _NOT_FOUND not in err:
            raise DockerError(f"cannot read {path} from image {image_id[:19]}: "
                              f"{err.decode(errors='replace').strip()}")
        return owner
    finally:
        _run(["docker", "rm", "-f", "-v", name], capture=True)
