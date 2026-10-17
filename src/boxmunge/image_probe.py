# SPDX-License-Identifier: Apache-2.0
"""Who owns a path in an image, read without running the image.

Docker copies an image's directory, owner included, into an empty named
volume when a container is created on it, so a numeric non-root service's
volume targets must be owned by its own uid in the image (deploy_checks).
The helper mounts the image read-only (`--mount type=image`, Docker >= 28)
and stats the one path: nothing is extracted or archived, however large
the image's files, and a link is reported as itself. The helper runs in
the daemon's namespace, so on a remapped box it sees the container view
of every owner (a remapped daemon stores no id it cannot map).
"""
from __future__ import annotations

import shlex
import stat
from dataclasses import dataclass

from boxmunge.data_helper import helper_result
from boxmunge.docker_run import DockerError

_ABSENT_RC = 3


@dataclass(frozen=True)
class DirOwner:
    uid: int
    gid: int
    mode: int
    is_dir: bool


def probe_dir(image_id: str, path: str) -> DirOwner | None:
    """The owner of `path` in the image, or None when it has no such path."""
    target = shlex.quote(f"/img{path}")
    result = helper_result(
        "probe", ["--mount", f"type=image,source={image_id},target=/img"],
        f'p={target}; {{ [ -e "$p" ] || [ -L "$p" ]; }} || exit {_ABSENT_RC}; '
        f'stat -c "%u %g %f" "$p"')
    if result.returncode == _ABSENT_RC:
        return None
    fields = result.stdout.split()
    if result.returncode != 0 or len(fields) != 3 or not all(
            f.isascii() and f.isalnum() for f in fields):
        raise DockerError(f"cannot read {path} in image {image_id[:19]}: exit "
                          f"{result.returncode}: {(result.stderr or result.stdout).strip()}")
    mode = int(fields[2], 16)
    return DirOwner(int(fields[0]), int(fields[1]), stat.S_IMODE(mode), stat.S_ISDIR(mode))
