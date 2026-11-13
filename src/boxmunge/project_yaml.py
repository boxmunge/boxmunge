# SPDX-License-Identifier: Apache-2.0
"""Reading a YAML file of a project as root.

A project's directory is deploy-writable, and root reads its manifest and
compose files from timers (health, scan, container-update) and from sudo
commands. A plain open would follow a link to any file on the host, block
forever on a FIFO, and read a file deploy grew without bound. Parse errors
are the other leak: PyYAML quotes the offending source line when it is
given a string, so a link to a root-only file that is not YAML would be
printed, and logged where deploy reads, a line at a time. Parsing a stream
quotes no line, only the problem and its position.

A git project's manifest.yml and compose.yml are links into its checkout
(repo/), so a link is followed when, resolved, it stays inside ``within``
(the project directory) and no component of the resolved path is swapped for
a link before the open (caddy.read_override's rules). A file that is never
a link (a release tree's, a generated one) is read with read_bytes_nofollow.
"""
from __future__ import annotations

import io
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from boxmunge.fs_nofollow import open_resolved_nofollow, read_bytes_nofollow

# Far above any manifest or compose file, far below what would hurt a root timer.
PROJECT_YAML_LIMIT_BYTES = 1024 * 1024


def read_project_bytes(path: Path, within: Path | None = None, *,
                       limit: int = PROJECT_YAML_LIMIT_BYTES) -> bytes:
    """The bytes of ``path``, a file of a project.

    With ``within`` (the directory it belongs to) a link is followed only
    to a file inside it; without, the name must not be a link at all.
    Raises FileNotFoundError when nothing is at the name, and an OSError
    naming the path and what to do for anything else: a link out of the
    project, a dangling link, a FIFO or other non-regular file, or a file
    over ``limit``."""
    def refused(why: str) -> OSError:
        return OSError(f"{path} {why}. Make it a regular file inside the project "
                       f"(remove it so it can be recreated).")
    if within is None:
        try:
            return read_bytes_nofollow(path, limit=limit)
        except FileNotFoundError:
            raise
        except OSError as e:
            raise refused(f"cannot be read ({e})") from e
    if not os.path.lexists(path):
        raise FileNotFoundError(f"{path} does not exist")
    inside = Path(os.path.realpath(within))
    target = Path(os.path.realpath(path))
    if not target.is_relative_to(inside):
        raise refused(f"is a link to {target}, outside the project, which boxmunge "
                      f"does not follow")
    try:
        fd = open_resolved_nofollow(target, os.O_RDONLY)
    except FileNotFoundError as e:
        raise refused(f"is a link to {target}, which does not exist") from e
    except OSError as e:
        raise refused(f"is not a regular file, or a link on its way was swapped ({e})") from e
    with os.fdopen(fd, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise refused(f"is larger than {limit} bytes")
    return data


def home_of(path: Path, roots: Sequence[Path]) -> Path:
    """The directory ``path`` belongs to: the first of ``roots`` it lies in
    (by name, as written), else its own directory."""
    name = Path(os.path.abspath(path))
    return next((root for root in roots if name.is_relative_to(os.path.abspath(root))),
                path.parent)


def load_project_yaml(path: Path, within: Path | None = None) -> Any:
    """The parsed YAML of a file of a project (read_project_bytes' rules).
    Raises OSError when it cannot be read and yaml.YAMLError when it does
    not parse; the error text carries the problem and its line number,
    never a line of the file."""
    return yaml.safe_load(io.BytesIO(read_project_bytes(path, within)))
