# SPDX-License-Identifier: Apache-2.0
"""Placeholders for staging's copy destinations, owned by whoever runs boxmunge.

Compose refuses a missing config or secret file and creates any other
missing bind source as a root-owned directory, so each destination of the
data copy is made first, as the type production's source is. The copy
replaces it with production's data and ownership.

A placeholder and the ``-staging`` directories holding it are made on the
host, as the calling user (deploy, or root handing them to deploy), so the
deploy user can replace and remove them later. Every step goes through a
directory descriptor opened without following links. Only when a directory
on the way belongs to someone else (a copy of production data owned by a
container user) is the rest made in the data helper, and then handed to
the same owner explicitly.

On a remapped box container root cannot write a deploy-owned directory, so
the copy could not fill a placeholder deploy made. There the daemon creates
a ``-staging`` directory (owned by container root, from a bind mount of the
missing path) and the helper makes the rest inside it; nothing is handed to
deploy, which removes the copies through the helper later (staging_cleanup).
"""
from __future__ import annotations

import os
import pwd
import shlex
from pathlib import Path

from boxmunge.data_helper import run_helper
from boxmunge.docker import staging_compose_project

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _owner() -> tuple[int, int]:
    """Who the placeholders belong to: deploy when root runs boxmunge (and
    deploy exists), else the calling user."""
    if os.getuid() == 0:
        try:
            pw = pwd.getpwnam("deploy")
            return pw.pw_uid, pw.pw_gid
        except KeyError:
            pass
    return os.getuid(), os.getgid()


def _on_host(project_dir: Path, parts: list[str], is_file: bool) -> bool:
    """Make ``parts`` under the project dir; False if a directory on the way
    is not writable by the calling user."""
    owner, root = _owner(), os.getuid() == 0
    fd = os.open(project_dir, _DIR)
    try:
        for part in parts[:-1] if is_file else parts:
            try:
                os.mkdir(part, 0o755, dir_fd=fd)
                made = True
            except FileExistsError:
                made = False
            child = os.open(part, _DIR, dir_fd=fd)
            os.close(fd)
            fd = child
            if made and root:
                os.fchown(fd, *owner)
        if is_file:
            try:
                leaf = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL
                               | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            except FileExistsError:
                return True
            try:
                if root:
                    os.fchown(leaf, *owner)
            finally:
                os.close(leaf)
        return True
    except PermissionError:
        return False
    finally:
        os.close(fd)


def copy_label(project: str) -> str:
    """The name the helper runs of a project's staging copy carry."""
    return f"{staging_compose_project(project)}-copy"


def _not_a_link(path: Path) -> None:
    """The daemon follows a bind source's links on the host; refuse one."""
    if path.is_symlink():
        raise OSError(f"{path} is a symlink; refusing to mount it for the staging copy")


def make_placeholder(project: str, project_dir: Path, rel: str, is_file: bool, *,
                     remapped: bool) -> None:
    """Make the destination ``rel`` (a project-relative path whose first
    component is a ``-staging`` entry) as an empty file or directory."""
    parts = rel.split(os.sep)
    if not remapped and _on_host(project_dir, parts, is_file):
        return
    top = project_dir / parts[0]
    _not_a_link(top)
    if len(parts) == 1:
        if remapped and not is_file:
            run_helper(copy_label(project), ["-v", f"{top}:/x"], "true")
            return
        raise PermissionError(f"cannot create {top}: the project directory is not "
                              f"writable by this user" + (" or by containers" if remapped else ""))
    rest = parts[1:]
    chain = ["/x/" + "/".join(rest[:i + 1]) for i in range(len(rest))]
    make = (f"mkdir -p {shlex.quote(os.path.dirname(chain[-1]))} && touch "
            if is_file else "mkdir -p ") + shlex.quote(chain[-1])
    if not remapped:
        uid, gid = _owner()
        make += f" && chown -h {uid}:{gid} {' '.join(map(shlex.quote, chain))}"
    run_helper(copy_label(project), ["-v", f"{top}:/x"], make)
