# SPDX-License-Identifier: Apache-2.0
"""The directories the deploy user writes and root code paths may create.

Commands run in the deploy shell (and over MCP) write into these. Root's
timers and upgrade write there too, and before v0.9.3 whichever of them ran
first created the directory, as root, so deploy could not write it
afterwards (a manual `security scan` died with EACCES in state/scans).
`prepare_deploy_dirs` (run by the upgrade) creates what is missing and
re-owns what root made; `unwritable_by_deploy` (doctor) reports what is
still out of deploy's reach.

Deliberately absent, because only root writes there: state/container-updates
(boxmunge container-update, a root timer, is not in the deploy shell) and
state/jobs (the action API's records).
"""
from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.fs_nofollow import (
    chown_open_tree_deploy, deploy_ids, mkdir_p_deploy, running_as_root,
)
from boxmunge.log import log_error, log_warning

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# Under state/. health and deploy: per-project health and deploy records
# (written by the root health timer as well as deploy-run commands); scans:
# CVE scan results; kev: the CISA catalog cache; staging: records of a
# release staged by 0.10.1; start-refused and project-alerts: alert
# throttles; secrets-locks: writer locks for secrets files.
STATE_DIRS = ("health", "deploy", "scans", "kev", "staging",
              "start-refused", "project-alerts", "secrets-locks")
# Under projects/<name>/: `security suppress` writes suppressions.yml here.
PROJECT_DIRS = ("security",)

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _project_dir_names(paths: BoxPaths) -> list[str]:
    try:
        with os.scandir(paths.projects) as it:
            return sorted(e.name for e in it if e.is_dir(follow_symlinks=False))
    except FileNotFoundError:
        return []


def _targets(paths: BoxPaths) -> list[tuple[Path, str]]:
    """(parent, name) of every directory in the set, whether or not it exists."""
    found = [(paths.state, name) for name in STATE_DIRS]
    for project in _project_dir_names(paths):
        found += [(paths.projects / project, name) for name in PROJECT_DIRS]
    return found


def deploy_dirs(paths: BoxPaths) -> list[Path]:
    """The directories of the set that exist (a link in place of one is not one)."""
    return [parent / name for parent, name in _targets(paths)
            if (parent / name).is_dir() and not (parent / name).is_symlink()]


ROOT_UID = 0


def _uid_of(fd: int) -> int:
    return os.fstat(fd).st_uid


@dataclass
class Reowned:
    """What prepare_deploy_dirs did: directories that were not deploy's and
    now are, and those still not deploy's after the attempt."""

    done: list[Path] = field(default_factory=list)
    failed: list[Path] = field(default_factory=list)


def _open_dir(paths: BoxPaths, name: str, dir_fd: int | None, shown: Path) -> int | None:
    """A directory opened without following a link; None (a link or a
    non-directory is warned about, never re-owned) when absent or not one."""
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            log_warning("upgrade", f"{shown} is not a plain directory; not re-owned", paths)
            return None
        raise


def _reown(paths: BoxPaths, parent: Path, name: str, uid: int, result: Reowned) -> None:
    """Re-own parent/name and what root made under it to deploy, through
    descriptors that refuse a link, so a link deploy swapped in is left
    alone. Records the directory in ``result`` when it was not deploy's."""
    shown = parent / name
    pfd = _open_dir(paths, str(parent), None, parent)
    if pfd is None:
        return
    try:
        fd = _open_dir(paths, name, pfd, shown)
        if fd is None:
            return
        try:
            was_deploys = _uid_of(fd) == uid
            chown_open_tree_deploy(fd, str(shown), only_uid=ROOT_UID)
            now_deploys = _uid_of(fd) == uid
        finally:
            os.close(fd)
    finally:
        os.close(pfd)
    if not now_deploys:
        log_error("upgrade", f"{shown} is still not owned by deploy after the chown", paths)
        result.failed.append(shown)
    elif not was_deploys:
        result.done.append(shown)


def prepare_deploy_dirs(paths: BoxPaths) -> Reowned:
    """Create state/<dir> for each STATE_DIRS entry that is missing, and
    re-own every directory of the set (and what root made in it) to deploy.
    As root only.

    Never re-owns a parent (/opt/boxmunge stays root's; state/ and
    projects/ are deploy's from install).
    """
    result = Reowned()
    ids = deploy_ids()
    if not running_as_root() or ids is None:
        return result
    for name in STATE_DIRS:
        mkdir_p_deploy(paths.state / name)
    for parent, name in _targets(paths):
        _reown(paths, parent, name, ids[0], result)
    return result


def fix_command(directory: Path) -> str:
    """The command that gives deploy back a directory root made."""
    return f"sudo chown -R deploy:deploy {directory}"


def unwritable_by_deploy(paths: BoxPaths) -> list[Path] | None:
    """The directories of the set deploy cannot create files in, or None
    when there is no deploy user to ask about. Judged from the owner, group
    and mode, so it is the same answer whoever asks (root can write anything)."""
    ids = deploy_ids()
    if ids is None:
        return None
    uid, gid = ids
    gids = set(os.getgrouplist("deploy", gid))
    blocked = []
    for directory in deploy_dirs(paths):
        st = os.lstat(directory)
        if st.st_uid == uid:
            need = stat.S_IWUSR | stat.S_IXUSR
        elif st.st_gid in gids:
            need = stat.S_IWGRP | stat.S_IXGRP
        else:
            need = stat.S_IWOTH | stat.S_IXOTH
        if st.st_mode & need != need:
            blocked.append(directory)
    return blocked
