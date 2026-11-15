# SPDX-License-Identifier: Apache-2.0
"""The directories the deploy user writes and root code paths may create.

Commands run in the deploy shell (and over MCP) write into these. Root's
timers and upgrade write there too. `prepare_deploy_dirs` (run by the
upgrade) creates what is missing, as deploy's; `unwritable_by_deploy`
(doctor) reports any that are out of deploy's reach.

Deliberately absent, because only root writes there: state/container-updates
(boxmunge container-update, a root timer, is not in the deploy shell) and
state/jobs (the action API's records).
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.fs_nofollow import deploy_ids, mkdir_p_deploy, running_as_root

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

# Under state/. health and deploy: per-project health and deploy records
# (written by the root health timer as well as deploy-run commands); scans:
# CVE scan results; kev: the CISA catalog cache; start-refused and
# project-alerts: alert throttles; secrets-locks: writer locks for secrets
# files; backup: backup evidence (deploy's backups and root's check-all).
STATE_DIRS = ("health", "deploy", "scans", "kev",
              "start-refused", "project-alerts", "secrets-locks", "backup")
# Under projects/<name>/: `security suppress` writes suppressions.yml here.
PROJECT_DIRS = ("security",)

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


def prepare_deploy_dirs(paths: BoxPaths) -> None:
    """Create state/<dir>, as deploy's, for each STATE_DIRS entry that is
    missing. As root only; never changes a parent (/opt/boxmunge stays
    root's; state/ and projects/ are deploy's from install)."""
    if not running_as_root() or deploy_ids() is None:
        return
    for name in STATE_DIRS:
        mkdir_p_deploy(paths.state / name)


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
