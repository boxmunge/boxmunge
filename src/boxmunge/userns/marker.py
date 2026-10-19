# SPDX-License-Identifier: Apache-2.0
"""The "migration in progress" marker every project command honours.

From the moment the migration (or its rollback) starts stopping containers
until the box runs again, the daemon, the volumes and the data are in
between two states: a deploy, a restore or a container-update then would
start a project on a new, empty volume beside its data. The marker is set
before the quiesce and cleared only once the box runs again; lifecycle's
is_blocked reports it, so every project command refuses, naming the
command that finishes the migration. It lives in /opt/boxmunge itself,
which only root can write, and every user can read.

What refuses: deploy, stage, unstage, promote, rollback, restore, pause,
resume, recover, security resume and scan, backups, container-update,
project-delete, data adopt and chown, legacy-stage, self-test; the
timers' entry points (check-all, backup-all) skip the project.
"""
from __future__ import annotations

import os

from boxmunge.fileutil import atomic_write_bytes, fsync_dir
from boxmunge.paths import BoxPaths

SHIM = "sudo /opt/boxmunge/bin/boxmunge-upgrade"


def set_marker(paths: BoxPaths, finish: str) -> None:
    """`finish`: the shim subcommand(s) that complete what is in progress."""
    atomic_write_bytes(paths.userns_marker, f"{finish}\n".encode(), mode=0o644,
                       owner=(os.geteuid(), os.getegid()))


def clear_marker(paths: BoxPaths) -> None:
    if os.path.lexists(paths.userns_marker):
        os.unlink(paths.userns_marker)
        fsync_dir(paths.root)


def migration_in_progress(paths: BoxPaths) -> str | None:
    """The command that finishes the migration, or None when none is open."""
    try:
        with open(paths.userns_marker, encoding="utf-8") as f:
            finish = f.read().strip()
    except FileNotFoundError:
        return None
    return finish or "userns-migrate"
